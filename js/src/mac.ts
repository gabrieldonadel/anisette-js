// MacAnisette — produce genuine mac-identity anisette in WASM by driving the macOS CoreADI
// directly (F-142). Mirrors the Android ProvisioningSession flow but over the mac exports:
// MidService provisioning + a synthetic "SoftwareMac" identity, no storeservicescore.
//
//   const mac = await createMacAnisette(wasmModule, coreadiBytes);  // or pass a saved identity
//   await mac.provision();                                          // one-time, hits Apple
//   const headers = await mac.headers();                            // repeatable
//
// The store lives in the WASM virtual FS at /Users/Shared/adi; persist it (idbfs sync in the
// browser) together with `identity` — the host UUID is hashed into the machine id, so a new
// identity rotates X-Apple-I-MD-M and invalidates a persisted GrandSlam session.

import { WasmBridge } from "./wasm-bridge.js";
import { FetchHttpClient, type HttpClient } from "./http.js";
import { toBase64, fromBase64, toAppleClientTime, randomHex, detectLocale, encodeUtf8 } from "./utils.js";

const LOOKUP_URL = "https://gsa.apple.com/grandslam/GsService2/lookup";
const DS_ID = -2n; // Apple's account-less "no account" pseudo-DSID; pre-auth, no Apple ID.
const CLIENT_INFO = "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";
const USER_AGENT = "akd/1.0 CFNetwork/1404.0.5 Darwin/22.3.0";

export interface MacIdentity {
  /** `00006000-<16 hex upper>` */ deviceId: string;
  /** 32 hex upper */ localUserUuid: string;
  /** 32 hex lower — hashed into the machine id via gethostuuid */ hostUuid: string;
  /** `C02` + 9 chars */ serial: string;
  clientInfo: string;
  routing?: number;
}

export interface AnisetteHeaders {
  "X-Apple-I-Client-Time": string;
  "X-Apple-I-MD": string;
  "X-Apple-I-MD-LU": string;
  "X-Apple-I-MD-M": string;
  "X-Apple-I-MD-RINFO": string;
  "X-Apple-I-SRL-NO": string;
  "X-Apple-I-TimeZone": string;
  "X-Apple-Locale": string;
  "X-MMe-Client-Info": string;
  "X-Mme-Device-Id": string;
}

const SERIAL_ALPHABET = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZ";

export interface MintOptions {
  /**
   * Serial-number prefix. Defaults to `"C02"` (Apple's manufacturer prefix); pass e.g. `"APPDROP"`
   * to brand the device. The remainder is filled with random Apple-serial characters to at least 12
   * chars total. The serial is a header identifier only (`X-Apple-I-SRL-NO`) — it is NOT hashed into
   * the machine id (that is `hostUuid`), so any prefix is safe. Uppercased; non-alphanumerics drop.
   */
  serialPrefix?: string;
}

/** A synthetic Apple-style serial that starts with `prefix`, padded with random chars (>= 12 long). */
export function mintSerial(prefix = "C02"): string {
  const p = prefix.toUpperCase().replace(/[^0-9A-Z]/g, "");
  const fill = Math.max(4, 12 - p.length);
  const rand = randomHex(fill);
  let serial = p;
  for (let i = 0; i < fill; i++) {
    serial += SERIAL_ALPHABET[parseInt(rand.slice(i * 2, i * 2 + 2) || "0", 16) % SERIAL_ALPHABET.length];
  }
  return serial;
}

export function mintMacIdentity(opts: MintOptions = {}): MacIdentity {
  return {
    deviceId: "00006000-" + randomHex(8, true),
    localUserUuid: randomHex(16, true),
    hostUuid: randomHex(16),
    serial: mintSerial(opts.serialPrefix),
    clientInfo: CLIENT_INFO,
  };
}

function plistField(xml: string, key: string): string | null {
  const m = xml.match(new RegExp(`<key>${key}</key>\\s*<(?:string|integer)>([^<]*)</`));
  return m ? m[1] : null;
}

function plistReq(innerRequestDict: string): string {
  return (
    `<?xml version="1.0" encoding="UTF-8"?>` +
    `<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` +
    `<plist version="1.0"><dict><key>Header</key><dict/><key>Request</key>${innerRequestDict}</dict></plist>`
  );
}

export class MacAnisette {
  private urlBag: Record<string, string> = {};

  constructor(
    private bridge: WasmBridge,
    public identity: MacIdentity,
    private http: HttpClient = new FetchHttpClient()
  ) {}

  private headersForMid(withTime: boolean): Record<string, string> {
    const h: Record<string, string> = {
      "User-Agent": USER_AGENT,
      "Content-Type": "application/x-www-form-urlencoded",
      Connection: "keep-alive",
      Accept: "*/*",
      "X-Mme-Device-Id": this.identity.deviceId,
      "X-MMe-Client-Info": this.identity.clientInfo,
      "X-Apple-I-MD-LU": this.identity.localUserUuid,
      "X-Apple-Client-App-Name": "Setup",
      "X-Apple-I-SRL-NO": this.identity.serial,
    };
    if (withTime) h["X-Apple-I-Client-Time"] = toAppleClientTime();
    return h;
  }

  private async loadUrlBag(): Promise<void> {
    const xml = new TextDecoder().decode(await this.http.get(LOOKUP_URL, this.headersForMid(false)));
    this.urlBag = {};
    for (const m of xml.matchAll(/<key>(mid\w+Provisioning)<\/key>\s*<string>([^<]+)</g)) {
      this.urlBag[m[1]] = m[2];
    }
  }

  /** One-time provision against Apple's MidService. Writes the store into the WASM virtual FS. */
  async provision(): Promise<void> {
    await this.loadUrlBag();
    const startUrl = this.urlBag["midStartProvisioning"];
    const finishUrl = this.urlBag["midFinishProvisioning"];
    if (!startUrl || !finishUrl) throw new Error("MidService url bag missing start/finish");

    const startXml = new TextDecoder().decode(
      await this.http.post(startUrl, plistReq("<dict/>"), this.headersForMid(true))
    );
    const spimB64 = plistField(startXml, "spim");
    if (!spimB64) throw new Error(`midStartProvisioning gave no spim: ${startXml.slice(0, 200)}`);
    const spim = fromBase64(spimB64);

    const { cpim, session } = this.bridge.macStartProvisioning(DS_ID, spim);

    const finishXml = new TextDecoder().decode(
      await this.http.post(
        finishUrl,
        plistReq(`<dict><key>cpim</key><string>${toBase64(cpim)}</string></dict>`),
        this.headersForMid(true)
      )
    );
    const ptmB64 = plistField(finishXml, "ptm");
    const tkB64 = plistField(finishXml, "tk");
    if (!ptmB64 || !tkB64) throw new Error(`midFinishProvisioning gave no ptm/tk: ${finishXml.slice(0, 200)}`);
    const routing = parseInt(plistField(finishXml, "X-Apple-I-MD-RINFO") ?? "0", 10);

    this.bridge.macEndProvisioning(session, fromBase64(ptmB64), fromBase64(tkB64));
    this.bridge.macSetRouting(DS_ID, BigInt(routing));
    this.identity.routing = routing;
  }

  /** Produce fresh anisette from the (already provisioned) store. Repeatable, no network. */
  async headers(): Promise<AnisetteHeaders> {
    const { otp, machineId } = this.bridge.macRequestOtp(DS_ID);
    let routing = this.identity.routing ?? 0;
    try {
      routing = Number(this.bridge.macGetRouting(DS_ID));
    } catch {
      /* keep the saved routing */
    }
    return {
      "X-Apple-I-Client-Time": toAppleClientTime(),
      "X-Apple-I-MD": toBase64(otp),
      "X-Apple-I-MD-LU": toBase64(encodeUtf8(this.identity.localUserUuid)),
      "X-Apple-I-MD-M": toBase64(machineId),
      "X-Apple-I-MD-RINFO": String(routing),
      "X-Apple-I-SRL-NO": this.identity.serial,
      "X-Apple-I-TimeZone": "UTC",
      "X-Apple-Locale": detectLocale(),
      "X-MMe-Client-Info": this.identity.clientInfo,
      "X-Mme-Device-Id": this.identity.deviceId,
    };
  }
}

/** Load the CoreADI blob into the module and return a ready MacAnisette (mints an identity if none
 * is supplied). `wasmModule` is the Emscripten module from the anisette_rs glue. */
export async function createMacAnisette(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  wasmModule: any,
  coreadi: Uint8Array,
  opts: {
    /** Reuse a saved identity (skips minting). */
    identity?: MacIdentity;
    /** Serial prefix when minting a fresh identity, e.g. "APPDROP". Ignored if `identity` is given. */
    serialPrefix?: string;
    http?: HttpClient;
  } = {}
): Promise<MacAnisette> {
  const id = opts.identity ?? mintMacIdentity({ serialPrefix: opts.serialPrefix });
  const bridge = new WasmBridge(wasmModule);
  bridge.macInit(coreadi, id.hostUuid);
  bridge.macInitialize();
  return new MacAnisette(bridge, id, opts.http);
}
