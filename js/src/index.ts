// Public entry point — re-exports everything users need

export { Anisette } from "./anisette.js";
export { WasmBridge } from "./wasm-bridge.js";
export { Device } from "./device.js";
export { LibraryStore } from "./library.js";
export { ProvisioningSession } from "./provisioning.js";
export {
  MacAnisette,
  createMacAnisette,
  mintMacIdentity,
  mintSerial,
  type MacIdentity,
  type MintOptions,
} from "./mac.js";
export { FetchHttpClient } from "./http.js";
export type { HttpClient } from "./http.js";
export type {
  AnisetteHeaders,
  AnisetteDeviceConfig,
  InitOptions,
  DeviceJson,
} from "./types.js";
export type { AnisetteOptions } from "./anisette.js";

export {
  loadWasmModule,
  loadWasmModule as loadWasm,
  isNodeEnvironment,
  getWasmBinaryPath,
  type EmscriptenModule,
  type ModuleOverrides,
} from "./wasm-loader.js";
