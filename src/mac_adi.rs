// MacAdi — drive the macOS CoreADI whitebox directly (F-140/F-142), the Mac counterpart to the
// Android-SSC `Adi`. No storeservicescore: it resolves `vdfut768ig` and calls it with the
// CoreADIParameters ABI + Mac function codes. Pure emulator work (no HTTP, no host FS), so it
// compiles for wasm32; the HTTP (MidService) and identity/store live in JS, exactly like `Adi`.
//
// Environment the macOS core needs (defeats the -45076 / -45054 gates) is already baked into the
// shared emulator: slide 0 (set here), arc4random=0x12345678 and NSVersionOfRunTimeLibrary=0
// (stub defaults), the virtual CFURL layer, distinct data-import cells, Darwin open() flags,
// fds from 3, and fcntl — see stub.rs / macho.rs.

use crate::emu::EmuCore;
use crate::errors::VmError;

// Mac function codes (os-findmy-e adi_run.py / Dadoum apple-crates calls.rs).
const INITIALIZE: u32 = 0x12DB_31C5;
const IS_MACHINE_PROVISIONED: u32 = 0xB0ED_A7AF;
const SET_IDMS_ROUTING: u32 = 0x632B_8D6E;
const GET_IDMS_ROUTING: u32 = 0x85FE_63B0;
const REQUEST_OTP: u32 = 0xCFE0_B46A;
const PROVISIONING_START: u32 = 0x716B_D86C;
const PROVISIONING_END: u32 = 0x0B2B_3196;
const TEARDOWN: u32 = 0x08C0_FE9E;

fn be_i64(v: i64) -> [u8; 8] { v.to_be_bytes() }
fn be_u64(v: u64) -> [u8; 8] { v.to_be_bytes() }
fn be_u32(v: u32) -> [u8; 4] { v.to_be_bytes() }

/// Result of one dispatcher call: `rc` is the raw return (eax, sign-extended), `status` is the
/// BE i32 the core writes into the payload header. Both must be >= 0 for success.
pub struct Dispatch {
    pub rc: i64,
    pub status: i32,
}

impl Dispatch {
    pub fn ok(&self) -> bool {
        self.rc >= 0 && self.status >= 0
    }
    fn check(&self, name: &'static str) -> Result<(), VmError> {
        if self.ok() {
            Ok(())
        } else {
            Err(VmError::AdiCallFailed {
                name,
                code: if self.status < 0 { self.status } else { self.rc as i32 },
            })
        }
    }
}

pub struct MacProvisioningStart {
    pub cpim: Vec<u8>,
    pub session: u32,
}

pub struct MacOtp {
    pub otp: Vec<u8>,
    pub machine_id: Vec<u8>,
}

pub struct MacAdi {
    core: EmuCore,
    vdf: u64,
}

impl MacAdi {
    pub fn new(coreadi: Vec<u8>) -> Result<Self, VmError> {
        // The macOS core must load at slide 0 (part of clearing the -45076 gate). The loader reads
        // this override; WASM is single-threaded at construction so the global env write is safe.
        unsafe { std::env::set_var("EMU_MACHO_BASE", "0") };
        let mut core = EmuCore::new_x86_64()?;
        core.register_library_blob("CoreADI", coreadi);
        let idx = core.load_library("CoreADI")?;
        let vdf = core.resolve_symbol_by_name(idx, "vdfut768ig")?;
        Ok(Self { core, vdf })
    }

    fn out(&mut self) -> Result<u64, VmError> {
        self.core.alloc_data(&[0u8; 8])
    }

    fn buf(&mut self, data: &[u8]) -> Result<u64, VmError> {
        let mut b = vec![0u8; core::cmp::max(data.len(), 16)];
        b[..data.len()].copy_from_slice(data);
        self.core.alloc_data(&b)
    }

    /// Build the CoreADIParameters wrapper around `message`, invoke `vdfut768ig(code, params)`,
    /// return (raw rc, BE-i32 status from the payload header).
    fn dispatch(&mut self, code: u32, message: &[u8]) -> Result<Dispatch, VmError> {
        let mut buf = vec![0u8; core::cmp::max(0x800, 8 + message.len())];
        buf[3] = 1; // encryption_type = Clear
        buf[7] = 1; // marker
        buf[8..8 + message.len()].copy_from_slice(message);
        let buf_addr = self.core.alloc_data(&buf)?;

        let mut params = vec![0u8; 0x20];
        params[0x00..0x08].copy_from_slice(&buf_addr.to_le_bytes()); // payload
        params[0x08..0x0C].copy_from_slice(&((8 + message.len()) as u32).to_le_bytes()); // input_size
        params[0x0C..0x10].copy_from_slice(&4u32.to_le_bytes()); // output_size
        // flags at 0x10 stay 0
        let params_addr = self.core.alloc_data(&params)?;

        let rc = self.core.invoke_cdecl(self.vdf, &[code as u64, params_addr])? as u32 as i32 as i64;
        let st = self.core.read_data(buf_addr, 4)?;
        Ok(Dispatch { rc, status: i32::from_be_bytes([st[0], st[1], st[2], st[3]]) })
    }

    fn read_slice(&self, p: u64, l: u64) -> Result<Vec<u8>, VmError> {
        let ptr = self.core.read_u64(p)?;
        let len = self.core.read_u32(l)? as usize;
        if ptr == 0 || len == 0 {
            return Ok(Vec::new());
        }
        self.core.read_data(ptr, len)
    }

    pub fn initialize(&mut self) -> Result<(), VmError> {
        self.dispatch(INITIALIZE, &[])?.check("Initialize")
    }

    pub fn teardown(&mut self) -> Result<(), VmError> {
        self.dispatch(TEARDOWN, &[])?.check("TearDown")
    }

    /// true = provisioned, false = not provisioned (-45061); other statuses are errors.
    pub fn is_machine_provisioned(&mut self, dsid: i64) -> Result<bool, VmError> {
        let d = self.dispatch(IS_MACHINE_PROVISIONED, &be_i64(dsid))?;
        if d.ok() {
            return Ok(true);
        }
        if d.status == -45061 {
            return Ok(false);
        }
        Err(VmError::AdiCallFailed { name: "IsMachineProvisioned", code: d.status })
    }

    pub fn set_routing(&mut self, dsid: i64, routing: u64) -> Result<(), VmError> {
        let mut m = Vec::new();
        m.extend(be_i64(dsid));
        m.extend(be_u64(routing));
        self.dispatch(SET_IDMS_ROUTING, &m)?.check("SetIDMSRouting")
    }

    pub fn get_routing(&mut self, dsid: i64) -> Result<u64, VmError> {
        let route = self.out()?;
        let mut m = Vec::new();
        m.extend(be_i64(dsid));
        m.extend(be_u64(route));
        self.dispatch(GET_IDMS_ROUTING, &m)?.check("GetIDMSRouting")?;
        self.core.read_u64(route)
    }

    pub fn request_otp(&mut self, dsid: i64) -> Result<MacOtp, VmError> {
        let (mp, ml, op, ol) = (self.out()?, self.out()?, self.out()?, self.out()?);
        let mut m = Vec::new();
        m.extend(be_i64(dsid));
        m.extend(be_u64(mp));
        m.extend(be_u64(ml));
        m.extend(be_u64(op));
        m.extend(be_u64(ol));
        self.dispatch(REQUEST_OTP, &m)?.check("RequestOTP")?;
        Ok(MacOtp {
            machine_id: self.read_slice(mp, ml)?,
            otp: self.read_slice(op, ol)?,
        })
    }

    pub fn start_provisioning(&mut self, dsid: i64, spim: &[u8]) -> Result<MacProvisioningStart, VmError> {
        let spim_buf = self.buf(spim)?;
        let (cp, cl, sess) = (self.out()?, self.out()?, self.out()?);
        let mut m = Vec::new();
        m.extend(be_i64(dsid));
        m.extend(be_u64(spim_buf));
        m.extend(be_u32(spim.len() as u32));
        m.extend(be_u64(cp));
        m.extend(be_u64(cl));
        m.extend(be_u64(sess));
        self.dispatch(PROVISIONING_START, &m)?.check("ProvisioningStart")?;
        Ok(MacProvisioningStart {
            cpim: self.read_slice(cp, cl)?,
            session: self.core.read_u32(sess)?,
        })
    }

    pub fn end_provisioning(&mut self, session: u32, ptm: &[u8], tk: &[u8]) -> Result<(), VmError> {
        let (pb, tb) = (self.buf(ptm)?, self.buf(tk)?);
        let mut m = Vec::new();
        m.extend(be_u32(session));
        m.extend(be_u64(pb));
        m.extend(be_u32(ptm.len() as u32));
        m.extend(be_u64(tb));
        m.extend(be_u32(tk.len() as u32));
        self.dispatch(PROVISIONING_END, &m)?.check("ProvisioningEnd")
    }
}
