use std::collections::HashMap;

use goblin::elf::program_header::PT_LOAD;
use goblin::elf::section_header::SHN_UNDEF;
use goblin::elf::{Elf, Reloc};
use unicorn_engine::unicorn_const::{Arch, HookType, Mode, Prot, uc_error};
use unicorn_engine::X86CpuModel;
use unicorn_engine::{RegisterARM64, RegisterX86, Unicorn};

use crate::arch::EmuArch;
use crate::constants::{
    ARG_REGS, IMPORT_ADDRESS, IMPORT_LIBRARY_COUNT, IMPORT_LIBRARY_STRIDE, IMPORT_SIZE,
    LIB_RESERVATION_SIZE, MALLOC_ADDRESS, MALLOC_SIZE, PAGE_SIZE, RET_AARCH64, RETURN_ADDRESS,
    STACK_ADDRESS, STACK_SIZE,
};
use crate::debug::{debug_print, trace_mem_invalid_hook};
use crate::errors::VmError;
use crate::runtime::{LoadedLibrary, RuntimeState, SymbolEntry};
use crate::stub::dispatch_import_stub;
use crate::util::{add_i64, align_down, align_up, as_usize};

thread_local! {
    static CORE_TRACE: std::cell::RefCell<std::collections::VecDeque<(u64, u32)>> =
        std::cell::RefCell::new(std::collections::VecDeque::new());
    // EMU_CORE_TRACE_FILE=path: full per-instruction (offset, GP regs) trace of the core
    // region, written to a file for offline differential alignment (docs/14 approach 1).
    static CORE_TRACE_FILE: std::cell::RefCell<Option<(std::io::BufWriter<std::fs::File>, u64)>> =
        std::cell::RefCell::new(None);
    // EMU_ADID_TRACE: full instruction trace over adid's whole text range, armed at EMU_TRACE_FROM.
    static ADID_TRACE: std::cell::RefCell<Option<(std::io::BufWriter<std::fs::File>, bool, u64)>> =
        std::cell::RefCell::new(None);
}

/// Flush the full-instruction trace file if one is open (called from the negative-return
/// dump so the tail of a failing run is never lost).
pub(crate) fn flush_core_trace_file() {
    use std::io::Write;
    CORE_TRACE_FILE.with(|c| {
        if let Some((w, _)) = c.borrow_mut().as_mut() {
            let _ = w.flush();
        }
    });
}

pub struct EmuCore {
    uc: Unicorn<'static, RuntimeState>,
}

impl EmuCore {
    pub fn new_arm64() -> Result<Self, VmError> {
        Self::new(EmuArch::Arm64)
    }

    pub fn new_x86_64() -> Result<Self, VmError> {
        Self::new(EmuArch::X86_64)
    }

    pub fn new(arch: EmuArch) -> Result<Self, VmError> {
        let (uc_arch, uc_mode) = match arch {
            EmuArch::Arm64 => (Arch::ARM64, Mode::ARM),
            EmuArch::X86_64 => (Arch::X86, Mode::MODE_64),
        };
        let mut uc = Unicorn::new_with_data(uc_arch, uc_mode, RuntimeState::new(arch))?;

        if arch == EmuArch::X86_64 {
            // The default x86_64 CPU model (qemu64) lacks SSE4.1; the SSC/core use pmulld etc.
            // Pick a model that has SSE4.1/4.2 + AVX.
            uc.ctl_set_cpu_model(19i32)?;
            // Unicorn starts x86_64 with SSE disabled; enable FPU + SSE so those don't fault:
            //   CR0: clear EM (bit2), set MP (bit1); CR4: set OSFXSR (bit9), OSXMMEXCPT (bit10)
            let cr0 = uc.reg_read(RegisterX86::CR0)?;
            uc.reg_write(RegisterX86::CR0, (cr0 & !(1 << 2)) | (1 << 1))?;
            let cr4 = uc.reg_read(RegisterX86::CR4)?;
            uc.reg_write(RegisterX86::CR4, cr4 | (1 << 9) | (1 << 10))?;
        }

        // EMU_WATCH=0xADDR[,0xADDR...] : dump registers when PC hits each address.
        if let Ok(spec) = std::env::var("EMU_WATCH") {
            for tok in spec.split(',') {
                let t = tok.trim().trim_start_matches("0x");
                if let Ok(at) = u64::from_str_radix(t, 16) {
                    uc.add_code_hook(at, at + 1, move |uc, a, _| {
                        let r = |x| uc.reg_read(x).unwrap_or(0);
                        eprintln!("[watch 0x{a:X}] rax=0x{:X} rcx=0x{:X} rdx=0x{:X} rbx=0x{:X} rsi=0x{:X} rdi=0x{:X}",
                            r(RegisterX86::RAX), r(RegisterX86::RCX), r(RegisterX86::RDX),
                            r(RegisterX86::RBX), r(RegisterX86::RSI), r(RegisterX86::RDI));
                    }).ok();
                }
            }
        }

        // EMU_ADID_TRACE=path (+ EMU_TRACE_FROM=0xADDR): per-instruction trace of the whole
        // adid text range, armed when pc first hits EMU_TRACE_FROM. For reversing the OTP handler.
        if arch == EmuArch::X86_64 {
            if let Ok(path) = std::env::var("EMU_ADID_TRACE") {
                if let Ok(f) = std::fs::File::create(&path) {
                    use std::io::Write;
                    let mut w = std::io::BufWriter::new(f);
                    let _ = writeln!(w, "# vmaddr	rax	rbx	rcx	rdx	rsi	rdi	r12	r13	r14	r15");
                    ADID_TRACE.with(|c| *c.borrow_mut() = Some((w, false, 0)));
                    eprintln!("[adid-trace] -> {path}");
                }
                let from = std::env::var("EMU_TRACE_FROM").ok()
                    .and_then(|v| u64::from_str_radix(v.trim().trim_start_matches("0x"), 16).ok())
                    .unwrap_or(0);
                uc.add_code_hook(0x1_0010_0000, 0x1_004b_0000, move |uc, address, _| {
                    ADID_TRACE.with(|c| {
                        use std::io::Write;
                        if let Some((w, armed, n)) = c.borrow_mut().as_mut() {
                            if !*armed && from != 0 && address == from { *armed = true; }
                            if *armed {
                                let r = |x| uc.reg_read(x).unwrap_or(0);
                                let _ = write!(w, "{:x}", address - 0x100000);
                                for reg in [RegisterX86::RAX, RegisterX86::RBX, RegisterX86::RCX,
                                            RegisterX86::RDX, RegisterX86::RSI, RegisterX86::RDI,
                                            RegisterX86::R12, RegisterX86::R13, RegisterX86::R14, RegisterX86::R15] {
                                    let _ = write!(w, "	{:x}", r(reg));
                                }
                                let _ = writeln!(w);
                                *n += 1;
                                if *n % 4096 == 0 { let _ = w.flush(); }
                            }
                        }
                    });
                }).ok();
            }
        }

        uc.mem_map(RETURN_ADDRESS, PAGE_SIZE, Prot::ALL)?;
        uc.mem_map(MALLOC_ADDRESS, MALLOC_SIZE, Prot::ALL)?;
        uc.mem_map(crate::constants::DATA_IMPORT_BASE, crate::constants::DATA_IMPORT_SIZE, Prot::ALL)?;
        uc.mem_map(STACK_ADDRESS, STACK_SIZE, Prot::ALL)?;

        // EMU_LAZY_MAP: bring-up aid for emulating full executables (e.g. adid) — on an unmapped
        // data read/write, lazily map a zeroed page and retry, so dyld-uninitialized globals and
        // missing structures read as 0 instead of faulting. Does NOT cover FETCH (unmapped code
        // stays a real error, to avoid running into zero-filled regions).
        if std::env::var("EMU_LAZY_MAP").is_ok() {
            uc.add_mem_hook(HookType::MEM_READ_UNMAPPED, 0, u64::MAX, |uc, _t, addr, _sz, _v| {
                let page = addr & !0xfffu64;
                let _ = uc.mem_map(page, 0x1000, Prot::ALL);
                if std::env::var("EMU_LAZY_MAP_DEBUG").is_ok() { eprintln!("[lazy-map] R 0x{page:X}"); }
                true
            }).ok();
            uc.add_mem_hook(HookType::MEM_WRITE_UNMAPPED, 0, u64::MAX, |uc, _t, addr, _sz, _v| {
                let page = addr & !0xfffu64;
                let _ = uc.mem_map(page, 0x1000, Prot::ALL);
                if std::env::var("EMU_LAZY_MAP_DEBUG").is_ok() { eprintln!("[lazy-map] W 0x{page:X}"); }
                true
            }).ok();
        }

        // EMU_DUMP_MEM=<hexoff>:<hexaddr>:<hexsize> — when PC first hits core offset <hexoff>,
        // hexdump [addr,addr+size] (16B/line with LE-word view). For inspecting the hash-input
        // heap buffers that drive the -45076 state machine.
        if let Ok(spec) = std::env::var("EMU_DUMP_MEM") {
            let parts: Vec<&str> = spec.split(':').collect();
            if parts.len() == 3 {
                if let (Ok(off), Ok(addr), Ok(size)) = (
                    u64::from_str_radix(parts[0].trim_start_matches("0x"),16),
                    u64::from_str_radix(parts[1].trim_start_matches("0x"),16),
                    u64::from_str_radix(parts[2].trim_start_matches("0x"),16)) {
                    use std::sync::atomic::{AtomicBool, Ordering};
                    static DONE: AtomicBool = AtomicBool::new(false);
                    let at = 0x1010_0000 + off;
                    uc.add_code_hook(at, at + 1, move |uc, _a, _| {
                        if DONE.swap(true, Ordering::Relaxed) { return; }
                        let mut buf = vec![0u8; size as usize];
                        if uc.mem_read(addr, &mut buf).is_ok() {
                            for (i, ch) in buf.chunks(16).enumerate() {
                                let hex: String = ch.iter().map(|b| format!("{b:02x}")).collect();
                                let mut w = String::new();
                                for c in ch.chunks(8) { if c.len()==8 { w.push_str(&format!(" {:016x}", u64::from_le_bytes(c.try_into().unwrap()))); } }
                                eprintln!("[mem 0x{:X}] {hex} |{w}", addr + (i*16) as u64);
                            }
                        } else { eprintln!("[mem] unreadable 0x{addr:X}"); }
                    }).ok();
                }
            }
        }

        // EMU_CTX_READS=<hexaddr>:<size> — log reads from the ADI ctx window beyond the known
        // state(0x0)/state(0x8)/fnptr(0x10,0x18) slots, to find which ctx field the auth gate
        // branches on. Logs pc + offset + value; caps output.
        if let Ok(spec) = std::env::var("EMU_CTX_READS") {
            if let Some((a, s)) = spec.split_once(':') {
                if let (Ok(base), Ok(size)) = (u64::from_str_radix(a.trim_start_matches("0x"),16), u64::from_str_radix(s.trim_start_matches("0x"),16)) {
                    use std::sync::atomic::{AtomicU32, Ordering};
                    static N: AtomicU32 = AtomicU32::new(0);
                    uc.add_mem_hook(HookType::MEM_READ, base, base + size, move |uc, _t, addr, sz, _v| {
                        let off = addr - base;
                        if off >= 0x20 {
                            let n = N.fetch_add(1, Ordering::Relaxed);
                            if n < 400 {
                                let mut b=[0u8;8]; let _=uc.mem_read(addr, &mut b[..sz.min(8) as usize]);
                                let v=u64::from_le_bytes(b);
                                let pc=uc.reg_read(RegisterX86::RIP).unwrap_or(0);
                                eprintln!("[ctxread] pc=0x{:X} off=0x{off:X} sz={sz} val=0x{v:X}", pc.wrapping_sub(0x1010_0000));
                            }
                        }
                        true
                    }).ok();
                }
            }
        }

        // Debug (EMU_CORE_TRACE=1): keep a ring of the most recent (pc, eax) over the core
        // region so a failing ADI call can be traced back to the instruction that set the
        // error code. Dumped by invoke_cdecl on a negative return. x86_64 only.
        if arch == EmuArch::X86_64 && std::env::var("EMU_CORE_TRACE").is_ok() {
            if let Ok(spec) = std::env::var("EMU_SETCL_AT") {
                // "OFF:V" — force CL=V just before the instruction at core offset OFF.
                if let Some((o, v)) = spec.split_once(':') {
                    if let (Ok(off), Ok(val)) = (u64::from_str_radix(o.trim_start_matches("0x"),16), v.parse::<u64>()) {
                        let at = 0x1010_0000 + off;
                        uc.add_code_hook(at, at + 1, move |uc, _a, _| {
                            let rcx = uc.reg_read(RegisterX86::RCX).unwrap_or(0);
                            let _ = uc.reg_write(RegisterX86::RCX, (rcx & !0xff) | (val & 0xff));
                        }).ok();
                    }
                }
            }
            if let Ok(spec) = std::env::var("EMU_SET_RDX_AT") {
                // "OFF:HEXVAL" — set RDX := HEXVAL just before the instruction at OFF.
                if let Some((o, v)) = spec.split_once(':') {
                    if let (Ok(off), Ok(val)) = (u64::from_str_radix(o.trim_start_matches("0x"),16), u64::from_str_radix(v.trim_start_matches("0x"),16)) {
                        let at = 0x1010_0000 + off;
                        uc.add_code_hook(at, at + 1, move |uc, _a, _| {
                            let _ = uc.reg_write(RegisterX86::RDX, val);
                        }).ok();
                    }
                }
            }
            if let Ok(hex) = std::env::var("EMU_FORCE_ALEQCL_AT") {
                // Force AL := CL just before the instruction at OFF, so a `cmpb %cl,%al`
                // sees them equal (sete=1). Steers the flattened auth branch to the
                // "matched" successor (next index = state + 1).
                if let Ok(off) = u64::from_str_radix(hex.trim_start_matches("0x"), 16) {
                    let at = 0x1010_0000 + off;
                    uc.add_code_hook(at, at + 1, move |uc, _a, _| {
                        let rax = uc.reg_read(RegisterX86::RAX).unwrap_or(0);
                        let rcx = uc.reg_read(RegisterX86::RCX).unwrap_or(0);
                        let _ = uc.reg_write(RegisterX86::RAX, (rax & !0xff) | (rcx & 0xff));
                    }).ok();
                }
            }
            if let Ok(hex) = std::env::var("EMU_FORCE_EAX0_AT") {
                if let Ok(off) = u64::from_str_radix(hex.trim_start_matches("0x"), 16) {
                    let at = 0x1010_0000 + off;
                    uc.add_code_hook(at, at + 1, move |uc, _a, _| {
                        // Neutralize a specific error-emission block: force the return reg to 0.
                        let _ = uc.reg_write(RegisterX86::RAX, 0);
                    }).ok();
                }
            }
            if let Ok(hex) = std::env::var("EMU_HOOK_OFF") {
                if let Ok(off) = u64::from_str_radix(hex.trim_start_matches("0x"), 16) {
                    let at = 0x1010_0000 + off;
                    uc.add_code_hook(at, at + 1, move |uc, _a, _| {
                        let r = |x| uc.reg_read(x).unwrap_or(0);
                        let (rdi, rsi, rdx, rcx) = (r(RegisterX86::RDI), r(RegisterX86::RSI), r(RegisterX86::RDX), r(RegisterX86::RCX));
                        let rax = r(RegisterX86::RAX); let r14 = r(RegisterX86::R14); let rbx = r(RegisterX86::RBX);
                        let dump = |a: u64| { let mut b=[0u8;48]; if a!=0 && uc.mem_read(a,&mut b).is_ok() { b.iter().map(|x| format!("{x:02x}")).collect::<String>() } else { "-".into() } };
                        eprintln!("[hook 0x{off:X}] rax=0x{rax:X} rbx=0x{rbx:X} r14=0x{r14:X} rdi=0x{rdi:X} rsi=0x{rsi:X} rdx=0x{rdx:X} rcx=0x{rcx:X} [rdi]={} [rsi]={}", dump(rdi), dump(rsi));
                    }).ok();
                }
            }
            if let Ok(nstr) = std::env::var("EMU_DUMP_CTX") {
                let n: u64 = nstr.trim().parse().unwrap_or(0x200);
                let cvu_off = std::env::var("EMU_CVU_OFF").ok()
                    .and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"),16).ok())
                    .unwrap_or(0x82650);
                let at = 0x1010_0000u64 + cvu_off;
                uc.add_code_hook(at, at + 1, move |uc, _a, _| {
                    let ctx = uc.reg_read(RegisterX86::RDI).unwrap_or(0);
                    let sel = uc.reg_read(RegisterX86::RSI).unwrap_or(0);
                    let rdx = uc.reg_read(RegisterX86::RDX).unwrap_or(0);
                    let rcx = uc.reg_read(RegisterX86::RCX).unwrap_or(0);
                    let rdstr = |a: u64| -> String { if a==0 {return "<null>".into();} let mut b=[0u8;160]; if uc.mem_read(a,&mut b).is_ok() { let end=b.iter().position(|&x|x==0).unwrap_or(b.len()); String::from_utf8_lossy(&b[..end]).into_owned() } else { "<unreadable>".into() } };
                    eprintln!("[cvu] ctx=0x{ctx:X} sel=0x{sel:X} rdx=0x{rdx:X} rcx=0x{rcx:X} [rcx]=\"{}\" [rdx]=\"{}\"", rdstr(rcx), rdstr(rdx));
                    let mut buf = vec![0u8; n as usize];
                    if uc.mem_read(ctx, &mut buf).is_ok() {
                        for (i, chunk) in buf.chunks(16).enumerate() {
                            let hex: String = chunk.iter().map(|b| format!("{b:02x}")).collect();
                            // interpret 8-byte little-endian words to spot pointers
                            let mut words = String::new();
                            for w in chunk.chunks(8) {
                                if w.len()==8 { let v=u64::from_le_bytes(w.try_into().unwrap()); words.push_str(&format!(" {v:016x}")); }
                            }
                            eprintln!("[ctx+0x{:03x}] {hex}  |{words}", i*16);
                        }
                    }
                }).ok();
            }
            if let Ok(dir) = std::env::var("EMU_FULL_SNAPSHOT") {
                // Dump EVERY mapped region + all GP registers at the first vdf entry (or
                // EMU_SNAP_OFF), so a native replayer can MAP_FIXED the exact state and run
                // vdf on a real CPU. Writes <dir>/manifest.txt + <dir>/seg_<addr>.bin.
                let voff = std::env::var("EMU_SNAP_OFF").ok()
                    .and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"),16).ok())
                    .unwrap_or(0x17bf60);
                let at = 0x1010_0000u64 + voff;
                let done = std::cell::Cell::new(false);
                let dir = dir.clone();
                uc.add_code_hook(at, at + 1, move |uc, _a, _| {
                    if done.get() { return; } done.set(true);
                    use std::io::Write;
                    let _ = std::fs::create_dir_all(&dir);
                    let mut man = std::fs::File::create(format!("{dir}/manifest.txt")).unwrap();
                    // registers
                    let rr = |r| uc.reg_read(r).unwrap_or(0);
                    let regs = [
                        ("rax",RegisterX86::RAX),("rbx",RegisterX86::RBX),("rcx",RegisterX86::RCX),
                        ("rdx",RegisterX86::RDX),("rsi",RegisterX86::RSI),("rdi",RegisterX86::RDI),
                        ("rbp",RegisterX86::RBP),("rsp",RegisterX86::RSP),("r8",RegisterX86::R8),
                        ("r9",RegisterX86::R9),("r10",RegisterX86::R10),("r11",RegisterX86::R11),
                        ("r12",RegisterX86::R12),("r13",RegisterX86::R13),("r14",RegisterX86::R14),
                        ("r15",RegisterX86::R15),("rip",RegisterX86::RIP),("rflags",RegisterX86::EFLAGS),
                    ];
                    let regline: String = regs.iter().map(|(n,r)| format!("{n}=0x{:x}", rr(*r))).collect::<Vec<_>>().join(" ");
                    let _ = writeln!(man, "REGS {regline}");
                    // all memory regions
                    if let Ok(regions) = uc.mem_regions() {
                        for reg in regions {
                            let size = (reg.end - reg.begin + 1) as usize;
                            if let Ok(bytes) = uc.mem_read_as_vec(reg.begin, size) {
                                let fname = format!("seg_{:x}.bin", reg.begin);
                                let _ = std::fs::write(format!("{dir}/{fname}"), &bytes);
                                let _ = writeln!(man, "SEG 0x{:x} 0x{:x} perms=0x{:x} {fname}", reg.begin, size, reg.perms);
                            }
                        }
                    }
                    { let c = uc.get_data().malloc_allocator.cursor(); let _ = writeln!(man, "MALLOC_CURSOR 0x{c:x}"); }
                    // import symbol tables: stub addr = IMPORT_ADDRESS + lib*STRIDE + idx*4
                    {
                        let state = uc.get_data();
                        for (lib_i, lib) in state.loaded_libraries.iter().enumerate() {
                            for (sym_i, sym) in lib.symbols.iter().enumerate() {
                                if sym.name.is_empty() { continue; }
                                let stub = 0xA000_0000u64 + (lib_i as u64)*0x0100_0000 + (sym_i as u64)*4;
                                let _ = writeln!(man, "IMPORT 0x{stub:x} {}", sym.name);
                            }
                        }
                    }
                    let _ = man.flush();
                    eprintln!("[full-snapshot] wrote state at vdf entry to {dir}");
                }).ok();
            }
            if let Ok(spath) = std::env::var("EMU_VDF_SNAPSHOT") {
                // BFS-dump the memory closure reachable from the vdfut args pointer (rsi) at the
                // first vdfut768ig call, so a native harness can replay the exact arg state.
                let voff = std::env::var("EMU_VDF_OFF").ok()
                    .and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"),16).ok())
                    .unwrap_or(0x17bf60);
                let at = 0x1010_0000u64 + voff;
                let done = std::cell::Cell::new(false);
                uc.add_code_hook(at, at + 1, move |uc, _a, _| {
                    if done.get() { return; } done.set(true);
                    use std::io::Write;
                    let op = uc.reg_read(RegisterX86::RDI).unwrap_or(0) as u32;
                    let rsi = uc.reg_read(RegisterX86::RSI).unwrap_or(0);
                    let mut out = std::fs::File::create(&spath).unwrap();
                    let _ = writeln!(out, "op=0x{op:08x} argp=0x{rsi:x}");
                    let mut seen: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
                    let mut queue: std::collections::VecDeque<(u64,u32)> = std::collections::VecDeque::new();
                    queue.push_back((rsi, 0));
                    while let Some((addr, depth)) = queue.pop_front() {
                        let page = addr & !0xffu64;
                        if seen.contains(&page) || seen.len() > 400 { continue; }
                        let mut buf = [0u8; 256];
                        if uc.mem_read(page, &mut buf).is_err() { continue; }
                        seen.insert(page);
                        let hx: String = buf.iter().map(|b| format!("{b:02x}")).collect();
                        let _ = writeln!(out, "R 0x{page:x} {hx}");
                        if depth < 5 {
                            for w in buf.chunks(8) {
                                let v = u64::from_le_bytes(w.try_into().unwrap());
                                // plausible pointer: emulator mapped ranges (SSC/stack/core/heap)
                                if (v > 0x1000 && v < 0x200_0000)            // SSC/low data
                                   || (0x6000_0000..0x6100_0000).contains(&v) // malloc
                                   || (0xF000_0000..0xF010_0000).contains(&v) // stack
                                   || (0x1010_0000..0x2010_0000).contains(&v) // core
                                { queue.push_back((v, depth+1)); }
                            }
                        }
                    }
                    let _ = out.flush();
                    eprintln!("[vdf-snapshot] wrote {} pages for op=0x{op:08x} argp=0x{rsi:x} to {spath}", seen.len());
                }).ok();
            }
            if let Ok(vstr) = std::env::var("EMU_VDF_OFF") {
                if let Ok(voff) = u64::from_str_radix(vstr.trim_start_matches("0x"),16) {
                    let at = 0x1010_0000u64 + voff;
                    uc.add_code_hook(at, at + 1, move |uc, _a, _| {
                        let op = uc.reg_read(RegisterX86::RDI).unwrap_or(0) as u32;
                        let argp = uc.reg_read(RegisterX86::RSI).unwrap_or(0);
                        let mut b = [0u8; 96];
                        let hx = if uc.mem_read(argp, &mut b).is_ok() {
                            b.iter().map(|x| format!("{x:02x}")).collect::<String>()
                        } else { "<unmapped>".into() };
                        eprintln!("[vdf] op=0x{op:08X} args@0x{argp:X}={hx}");
                        // Follow each 8-byte word that looks like a pointer and dump its target.
                        if std::env::var("EMU_VDF_DEEP").is_ok() {
                            for wi in 0..12usize {
                                let w = u64::from_le_bytes(b[wi*8..wi*8+8].try_into().unwrap());
                                if w > 0x1000 && w < 0x2_0000_0000 {
                                    let mut t = [0u8; 48];
                                    if uc.mem_read(w, &mut t).is_ok() {
                                        let th: String = t.iter().map(|x| format!("{x:02x}")).collect();
                                        let asc: String = t.iter().map(|&c| if (0x20..0x7f).contains(&c) { c as char } else { '.' }).collect();
                                        eprintln!("   arg+0x{:02x} -> 0x{w:X}: {th}  |{asc}|", wi*8);
                                    }
                                }
                            }
                        }
                    }).ok();
                }
            }
            let want = std::env::var("EMU_WATCH_EAX").ok()
                .and_then(|v| u32::from_str_radix(v.trim_start_matches("0x"), 16).ok());
            let wlast = std::cell::Cell::new(0u32);
            // EMU_CORE_TRACE_FILE=path: open a full per-instruction trace file (offset + GP regs).
            if let Ok(path) = std::env::var("EMU_CORE_TRACE_FILE") {
                if let Ok(f) = std::fs::File::create(&path) {
                    use std::io::Write;
                    let mut w = std::io::BufWriter::new(f);
                    let _ = writeln!(w, "# off\trax\trbx\trcx\trdx\trsi\trdi\tr8\tr9\tr10\tr11\tr12\tr13\tr14\tr15");
                    CORE_TRACE_FILE.with(|c| *c.borrow_mut() = Some((w, 0)));
                    eprintln!("[core-trace-file] writing full instruction trace to {path}");
                }
            }
            uc.add_code_hook(0x1010_0000, 0x2010_0000, move |uc, address, _| {
                let eax = uc.reg_read(RegisterX86::RAX).unwrap_or(0) as u32;
                let off = address - 0x1010_0000;
                CORE_TRACE_FILE.with(|c| {
                    use std::io::Write;
                    if let Some((w, n)) = c.borrow_mut().as_mut() {
                        let r = |x| uc.reg_read(x).unwrap_or(0);
                        let _ = write!(w, "{off:x}");
                        for reg in [RegisterX86::RAX, RegisterX86::RBX, RegisterX86::RCX, RegisterX86::RDX,
                                    RegisterX86::RSI, RegisterX86::RDI, RegisterX86::R8, RegisterX86::R9,
                                    RegisterX86::R10, RegisterX86::R11, RegisterX86::R12, RegisterX86::R13,
                                    RegisterX86::R14, RegisterX86::R15] {
                            let _ = write!(w, "\t{:x}", r(reg));
                        }
                        // Resolve the gate's indirect call `call [r15+rax*8]` at offset 0x10770a:
                        // compute and annotate the actual target so we learn what macOS calls here.
                        if off == 0x10770a {
                            let r15 = r(RegisterX86::R15); let rax = r(RegisterX86::RAX);
                            let slot = r15.wrapping_add(rax.wrapping_mul(8));
                            let mut b = [0u8; 8];
                            let tgt = if uc.mem_read(slot, &mut b).is_ok() { u64::from_le_bytes(b) } else { 0 };
                            let _ = write!(w, "\tCALL_SLOT=0x{slot:x}\tCALL_TGT=0x{tgt:x}\tTGT_OFF=0x{:x}",
                                           tgt.wrapping_sub(0x1010_0000));
                        }
                        let _ = writeln!(w);
                        *n += 1;
                        if *n % 4096 == 0 { let _ = w.flush(); }
                    }
                });
                if let Some(w) = want {
                    if eax == w && wlast.get() != w {
                        eprintln!("[watch] EAX->0x{w:08X} at core pc=0x{address:X} (off 0x{:X}); lead-up:", address - 0x1010_0000);
                        CORE_TRACE.with(|r| {
                            for (pc, _e) in r.borrow().iter() {
                                eprintln!("  LEAD off=0x{:X}", pc - 0x1010_0000);
                            }
                        });
                    }
                    wlast.set(eax);
                }
                CORE_TRACE.with(|r| {
                    let mut r = r.borrow_mut();
                    if r.len() == 400 {
                        r.pop_front();
                    }
                    r.push_back((address, eax));
                });
            })?;
        }

        if arch == EmuArch::X86_64 && std::env::var("EMU_DATA_READ").is_ok() {
            let seen = std::cell::Cell::new(0u64);
            uc.add_mem_hook(HookType::MEM_READ, 0x102D_A000, 0x102D_C200, move |uc, _t, addr, sz, _v| {
                let pc = uc.reg_read(RegisterX86::RIP).unwrap_or(0);
                if (0x1010_0000..0x2010_0000).contains(&pc) {
                    let mut b=[0u8;8]; let _=uc.mem_read(addr,&mut b[..sz.min(8)]);
                    let n=seen.get();
                    if n<60 { eprintln!("[data-read] pc=off0x{:X} reads __data off0x{:X} sz{} val=0x{:X}", pc-0x1010_0000, addr-0x1010_0000, sz, u64::from_le_bytes(b)); }
                    seen.set(n+1);
                }
                true
            }).ok();
        }
        if arch == EmuArch::X86_64 && std::env::var("EMU_CODE_READ").is_ok() {
            let seen = std::cell::Cell::new(0u64);
            uc.add_mem_hook(HookType::MEM_READ, 0x1010_08E0, 0x1028_6574, move |uc, _t, addr, _sz, _v| {
                let pc = uc.reg_read(RegisterX86::RIP).unwrap_or(0);
                // only code-region reads from code-region PCs (self-inspection / integrity)
                if (0x1010_0000..0x1028_6574).contains(&pc) {
                    let n = seen.get();
                    if n < 24 { eprintln!("[code-read] pc=0x{:X}(off 0x{:X}) reads code 0x{:X}(off 0x{:X})", pc, pc-0x1010_0000, addr, addr-0x1010_0000); }
                    seen.set(n+1);
                }
                true
            }).ok();
        }
        for i in 0..IMPORT_LIBRARY_COUNT {
            let base = IMPORT_ADDRESS + (i as u64) * IMPORT_LIBRARY_STRIDE;
            uc.mem_map(base, IMPORT_SIZE, Prot::ALL)?;

            // Each import slot must begin with a return instruction so, after the code hook
            // runs the Rust stub, control returns to the caller. AArch64 `ret` is 4 bytes;
            // x86_64 `ret` is the single byte 0xC3.
            let stubs = match arch {
                EmuArch::Arm64 => {
                    let mut s = vec![0_u8; IMPORT_SIZE as usize];
                    for chunk in s.chunks_mut(4) {
                        chunk.copy_from_slice(&RET_AARCH64);
                    }
                    s
                }
                EmuArch::X86_64 => vec![0xC3_u8; IMPORT_SIZE as usize],
            };
            uc.mem_write(base, &stubs)?;

            uc.add_code_hook(base, base + IMPORT_SIZE - 1, |uc, address, _| {
                if let Err(err) = dispatch_import_stub(uc, address) {
                    debug_print(format!("import hook failed at 0x{address:X}: {err}"));
                    let _ = uc.emu_stop();
                }
            })?;
        }

        uc.add_mem_hook(
            HookType::MEM_READ_UNMAPPED
                | HookType::MEM_WRITE_UNMAPPED
                | HookType::MEM_FETCH_UNMAPPED,
            1,
            0,
            |uc, access, address, size, value| {
                trace_mem_invalid_hook(uc, access, address, size, value);
                false
            },
        )?;

        Ok(Self { uc })
    }

    pub fn register_library_blob(&mut self, name: impl Into<String>, data: Vec<u8>) {
        self.uc
            .get_data_mut()
            .library_blobs
            .insert(name.into(), data);
    }

    pub fn set_library_root(&mut self, path: &str) {
        let normalized = normalize_library_root(path);
        if normalized.is_empty() {
            return;
        }
        self.uc.get_data_mut().library_root = Some(normalized);
    }

    pub fn load_library(&mut self, library_name: &str) -> Result<usize, VmError> {
        load_library_by_name(&mut self.uc, library_name)
    }

    pub fn resolve_symbol_by_name(
        &self,
        library_index: usize,
        symbol_name: &str,
    ) -> Result<u64, VmError> {
        resolve_symbol_from_loaded_library_by_name(&self.uc, library_index, symbol_name)
    }

    /// Instrumentation (EMU_TRACE_VDFUT): hook the core's `vdfut768ig`/`cvu8io98wun`
    /// dispatch exports and log, on each entry, the ADI opcode + the argument-block pointer
    /// and the bytes it points at. On x86_64 SSC calls these exports directly with
    /// `vdfut768ig(uint32 opcode = edi, void *args = rsi)`, so this recovers the opcode +
    /// arg-struct for each ADI call — the table a driver-less native/WASM core needs.
    pub fn install_vdfut_trace(&mut self) -> Result<(), VmError> {
        let arch = self.uc.get_data().arch;
        let mut entries: Vec<(&'static str, u64)> = Vec::new();
        {
            let state = self.uc.get_data();
            for lib in &state.loaded_libraries {
                for name in ["vdfut768ig", "cvu8io98wun"] {
                    if let Some(&addr) = lib.symbols_by_name.get(name) {
                        entries.push((if name == "vdfut768ig" { "vdfut768ig" } else { "cvu8io98wun" }, addr));
                        eprintln!("[trace] {name} @ 0x{addr:X}");
                    }
                }
            }
        }
        for (name, addr) in entries {
            self.uc.add_code_hook(addr, addr + 3, move |uc, _address, _| {
                // opcode = arg0, args = arg1 under the platform ABI.
                let (op, argp) = match arch {
                    EmuArch::Arm64 => (
                        uc.reg_read(RegisterARM64::X0).unwrap_or(0),
                        uc.reg_read(RegisterARM64::X1).unwrap_or(0),
                    ),
                    EmuArch::X86_64 => (
                        uc.reg_read(RegisterX86::RDI).unwrap_or(0),
                        uc.reg_read(RegisterX86::RSI).unwrap_or(0),
                    ),
                };
                let mut buf = [0u8; 128];
                let hexbuf = if uc.mem_read(argp, &mut buf).is_ok() {
                    buf.iter().map(|b| format!("{b:02x}")).collect::<String>()
                } else {
                    "<unmapped>".into()
                };
                eprintln!(
                    "VDFUT_TRACE fn={name} op=0x{:08X} args@0x{argp:X}={hexbuf}",
                    op as u32
                );
            })?;
        }
        Ok(())
    }

    pub fn invoke_cdecl(&mut self, address: u64, args: &[u64]) -> Result<u64, VmError> {
        debug_print(format!("Calling 0x{address:X}"));
        match self.uc.get_data().arch {
            EmuArch::Arm64 => {
                if args.len() > ARG_REGS.len() {
                    return Err(VmError::TooManyArguments(args.len()));
                }
                for (index, value) in args.iter().enumerate() {
                    self.uc.reg_write(ARG_REGS[index], *value)?;
                }
                self.uc
                    .reg_write(RegisterARM64::SP, STACK_ADDRESS + STACK_SIZE)?;
                self.uc.reg_write(RegisterARM64::LR, RETURN_ADDRESS)?;
                self.uc.emu_start(address, RETURN_ADDRESS, 0, 0)?;
                Ok(self.uc.reg_read(RegisterARM64::X0)?)
            }
            EmuArch::X86_64 => {
                const X86_ARGS: [RegisterX86; 6] = [
                    RegisterX86::RDI,
                    RegisterX86::RSI,
                    RegisterX86::RDX,
                    RegisterX86::RCX,
                    RegisterX86::R8,
                    RegisterX86::R9,
                ];
                if args.len() > X86_ARGS.len() {
                    return Err(VmError::TooManyArguments(args.len()));
                }
                for (index, value) in args.iter().enumerate() {
                    self.uc.reg_write(X86_ARGS[index], *value)?;
                }
                // SysV requires 16-byte stack alignment at the `call`; after pushing the
                // return address the callee sees RSP % 16 == 8. Start 16-aligned, then push.
                let top = (STACK_ADDRESS + STACK_SIZE) & !0xF;
                let sp = top - 8;
                self.uc.mem_write(sp, &RETURN_ADDRESS.to_le_bytes())?;
                self.uc.reg_write(RegisterX86::RSP, sp)?;
                if let Err(e) = self.uc.emu_start(address, RETURN_ADDRESS, 0, 0) {
                    let rip = self.uc.reg_read(RegisterX86::RIP).unwrap_or(0);
                    eprintln!("[x86 call 0x{address:X} failed at RIP=0x{rip:X}: {e:?}]");
                    return Err(e.into());
                }
                let rax = self.uc.reg_read(RegisterX86::RAX)?;
                if (rax as u32 as i32) < 0 && std::env::var("EMU_CORE_TRACE").is_ok() {
                    CORE_TRACE.with(|r| {
                        eprintln!("[core-trace] last core insns before call 0x{address:X} ret=0x{:X}:", rax as u32);
                        for (pc, eax) in r.borrow().iter() {
                            eprintln!("  pc=0x{pc:X} eax=0x{eax:08X}");
                        }
                        r.borrow_mut().clear();
                    });
                    flush_core_trace_file();
                }
                Ok(rax)
            }
        }
    }

    /// Captured XPC event-handler block pointers (listener first, peer handlers next).
    pub fn xpc_handlers(&self) -> Vec<u64> {
        self.uc.get_data().xpc_event_handlers.clone()
    }

    /// Store the XPC request payload and allocate a guest buffer for it.
    pub fn set_xpc_request(&mut self, data: &[u8]) -> Result<(), VmError> {
        let ptr = self.alloc_data(data)?;
        let state = self.uc.get_data_mut();
        state.xpc_request = data.to_vec();
        state.xpc_request_ptr = Some(ptr);
        Ok(())
    }

    /// Take the captured XPC reply payload (the OTP response), if any.
    pub fn take_xpc_reply(&mut self) -> Option<Vec<u8>> {
        self.uc.get_data_mut().xpc_reply.take()
    }

    pub fn alloc_data(&mut self, data: &[u8]) -> Result<u64, VmError> {
        alloc_temp_bytes(&mut self.uc, data, 0xCC)
    }

    pub fn alloc_temporary(&mut self, length: usize) -> Result<u64, VmError> {
        let data = vec![0xAA; length.max(1)];
        alloc_temp_bytes(&mut self.uc, &data, 0xAA)
    }

    pub fn read_data(&self, address: u64, length: usize) -> Result<Vec<u8>, VmError> {
        Ok(self.uc.mem_read_as_vec(address, length)?)
    }

    pub fn write_data(&mut self, address: u64, data: &[u8]) -> Result<(), VmError> {
        self.uc.mem_write(address, data)?;
        Ok(())
    }

    pub fn read_u32(&self, address: u64) -> Result<u32, VmError> {
        let mut bytes = [0_u8; 4];
        self.uc.mem_read(address, &mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    pub fn read_u64(&self, address: u64) -> Result<u64, VmError> {
        let mut bytes = [0_u8; 8];
        self.uc.mem_read(address, &mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    pub fn write_u32(&mut self, address: u64, value: u32) -> Result<(), VmError> {
        self.uc.mem_write(address, &value.to_le_bytes())?;
        Ok(())
    }

    pub fn write_u64(&mut self, address: u64, value: u64) -> Result<(), VmError> {
        self.uc.mem_write(address, &value.to_le_bytes())?;
        Ok(())
    }


    pub fn read_c_string(&self, address: u64, max_len: usize) -> Result<String, VmError> {
        read_c_string(&self.uc, address, max_len)
    }
}

pub(crate) fn alloc_c_string(core: &mut EmuCore, value: &str) -> Result<u64, VmError> {
    let mut bytes = Vec::with_capacity(value.len() + 1);
    bytes.extend_from_slice(value.as_bytes());
    bytes.push(0);
    core.alloc_data(&bytes)
}

pub(crate) fn ensure_zero_return(name: &'static str, value: u64) -> Result<(), VmError> {
    let code = value as u32 as i32;
    if code == 0 {
        Ok(())
    } else if std::env::var("EMU_FORCE_ADI_OK").is_ok() {
        eprintln!("[force-adi-ok] {name} returned {code}; forcing OK");
        Ok(())
    } else {
        Err(VmError::AdiCallFailed { name, code })
    }
}

fn normalize_library_root(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let mut out = String::with_capacity(trimmed.len());
    let mut prev_slash = false;
    for ch in trimmed.chars() {
        if ch == '/' {
            if prev_slash {
                continue;
            }
            prev_slash = true;
        } else {
            prev_slash = false;
        }
        out.push(ch);
    }

    while out.len() > 1 && out.ends_with('/') {
        out.pop();
    }

    out
}

fn alloc_temp_bytes(
    uc: &mut Unicorn<'_, RuntimeState>,
    data: &[u8],
    padding_byte: u8,
) -> Result<u64, VmError> {
    let request = data.len().max(1) as u64;
    let length = align_up(request, PAGE_SIZE);
    let address = {
        let state = uc.get_data_mut();
        state.temp_allocator.alloc(length)?
    };

    debug_print(format!(
        "Allocating at 0x{address:X}; bytes 0x{:X}/0x{length:X}",
        data.len()
    ));
    uc.mem_map(address, length, Prot::ALL)?;

    let mut buffer = vec![padding_byte; length as usize];
    if !data.is_empty() {
        buffer[..data.len()].copy_from_slice(data);
    }
    uc.mem_write(address, &buffer)?;

    Ok(address)
}

pub(crate) fn set_errno(uc: &mut Unicorn<'_, RuntimeState>, value: u32) -> Result<(), VmError> {
    let errno_address = ensure_errno_address(uc)?;
    uc.mem_write(errno_address, &value.to_le_bytes())?;
    Ok(())
}

pub(crate) fn ensure_errno_address(uc: &mut Unicorn<'_, RuntimeState>) -> Result<u64, VmError> {
    if let Some(address) = uc.get_data().errno_address {
        return Ok(address);
    }

    let address = alloc_temp_bytes(uc, &[0, 0, 0, 0], 0)?;
    uc.get_data_mut().errno_address = Some(address);
    Ok(address)
}

pub(crate) fn load_library_by_name(
    uc: &mut Unicorn<'_, RuntimeState>,
    library_name: &str,
) -> Result<usize, VmError> {
    for (index, library) in uc.get_data().loaded_libraries.iter().enumerate() {
        if library.name == library_name {
            debug_print("Library already loaded");
            return Ok(index);
        }
    }

    // Dispatch on the container magic: Mach-O cores (the macOS CoreADI) go through the
    // Mach-O loader; everything else is ELF (the Android SSC + core).
    let magic = {
        let state = uc.get_data();
        state
            .library_blobs
            .get(library_name)
            .and_then(|d| d.get(0..4))
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    if magic == Some(0xfeedfacf) {
        return crate::macho::load_macho_library(uc, library_name);
    }

    let (library_index, elf_data) = {
        let state = uc.get_data();
        let data = state
            .library_blobs
            .get(library_name)
            .cloned()
            .ok_or_else(|| VmError::LibraryNotRegistered(library_name.to_string()))?;
        (state.loaded_libraries.len(), data)
    };

    let elf = Elf::parse(&elf_data)?;
    let base = {
        let state = uc.get_data_mut();
        state.library_allocator.alloc(LIB_RESERVATION_SIZE)?
    };

    let mut symbols = Vec::with_capacity(elf.dynsyms.len());
    let mut symbols_by_name = HashMap::new();

    for (index, sym) in elf.dynsyms.iter().enumerate() {
        let name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("").to_string();
        let resolved = if sym.st_shndx == SHN_UNDEF as usize {
            IMPORT_ADDRESS + (library_index as u64) * IMPORT_LIBRARY_STRIDE + (index as u64) * 4
        } else {
            base.wrapping_add(sym.st_value)
        };

        if !name.is_empty() {
            symbols_by_name.entry(name.clone()).or_insert(resolved);
        }

        symbols.push(SymbolEntry { name, resolved });
    }

    for ph in &elf.program_headers {
        let seg_addr = base.wrapping_add(ph.p_vaddr);
        let map_start = align_down(seg_addr, PAGE_SIZE);
        let map_end = align_up(seg_addr.wrapping_add(ph.p_memsz), PAGE_SIZE);
        let map_len = map_end.saturating_sub(map_start);

        if map_len == 0 {
            continue;
        }

        debug_print(format!(
            "Mapping at 0x{map_start:X}-0x{map_end:X} (0x{seg_addr:X}-0x{:X}); bytes 0x{map_len:X}",
            seg_addr + map_len.saturating_sub(1)
        ));

        if ph.p_type != PT_LOAD || ph.p_memsz == 0 {
            debug_print(format!(
                "- Skipping p_type={} offset=0x{:X} vaddr=0x{:X}",
                ph.p_type, ph.p_offset, ph.p_vaddr
            ));
            continue;
        }
        match uc.mem_map(map_start, map_len, Prot::ALL) {
            Ok(()) => {}
            Err(uc_error::MAP) => {}
            Err(err) => return Err(err.into()),
        }

        let file_offset = ph.p_offset as usize;
        let file_len = ph.p_filesz as usize;
        let file_end = file_offset
            .checked_add(file_len)
            .ok_or(VmError::InvalidElfRange)?;

        if file_end > elf_data.len() {
            return Err(VmError::InvalidElfRange);
        }

        let mut bytes = vec![0_u8; map_len as usize];
        let start_offset = (seg_addr - map_start) as usize;

        if file_len > 0 {
            let dest_end = start_offset
                .checked_add(file_len)
                .ok_or(VmError::InvalidElfRange)?;
            if dest_end > bytes.len() {
                return Err(VmError::InvalidElfRange);
            }
            bytes[start_offset..dest_end].copy_from_slice(&elf_data[file_offset..file_end]);
        }

        uc.mem_write(map_start, &bytes)?;
    }

    for rela in elf.dynrelas.iter() {
        apply_relocation(uc, base, &rela, library_name, &symbols)?;
    }

    for rela in elf.pltrelocs.iter() {
        apply_relocation(uc, base, &rela, library_name, &symbols)?;
    }

    let loaded = LoadedLibrary {
        name: library_name.to_string(),
        symbols,
        symbols_by_name,
    };

    uc.get_data_mut().loaded_libraries.push(loaded);

    Ok(library_index)
}

fn apply_relocation(
    uc: &mut Unicorn<'_, RuntimeState>,
    base: u64,
    relocation: &Reloc,
    library_name: &str,
    symbols: &[SymbolEntry],
) -> Result<(), VmError> {
    if relocation.r_type == 0 {
        return Ok(());
    }

    let relocation_addr = base.wrapping_add(relocation.r_offset);
    let addend = relocation.r_addend.unwrap_or(0);

    let symbol_address = if relocation.r_sym < symbols.len() {
        symbols[relocation.r_sym].resolved
    } else {
        return Err(VmError::SymbolIndexOutOfRange {
            library: library_name.to_string(),
            index: relocation.r_sym,
        });
    };

    use goblin::elf64::reloc::*;
    let value = match relocation.r_type {
        // AArch64 and x86_64 share the same semantics for these relocation classes; the
        // library ABI is identical, only the numeric type IDs differ per architecture.
        R_AARCH64_ABS64 | R_AARCH64_GLOB_DAT | R_X86_64_64 | R_X86_64_GLOB_DAT => {
            add_i64(symbol_address, addend)
        }
        R_AARCH64_JUMP_SLOT | R_X86_64_JUMP_SLOT => symbol_address,
        R_AARCH64_RELATIVE | R_X86_64_RELATIVE => add_i64(base, addend),
        other => return Err(VmError::UnsupportedRelocation(other)),
    };

    uc.mem_write(relocation_addr, &value.to_le_bytes())?;
    Ok(())
}

pub(crate) fn resolve_symbol_from_loaded_library_by_name(
    uc: &Unicorn<'_, RuntimeState>,
    library_index: usize,
    symbol_name: &str,
) -> Result<u64, VmError> {
    let library = uc
        .get_data()
        .loaded_libraries
        .get(library_index)
        .ok_or(VmError::LibraryNotLoaded(library_index))?;

    library
        .symbols_by_name
        .get(symbol_name)
        .copied()
        .ok_or_else(|| VmError::SymbolNotFound {
            library: library.name.clone(),
            symbol: symbol_name.to_string(),
        })
}

pub(crate) fn read_c_string(
    uc: &Unicorn<'_, RuntimeState>,
    address: u64,
    max_len: usize,
) -> Result<String, VmError> {
    let bytes = uc.mem_read_as_vec(address, max_len)?;
    let len = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(VmError::UnterminatedCString(address))?;
    Ok(String::from_utf8_lossy(&bytes[..len]).into_owned())
}
