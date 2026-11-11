//! Minimal classic-Mach-O (LC_DYLD_INFO) loader, so the Android SSC can drive the macOS
//! `CoreADI` for a Mac identity (the hybrid in F-064). Mirrors `load_library_by_name`'s
//! output: maps segments at an allocated base, slides internal pointers (rebase), points
//! imports at the shared import-stub region keyed by name (bind), and records the two
//! exports. Chained-fixups Mach-Os are out of scope (this core predates them).

use std::collections::HashMap;

use unicorn_engine::unicorn_const::{uc_error, Prot};
use unicorn_engine::Unicorn;

use crate::constants::{IMPORT_ADDRESS, IMPORT_LIBRARY_STRIDE, LIB_RESERVATION_SIZE, PAGE_SIZE};
use crate::debug::debug_print;
use crate::errors::VmError;
use crate::runtime::{LoadedLibrary, RuntimeState, SymbolEntry};
use crate::util::{align_down, align_up, as_usize};

fn uleb(d: &[u8], p: &mut usize) -> u64 {
    let (mut r, mut s) = (0u64, 0);
    loop {
        let b = d[*p];
        *p += 1;
        r |= ((b & 0x7f) as u64) << s;
        if b & 0x80 == 0 {
            break;
        }
        s += 7;
    }
    r
}

fn sleb(d: &[u8], p: &mut usize) -> i64 {
    let (mut r, mut s) = (0i64, 0);
    loop {
        let b = d[*p];
        *p += 1;
        r |= ((b & 0x7f) as i64) << s;
        s += 7;
        if b & 0x80 == 0 {
            if s < 64 && (b & 0x40) != 0 {
                r |= -1i64 << s;
            }
            break;
        }
    }
    r
}

pub(crate) fn load_macho_library(
    uc: &mut Unicorn<'_, RuntimeState>,
    library_name: &str,
) -> Result<usize, VmError> {
    let (library_index, data) = {
        let state = uc.get_data();
        let data = state
            .library_blobs
            .get(library_name)
            .cloned()
            .ok_or_else(|| VmError::LibraryNotRegistered(library_name.to_string()))?;
        (state.loaded_libraries.len(), data)
    };

    // EMU_MACHO_BASE=<hex>: load the Mach-O at a fixed base (slide = base). os-findmy-e maps
    // the macOS CoreADI at its literal vmaddr (slide 0, EMU_MACHO_BASE=0) and drives the
    // dispatcher directly; the -45076 gate fires when the core is rebased to a non-zero slide.
    let base = if let Ok(b) = std::env::var("EMU_MACHO_BASE") {
        let fixed = u64::from_str_radix(b.trim().trim_start_matches("0x"), 16).unwrap_or(0);
        // still advance the allocator so later libs don't collide
        let _ = uc.get_data_mut().library_allocator.alloc(LIB_RESERVATION_SIZE);
        fixed
    } else {
        let state = uc.get_data_mut();
        state.library_allocator.alloc(LIB_RESERVATION_SIZE)?
    };

    let u32le = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap());
    let u64le = |o: usize| u64::from_le_bytes(data[o..o + 8].try_into().unwrap());

    let ncmds = u32le(16) as usize;
    let mut off = 32usize;
    let mut seg_vmaddrs: Vec<u64> = Vec::new(); // ordered LC_SEGMENT_64 vmaddrs (for rebase/bind indexing)
    let (mut symoff, mut nsyms, mut stroff) = (0usize, 0usize, 0usize);
    let mut dyld: Option<[usize; 6]> = None; // rebase off/size, bind off/size, lazy off/size

    for _ in 0..ncmds {
        let cmd = u32le(off);
        let sz = u32le(off + 4) as usize;
        match cmd {
            0x19 => {
                // LC_SEGMENT_64
                let vmaddr = u64le(off + 24);
                let vmsize = u64le(off + 32);
                let fileoff = u64le(off + 40) as usize;
                let filesize = u64le(off + 48) as usize;
                let seg = base + vmaddr;
                let start = align_down(seg, PAGE_SIZE);
                let end = align_up(seg + vmsize.max(1), PAGE_SIZE);
                match uc.mem_map(start, end - start, Prot::ALL) {
                    Ok(()) | Err(uc_error::MAP) => {}
                    Err(e) => return Err(e.into()),
                }
                if filesize > 0 {
                    let mut bytes = vec![0u8; (end - start) as usize];
                    let o = (seg - start) as usize;
                    bytes[o..o + filesize].copy_from_slice(&data[fileoff..fileoff + filesize]);
                    uc.mem_write(start, &bytes)?;
                }
                seg_vmaddrs.push(vmaddr);
            }
            0x2 => {
                // LC_SYMTAB
                symoff = u32le(off + 8) as usize;
                nsyms = u32le(off + 12) as usize;
                stroff = u32le(off + 16) as usize;
            }
            0x22 | 0x8000_0022 => {
                // LC_DYLD_INFO(_ONLY): rebase(+8/+12), bind(+16/+20), weak(+24/+28),
                // lazy(+32/+36), export(+40/+44). We apply rebase + bind + lazy_bind.
                dyld = Some([
                    u32le(off + 8) as usize,
                    u32le(off + 12) as usize,
                    u32le(off + 16) as usize,
                    u32le(off + 20) as usize,
                    u32le(off + 32) as usize,
                    u32le(off + 36) as usize,
                ]);
            }
            _ => {}
        }
        off += sz;
    }

    // nlist symbols: defined → base+value (symbols_by_name); undefined → a compact import
    // stub slot in this library's import region, recorded by name for bind + dispatch.
    let mut symbols_by_name: HashMap<String, u64> = HashMap::new();
    let mut import_stub_for: HashMap<String, u64> = HashMap::new();
    let mut symbols: Vec<SymbolEntry> = Vec::new(); // index = import slot; dispatch_import_stub indexes this
    let import_base = IMPORT_ADDRESS + (library_index as u64) * IMPORT_LIBRARY_STRIDE;
    for i in 0..nsyms {
        let b = symoff + i * 16;
        let strx = u32::from_le_bytes(data[b..b + 4].try_into().unwrap()) as usize;
        let n_type = data[b + 4];
        let n_value = u64::from_le_bytes(data[b + 8..b + 16].try_into().unwrap());
        let s = stroff + strx;
        let e = data[s..].iter().position(|&c| c == 0).unwrap() + s;
        let raw = std::str::from_utf8(&data[s..e]).unwrap_or("");
        if raw.is_empty() {
            continue;
        }
        let name = raw.trim_start_matches('_').to_string();
        if n_type & 0x0e != 0 {
            // defined
            symbols_by_name.entry(name).or_insert(base + n_value);
        } else if !import_stub_for.contains_key(raw) {
            // undefined import. Code imports get a 4-byte hooked stub slot. Data imports (Apple
            // constants such as kCFBooleanTrue / kCFURLIsDirectoryKey) are read as `*slot` as an
            // 8-byte pointer, so they instead get a dedicated 8-byte cell holding a distinct, stable
            // value (the cell's own address). `import_slot_addr` hands that same value back in the
            // CFURL stubs, so key identity and kCFBoolean comparisons line up.
            let is_data = name.starts_with("kCF") || name.starts_with("kSec");
            let resolved = if is_data {
                let cell = {
                    let st = uc.get_data_mut();
                    let c = st.data_import_next;
                    st.data_import_next += 8;
                    c
                };
                uc.mem_write(cell, &cell.to_le_bytes())?;
                cell
            } else {
                import_base + (symbols.len() as u64) * 4
            };
            symbols.push(SymbolEntry { name: name.clone(), resolved });
            import_stub_for.insert(raw.to_string(), resolved);
        }
    }

    // Rebase (slide internal pointers by `base`) and bind (point imports at their stubs).
    if let Some([roff, rsize, boff, bsize, loff, lsize]) = dyld {
        if std::env::var("EMU_MACHO_DEBUG").is_ok() {
            eprintln!("[macho] dyld rebase={roff:#x}/{rsize:#x} bind={boff:#x}/{bsize:#x} lazy={loff:#x}/{lsize:#x}");
        }
        apply_rebase(uc, base, &seg_vmaddrs, &data[roff..roff + rsize])?;
        apply_bind(uc, base, &seg_vmaddrs, &data[boff..boff + bsize], &import_stub_for)?;
        if lsize > 0 {
            apply_bind(uc, base, &seg_vmaddrs, &data[loff..loff + lsize], &import_stub_for)?;
        }
    }

    debug_print(format!(
        "[macho] loaded '{library_name}' at 0x{base:X} with {} imports", symbols.len()
    ));
    uc.get_data_mut().loaded_libraries.push(LoadedLibrary {
        name: library_name.to_string(),
        symbols,
        symbols_by_name,
    });
    Ok(library_index)
}

fn apply_rebase(
    uc: &mut Unicorn<'_, RuntimeState>,
    base: u64,
    segs: &[u64],
    s: &[u8],
) -> Result<(), VmError> {
    let mut p = 0usize;
    let mut addr = 0u64;
    let mut slide = |uc: &mut Unicorn<'_, RuntimeState>, at: u64| -> Result<(), VmError> {
        let mut v = [0u8; 8];
        uc.mem_read(at, &mut v)?;
        let nv = u64::from_le_bytes(v).wrapping_add(base);
        uc.mem_write(at, &nv.to_le_bytes())?;
        Ok(())
    };
    while p < s.len() {
        let b = s[p];
        p += 1;
        let (op, imm) = (b & 0xf0, (b & 0x0f) as u64);
        match op {
            0x00 | 0x10 => {}
            0x20 => addr = base + segs[imm as usize] + uleb(s, &mut p),
            0x30 => addr = addr.wrapping_add(uleb(s, &mut p)),
            0x40 => addr = addr.wrapping_add(imm * 8),
            0x50 => {
                for _ in 0..imm {
                    slide(uc, addr)?;
                    addr = addr.wrapping_add(8);
                }
            }
            0x60 => {
                let c = uleb(s, &mut p);
                for _ in 0..c {
                    slide(uc, addr)?;
                    addr = addr.wrapping_add(8);
                }
            }
            0x70 => {
                slide(uc, addr)?;
                addr = addr.wrapping_add(8 + uleb(s, &mut p));
            }
            0x80 => {
                let c = uleb(s, &mut p);
                let skip = uleb(s, &mut p);
                for _ in 0..c {
                    slide(uc, addr)?;
                    addr = addr.wrapping_add(8 + skip);
                }
            }
            _ => return Err(VmError::UnsupportedRelocation(op as u32)),
        }
    }
    Ok(())
}

fn apply_bind(
    uc: &mut Unicorn<'_, RuntimeState>,
    base: u64,
    segs: &[u64],
    s: &[u8],
    import_stub_for: &HashMap<String, u64>,
) -> Result<(), VmError> {
    let mut p = 0usize;
    let mut addr = 0u64;
    let mut sym = String::new();
    let mut addend = 0i64;
    let mut bind_one = |uc: &mut Unicorn<'_, RuntimeState>, addr: u64, sym: &str, addend: i64| -> Result<(), VmError> {
        let stub = import_stub_for.get(sym).copied().unwrap_or_else(|| {
            eprintln!("[macho] bind: no stub for symbol '{sym}' (addr 0x{addr:X}) -> writing 0");
            0
        });
        let v = (stub as i64 + addend) as u64;
        uc.mem_write(addr, &v.to_le_bytes())?;
        Ok(())
    };
    while p < s.len() {
        let b = s[p];
        p += 1;
        let (op, imm) = (b & 0xf0, (b & 0x0f) as u64);
        match op {
            0x00 | 0x10 | 0x30 | 0x50 => {}
            0x20 => {
                uleb(s, &mut p);
            }
            0x40 => {
                let start = p;
                while s[p] != 0 {
                    p += 1;
                }
                sym = std::str::from_utf8(&s[start..p]).unwrap_or("").to_string();
                p += 1;
            }
            0x60 => addend = sleb(s, &mut p),
            0x70 => addr = base + segs[imm as usize] + uleb(s, &mut p),
            0x80 => addr = addr.wrapping_add(uleb(s, &mut p)),
            0x90 => {
                if std::env::var("EMU_BIND_DEBUG").is_ok() { eprintln!("[bind] DO_BIND {sym} @0x{addr:X}"); }
                bind_one(uc, addr, &sym, addend)?;
                addr = addr.wrapping_add(8);
            }
            0xa0 => {
                bind_one(uc, addr, &sym, addend)?;
                addr = addr.wrapping_add(8 + uleb(s, &mut p));
            }
            0xb0 => {
                bind_one(uc, addr, &sym, addend)?;
                addr = addr.wrapping_add(8 + imm * 8);
            }
            0xc0 => {
                let count = uleb(s, &mut p);
                let skip = uleb(s, &mut p);
                for _ in 0..count {
                    bind_one(uc, addr, &sym, addend)?;
                    addr = addr.wrapping_add(8 + skip);
                }
            }
            _ => return Err(VmError::UnsupportedRelocation(op as u32)),
        }
    }
    Ok(())
}
