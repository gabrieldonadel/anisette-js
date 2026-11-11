use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use unicorn_engine::Unicorn;
use unicorn_engine::unicorn_const::Prot;

use crate::arch::{arg, ret, EmuArch};

use crate::constants::{
    ENOENT, IMPORT_ADDRESS, IMPORT_LIBRARY_STRIDE, O_ACCMODE, O_CREAT, O_NOFOLLOW, O_RDWR, O_WRONLY,
};
use crate::debug::{debug_print, debug_trace};
use crate::emu::{
    ensure_errno_address, load_library_by_name, read_c_string,
    resolve_symbol_from_loaded_library_by_name, set_errno,
};
use crate::errors::VmError;
use crate::runtime::RuntimeState;
use crate::util::bytes_to_hex;

/// EMU_FS_ROOT: redirect guest absolute/relative paths into a host sandbox dir so a full
/// daemon (adid) can read/create its state (e.g. /var/db/fpsd/adi/adi.pb) from a seeded tree.
fn sandbox_path(path: &str) -> Option<std::path::PathBuf> {
    let root = std::env::var("EMU_FS_ROOT").ok()?;
    let rel = path.trim_start_matches("./").trim_start_matches('/');
    Some(std::path::Path::new(&root).join(rel))
}

/// The path std::fs should use for a guest file op, or None to fall back to the legacy
/// `./anisette` guard. With EMU_FS_ROOT set, redirect into the host sandbox. On wasm/emscripten
/// there is no host FS — std::fs IS the virtual IDBFS-backed filesystem — so pass guest paths
/// through unchanged. This is how the macOS core's `/Users/Shared/adi` store persists in the browser.
fn vfs_path(path: &str) -> Option<String> {
    if let Some(hp) = sandbox_path(path) {
        return Some(hp.to_string_lossy().into_owned());
    }
    if cfg!(target_os = "emscripten") {
        return Some(path.to_string());
    }
    None
}

fn stub_mmap(uc: &mut Unicorn<'_, RuntimeState>) -> Result<(), VmError> {
    let hint = arg(uc, 0)?;
    let length = arg(uc, 1)?;
    let aligned = (length.max(1) + 0xFFF) & !0xFFF;
    let address = {
        let state = uc.get_data_mut();
        state.temp_allocator.alloc(aligned)?
    };
    uc.mem_map(address, aligned, Prot::ALL)?;
    let zeros = vec![0u8; aligned as usize];
    uc.mem_write(address, &zeros)?;
    if std::env::var("EMU_OBJC_DEBUG").is_ok() { eprintln!("[mmap] hint=0x{hint:X} len=0x{length:X} -> 0x{address:X}"); }
    ret(uc, address)?;
    Ok(())
}

pub fn dispatch_import_stub(
    uc: &mut Unicorn<'_, RuntimeState>,
    address: u64,
) -> Result<(), VmError> {
    if address < IMPORT_ADDRESS {
        return Err(VmError::InvalidImportAddress(address));
    }

    let offset = address - IMPORT_ADDRESS;
    let library_index = (offset / IMPORT_LIBRARY_STRIDE) as usize;
    let symbol_index = ((offset % IMPORT_LIBRARY_STRIDE) / 4) as usize;

    let symbol_name =
        {
            let state = uc.get_data();
            let library = state
                .loaded_libraries
                .get(library_index)
                .ok_or(VmError::LibraryNotLoaded(library_index))?;

            let symbol = library.symbols.get(symbol_index).ok_or_else(|| {
                VmError::SymbolIndexOutOfRange {
                    library: library.name.clone(),
                    index: symbol_index,
                }
            })?;

            symbol.name.clone()
        };

    if std::env::var("EMU_IMPORT_TRACE").is_ok() {
        eprintln!("[import] {symbol_name}");
    }
    handle_stub_by_name(uc, &symbol_name)
}

fn handle_stub_by_name(
    uc: &mut Unicorn<'_, RuntimeState>,
    symbol_name: &str,
) -> Result<(), VmError> {
    match symbol_name {
        "malloc" => stub_malloc(uc),
        "free" => stub_free(uc),
        "strncpy" => stub_strncpy(uc),
        "mkdir" => stub_mkdir(uc),
        "umask" => stub_umask(uc),
        "chmod" => stub_chmod(uc),
        "lstat" | "lstat$INODE64" | "stat" | "stat$INODE64" => stub_lstat(uc),
        "fstat" | "fstat$INODE64" => stub_fstat(uc),
        "statfs" | "statfs$INODE64" => ret(uc, 0),
        "mmap" => stub_mmap(uc),
        "munmap" => ret(uc, 0),
        "mprotect" => ret(uc, 0),
        "open" | "open$NOCANCEL" => stub_open(uc),
        "ftruncate" => stub_ftruncate(uc),
        "read" => stub_read(uc),
        "write" => stub_write(uc),
        "close" => stub_close(uc),
        "dlopen" => stub_dlopen(uc),
        "dlsym" => stub_dlsym(uc),
        "dlclose" => stub_dlclose(uc),
        "pthread_once" => stub_return_zero(uc),
        "pthread_create" => stub_return_zero(uc),
        "pthread_mutex_lock" => stub_return_zero(uc),
        "pthread_rwlock_unlock" => stub_return_zero(uc),
        "pthread_rwlock_destroy" => stub_return_zero(uc),
        "pthread_rwlock_wrlock" => stub_return_zero(uc),
        "pthread_rwlock_init" => stub_return_zero(uc),
        "pthread_mutex_unlock" => stub_return_zero(uc),
        "pthread_rwlock_rdlock" => stub_return_zero(uc),
        "gettimeofday" => stub_gettimeofday(uc),
        "__errno" | "errno" | "error" | "__error" | "___error" => stub_errno_location(uc),
        "getenv" => ret(uc, 0),
        "__system_property_get" => stub_system_property_get(uc),
        "arc4random" => stub_arc4random(uc),
        // macOS CoreADI imports (the hybrid: Android SSC driving the Mach-O core).
        "getuid" => ret(uc, std::env::var("EMU_UID").ok().and_then(|v| v.parse().ok()).unwrap_or(501)),
        "notify_post" => ret(uc, 0),
        "fchmod" | "lockf" | "unlink" | "fcntl" => ret(uc, 0),
        "gethostuuid" => stub_gethostuuid(uc),
        "objc_msgSend" => stub_objc_msgsend(uc),
        // CoreFoundation / CoreServices used for the on-disk adi state: treated as benign
        // no-ops (the real file writes go through open/read/write/mkdir, which are stubbed).
        "CFRelease" | "__stack_chk_fail" => ret(uc, 0),
        // os-findmy-e returns success (1) for these so the core's store setup proceeds.
        "CFFileSecuritySetMode" | "CFURLSetResourcePropertyForKey" | "CSBackupSetItemExcluded"
            => ret(uc, 1),
        "CFErrorGetCode" => ret(uc, (-1i64) as u64),
        "CFErrorGetDomain" | "CSBackupIsItemExcluded" => ret(uc, 0),
        // Virtual CFURL layer: the core checks the adi store directory through these.
        "CFURLCreateFromFileSystemRepresentation" => stub_cfurl_create(uc),
        "CFURLCopyResourcePropertyForKey" => stub_cfurl_copy_prop(uc),
        // NSVersionOfRunTimeLibrary: return a recent Foundation version (4032.0.0) so the
        // core's runtime-version gate passes (0/-1 would fail it).
        "NSVersionOfRunTimeLibrary" => {
            let name_ptr = arg(uc, 0)?;
            let name = read_c_string(uc, name_ptr, 128).unwrap_or_default();
            let v = std::env::var("EMU_NSVER").ok()
                .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                .unwrap_or(0x0000_0000);
            if std::env::var("EMU_OBJC_DEBUG").is_ok() { eprintln!("[nsver] NSVersionOfRunTimeLibrary('{name}') -> 0x{v:X}"); }
            ret(uc, v)
        }
        // --- CFRunLoop: non-null handles so adid proceeds past its run-loop setup ---
        "CFRunLoopGetMain" | "CFRunLoopGetCurrent" => ret(uc, 0xCF00_0001),
        "CFRunLoopRun" => { eprintln!("[xpc] CFRunLoopRun (returning, no block)"); ret(uc, 0) }
        "CFRunLoopAddSource" | "CFRunLoopStop" => ret(uc, 0),
        "CFFileDescriptorCreate" => ret(uc, 0xCFD0_0001),
        "CFFileDescriptorCreateRunLoopSource" => ret(uc, 0xCFD0_0002),
        "CFFileDescriptorEnableCallBacks" | "CFFileDescriptorInvalidate" => ret(uc, 0),
        "CFFileDescriptorGetNativeDescriptor" => ret(uc, 0),
        // --- XPC shim: capture event-handler blocks; opaque objects are fake pointers ---
        "xpc_connection_create_mach_service" => {
            let name = read_c_string(uc, arg(uc, 0)?, 256).unwrap_or_default();
            eprintln!("[xpc] create_mach_service('{name}') -> fake conn 0x7C000001");
            ret(uc, 0x7C00_0001)
        }
        "xpc_connection_set_event_handler" => {
            let block = arg(uc, 1)?;
            eprintln!("[xpc] set_event_handler block=0x{block:X}");
            uc.get_data_mut().xpc_event_handlers.push(block);
            ret(uc, 0)
        }
        "xpc_connection_activate" | "xpc_connection_resume" | "xpc_connection_cancel"
        | "xpc_connection_set_target_queue" | "xpc_transaction_begin"
        | "xpc_transaction_end" | "xpc_release" => ret(uc, 0),
        // xpc_get_type: return the dictionary-type sentinel (harness pins the GOT type
        // globals to these). Never the error sentinel, so handlers treat objects as messages.
        "xpc_get_type" => {
            // The handler compares get_type() against a deobfuscated type pointer
            // (CONST + GOT[idx]). EMU_XPC_TYPE pins the value we return so the
            // dictionary-type comparison passes.
            let v = std::env::var("EMU_XPC_TYPE").ok()
                .and_then(|s| u64::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())
                .unwrap_or(0xDDDD);
            ret(uc, v)
        }
        // xpc_dictionary_get_data(dict, key, *len): hand back the harness-supplied request.
        "xpc_dictionary_get_data" => {
            let key = read_c_string(uc, arg(uc, 1)?, 64).unwrap_or_default();
            let len_ptr = arg(uc, 2)?;
            let (ptr, len) = {
                let req = uc.get_data().xpc_request.clone();
                let ptr = uc.get_data().xpc_request_ptr;
                (ptr, req.len() as u64)
            };
            let ptr = ptr.unwrap_or(0);
            if len_ptr != 0 { let _ = uc.mem_write(len_ptr, &len.to_le_bytes()); }
            eprintln!("[xpc] get_data(key='{key}') -> ptr=0x{ptr:X} len={len}");
            ret(uc, ptr)
        }
        // xpc_dictionary_create_reply(original) -> fake reply object.
        "xpc_dictionary_create_reply" => { eprintln!("[xpc] create_reply"); ret(uc, 0x7C00_0004) }
        // xpc_dictionary_set_data(reply, key, bytes, len): capture the OTP reply bytes.
        "xpc_dictionary_set_data" => {
            let key = read_c_string(uc, arg(uc, 1)?, 64).unwrap_or_default();
            let bytes_ptr = arg(uc, 2)?;
            let len = arg(uc, 3)? as usize;
            let data = uc.mem_read_as_vec(bytes_ptr, len).unwrap_or_default();
            eprintln!("[xpc] set_data(key='{key}', len={len}) -> captured");
            uc.get_data_mut().xpc_reply = Some(data);
            ret(uc, 0)
        }
        "xpc_dictionary_send_reply" | "xpc_connection_send_message" => ret(uc, 0),
        "xpc_dictionary_get_audit_token" => ret(uc, 0),
        "xpc_dictionary_get_value" | "CFDictionaryGetValue" => ret(uc, 0),
        "audit_token_to_euid" => ret(uc, std::env::var("EMU_UID").ok().and_then(|v| v.parse().ok()).unwrap_or(0)),
        "audit_token_to_au32" => ret(uc, 0),
        "CFDataCreateWithBytesNoCopy" => ret(uc, 0),
        "sysctlbyname" => {
            let name = read_c_string(uc, arg(uc, 0)?, 128).unwrap_or_default();
            let oldp = arg(uc, 2)?;
            let oldlenp = arg(uc, 3)?;
            // kern.hv_vmm_present: adi.pb was provisioned inside a VM, so report 1.
            let val: Option<i32> = match name.as_str() {
                "kern.hv_vmm_present" => Some(1),
                _ => None,
            };
            if let (Some(v), true) = (val, oldp != 0) {
                let _ = uc.mem_write(oldp, &v.to_le_bytes());
                if oldlenp != 0 { let _ = uc.mem_write(oldlenp, &4u64.to_le_bytes()); }
            }
            eprintln!("[ioid] sysctlbyname('{name}') -> {:?}", val);
            ret(uc, 0)
        }
        "IOServiceMatching" => {
            let name = read_c_string(uc, arg(uc, 0)?, 128).unwrap_or_default();
            eprintln!("[ioid] IOServiceMatching('{name}')");
            ret(uc, 0x10000001)
        }
        "IOServiceGetMatchingServices" | "IOServiceGetMatchingService" => { eprintln!("[ioid] IOServiceGetMatchingServices"); ret(uc, 0) }
        "IOIteratorNext" => { eprintln!("[ioid] IOIteratorNext"); ret(uc, 0) }
        "IOServiceOpen" => { eprintln!("[ioid] IOServiceOpen"); ret(uc, 0) }
        "IOConnectCallStructMethod" => {
            eprintln!("[ioid] IOConnectCallStructMethod sel? in=0x{:X} inlen=0x{:X} out=0x{:X} outlen=0x{:X}", arg(uc,2)?, arg(uc,3)?, arg(uc,4)?, arg(uc,5)?);
            ret(uc, 0)
        }
        "IORegistryEntryCreateCFProperty" | "IORegistryEntrySearchCFProperty" => {
            let _ = arg(uc,0)?; eprintln!("[ioid] IORegistryEntryCreateCFProperty"); ret(uc, 0)
        }
        other => {
            if std::env::var("EMU_STUB_PERMISSIVE").is_ok() {
                eprintln!("[stub] permissive no-op for unhandled import '{other}' -> 0");
                return ret(uc, 0);
            }
            debug_print(other);
            Err(VmError::UnhandledImport(other.to_string()))
        }
    }
}

fn stub_return_zero(uc: &mut Unicorn<'_, RuntimeState>) -> Result<(), VmError> {
    ret(uc, 0)?;
    Ok(())
}

fn stub_malloc(uc: &mut Unicorn<'_, RuntimeState>) -> Result<(), VmError> {
    let request = arg(uc, 0)?;
    let address = {
        let state = uc.get_data_mut();
        state.malloc_allocator.alloc(request)?
    };

    debug_trace(format!("malloc(0x{request:X})=0x{address:X}"));
    ret(uc, address)?;
    Ok(())
}

fn stub_free(uc: &mut Unicorn<'_, RuntimeState>) -> Result<(), VmError> {
    ret(uc, 0)?;
    Ok(())
}

fn stub_strncpy(uc: &mut Unicorn<'_, RuntimeState>) -> Result<(), VmError> {
    let dst = arg(uc, 0)?;
    let src = arg(uc, 1)?;
    let length = arg(uc, 2)? as usize;

    let input = uc.mem_read_as_vec(src, length)?;
    let copy_len = input
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(length)
        .min(length);

    let mut output = vec![0_u8; length];
    output[..copy_len].copy_from_slice(&input[..copy_len]);

    uc.mem_write(dst, &output)?;
    ret(uc, dst)?;

    Ok(())
}

fn stub_mkdir(uc: &mut Unicorn<'_, RuntimeState>) -> Result<(), VmError> {
    let path_ptr = arg(uc, 0)?;
    let mode = arg(uc, 1)?;
    let path = read_c_string(uc, path_ptr, 0x1000)?;
    debug_trace(format!("mkdir('{path}', {mode:#o})"));

    if let Some(hp) = vfs_path(&path) {
        let _ = fs::create_dir_all(&hp);
        ret(uc, 0)?; return Ok(());
    }
    // Only allow creating ./anisette directory (matches Python reference impl)
    if path != "./anisette" {
        debug_print(format!("mkdir: rejecting invalid path '{path}'"));
        set_errno(uc, ENOENT)?;
        ret(uc, u64::MAX)?;
        return Ok(());
    }

    match fs::create_dir_all(&path) {
        Ok(()) => {
            ret(uc, 0)?;
        }
        Err(_) => {
            set_errno(uc, ENOENT)?;
            ret(uc, u64::MAX)?;
        }
    }

    Ok(())
}

fn stub_umask(uc: &mut Unicorn<'_, RuntimeState>) -> Result<(), VmError> {
    ret(uc, 0o777)?;
    Ok(())
}

fn stub_chmod(uc: &mut Unicorn<'_, RuntimeState>) -> Result<(), VmError> {
    let path_ptr = arg(uc, 0)?;
    let mode = arg(uc, 1)?;
    let path = read_c_string(uc, path_ptr, 0x1000)?;
    debug_trace(format!("chmod('{path}', {mode:#o})"));
    ret(uc, 0)?;
    Ok(())
}

fn emulated_uid() -> u32 {
    std::env::var("EMU_UID").ok().and_then(|v| v.parse().ok()).unwrap_or(501)
}

/// Darwin `struct stat` (the `$INODE64` / `__DARWIN_64_BIT_INO_T` variant that
/// `lstat$INODE64`/`stat$INODE64` fill on macOS x86_64). Totally different layout
/// from the Linux struct the Android (arm64/bionic) core expects. 144 bytes.
fn build_darwin_stat_bytes(mode: u32, size: u64) -> Vec<u8> {
    let mut st = vec![0u8; 144];
    let put = |st: &mut [u8], off: usize, bytes: &[u8]| {
        st[off..off + bytes.len()].copy_from_slice(bytes);
    };
    put(&mut st, 0, &0i32.to_le_bytes()); // st_dev
    put(&mut st, 4, &((mode & 0xFFFF) as u16).to_le_bytes()); // st_mode (uint16)
    put(&mut st, 6, &1u16.to_le_bytes()); // st_nlink
    put(&mut st, 8, &2u64.to_le_bytes()); // st_ino (nonzero)
    put(&mut st, 16, &emulated_uid().to_le_bytes()); // st_uid == getuid() so owner checks pass
    put(&mut st, 20, &emulated_uid().to_le_bytes()); // st_gid
    put(&mut st, 24, &0i32.to_le_bytes()); // st_rdev
    // 28..32 padding
    // timespecs 32..96 left zero
    put(&mut st, 96, &size.to_le_bytes()); // st_size (off_t)
    put(&mut st, 104, &size.div_ceil(512).to_le_bytes()); // st_blocks
    put(&mut st, 112, &512i32.to_le_bytes()); // st_blksize
    // st_flags/gen/spare left zero
    st
}

fn build_python_stat_bytes(mode: u32, size: u64) -> Vec<u8> {
    let mut stat = Vec::with_capacity(128);

    stat.extend_from_slice(&[0_u8; 8]); // st_dev
    stat.extend_from_slice(&[0_u8; 8]); // st_ino
    stat.extend_from_slice(&mode.to_le_bytes()); // st_mode
    stat.extend_from_slice(&[0_u8; 4]); // st_nlink
    stat.extend_from_slice(&[0xA4, 0x81, 0x00, 0x00]); // st_uid
    stat.extend_from_slice(&[0_u8; 4]); // st_gid
    stat.extend_from_slice(&[0_u8; 8]); // st_rdev
    stat.extend_from_slice(&[0_u8; 8]); // __pad1
    stat.extend_from_slice(&size.to_le_bytes()); // st_size
    stat.extend_from_slice(&[0_u8; 4]); // st_blksize
    stat.extend_from_slice(&[0_u8; 4]); // __pad2
    stat.extend_from_slice(&[0_u8; 8]); // st_blocks
    stat.extend_from_slice(&[0_u8; 8]); // st_atime
    stat.extend_from_slice(&[0_u8; 8]); // st_atime_nsec
    stat.extend_from_slice(&[0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00]); // st_mtime
    stat.extend_from_slice(&[0_u8; 8]); // st_mtime_nsec
    stat.extend_from_slice(&[0_u8; 8]); // st_ctime
    stat.extend_from_slice(&[0_u8; 8]); // st_ctime_nsec
    stat.extend_from_slice(&[0_u8; 4]); // __unused4
    stat.extend_from_slice(&[0_u8; 4]); // __unused5

    stat
}

fn write_python_stat(
    uc: &mut Unicorn<'_, RuntimeState>,
    out_ptr: u64,
    mode: u32,
    size: u64,
    stat_blksize: u64,
    stat_blocks: u64,
) -> Result<(), VmError> {
    debug_print(format!("{size} {stat_blksize} {stat_blocks}"));

    let fake_blksize = 512_u64;
    let fake_blocks = size.div_ceil(512);
    debug_print(format!("{size} {fake_blksize} {fake_blocks}"));

    debug_print(format!("0x{mode:X} = {mode}"));
    let stat_bytes = match uc.get_data().arch {
        EmuArch::X86_64 => build_darwin_stat_bytes(mode, size),
        EmuArch::Arm64 => build_python_stat_bytes(mode, size),
    };
    debug_print(format!("{}", stat_bytes.len()));
    debug_print(format!("Write to ptr: 0x{out_ptr:X}"));
    uc.mem_write(out_ptr, &stat_bytes)?;
    debug_print("Stat struct written to guest memory");
    Ok(())
}

fn stat_path_into_guest(
    uc: &mut Unicorn<'_, RuntimeState>,
    path: &str,
    out_ptr: u64,
) -> Result<(), VmError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => {
            debug_print(format!("Unable to stat '{path}'"));
            set_errno(uc, ENOENT)?;
            ret(uc, u64::MAX)?;
            return Ok(());
        }
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        write_python_stat(
            uc,
            out_ptr,
            metadata.mode(),
            metadata.size(),
            metadata.blksize(),
            metadata.blocks(),
        )?;
    }

    #[cfg(not(unix))]
    {
        write_python_stat(uc, out_ptr, 0, metadata.len(), 0, 0)?;
    }

    ret(uc, 0)?;
    Ok(())
}

fn stat_fd_into_guest(
    uc: &mut Unicorn<'_, RuntimeState>,
    fd: u64,
    out_ptr: u64,
) -> Result<(), VmError> {
    let fd_index = usize::try_from(fd).map_err(|_| VmError::InvalidFileDescriptor(fd))?;

    let metadata = {
        let state = uc.get_data_mut();
        let slot = state
            .file_handles
            .get_mut(fd_index)
            .ok_or(VmError::InvalidFileDescriptor(fd))?;
        let file = slot.as_mut().ok_or(VmError::InvalidFileDescriptor(fd))?;
        file.metadata()
    };

    let metadata = match metadata {
        Ok(metadata) => metadata,
        Err(_) => {
            debug_print(format!("Unable to stat '{fd}'"));
            set_errno(uc, ENOENT)?;
            ret(uc, u64::MAX)?;
            return Ok(());
        }
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        write_python_stat(
            uc,
            out_ptr,
            metadata.mode(),
            metadata.size(),
            metadata.blksize(),
            metadata.blocks(),
        )?;
    }

    #[cfg(not(unix))]
    {
        write_python_stat(uc, out_ptr, 0, metadata.len(), 0, 0)?;
    }

    ret(uc, 0)?;
    Ok(())
}
fn stub_lstat(uc: &mut Unicorn<'_, RuntimeState>) -> Result<(), VmError> {
    let path_ptr = arg(uc, 0)?;
    let out_ptr = arg(uc, 1)?;
    eprintln!("[lstat] path_ptr=0x{path_ptr:X} out_ptr=0x{out_ptr:X}");
    let path = read_c_string(uc, path_ptr, 0x1000)?;
    eprintln!("[lstat] raw='{path}' out=0x{out_ptr:X}");
    let path = sandbox_path(&path).map(|p| p.to_string_lossy().into_owned()).unwrap_or(path);
    eprintln!("[lstat] sandboxed='{path}' exists={} ", std::path::Path::new(&path).exists());
    stat_path_into_guest(uc, &path, out_ptr)
}

fn stub_fstat(uc: &mut Unicorn<'_, RuntimeState>) -> Result<(), VmError> {
    let fd = arg(uc, 0)?;
    let out_ptr = arg(uc, 1)?;
    debug_trace(format!("fstat({fd}, [...])"));
    stat_fd_into_guest(uc, fd, out_ptr)
}

fn stub_open(uc: &mut Unicorn<'_, RuntimeState>) -> Result<(), VmError> {
    let path_ptr = arg(uc, 0)?;
    let flags = arg(uc, 1)?;
    let mode = arg(uc, 2)?;
    let path = read_c_string(uc, path_ptr, 0x1000)?;
    if path.is_empty() {
        return Err(VmError::EmptyPath);
    }

    debug_trace(format!("open('{path}', {flags:#o}, {mode:#o})"));
    let path = if let Some(resolved) = vfs_path(&path) {
        if let Some(parent) = std::path::Path::new(&resolved).parent() {
            let _ = fs::create_dir_all(parent);
        }
        resolved
    } else {
        if path != "./anisette/adi.pb" {
            debug_print(format!("open: rejecting invalid path '{path}'"));
            set_errno(uc, ENOENT)?; ret(uc, u64::MAX)?; return Ok(());
        }
        if flags != O_NOFOLLOW && flags != (O_NOFOLLOW | O_CREAT | O_WRONLY) {
            debug_print(format!("open: rejecting unsupported flags {flags:#o}"));
            set_errno(uc, ENOENT)?; ret(uc, u64::MAX)?; return Ok(());
        }
        path
    };

    let mut options = OpenOptions::new();
    let access_mode = flags & O_ACCMODE;
    let _write_only = access_mode == O_WRONLY;
    // CoreADI is a macOS binary, so it passes Darwin open() flags (O_CREAT=0x200), not the Linux
    // values this emulator otherwise uses (0o100). Pick the right bit for the running arch.
    let o_creat = if matches!(uc.get_data().arch, EmuArch::X86_64) { 0x200 } else { O_CREAT };
    let create = (flags & o_creat) != 0;

    match access_mode {
        0 => {
            options.read(true);
        }
        O_WRONLY => {
            options.write(true).truncate(true);
        }
        O_RDWR => {
            options.read(true).write(true);
        }
        _ => {
            set_errno(uc, ENOENT)?;
            ret(uc, u64::MAX)?;
            return Ok(());
        }
    }

    if create {
        options.create(true).read(true).write(true);
        if let Some(parent) = std::path::Path::new(&path).parent() {
            let _ = fs::create_dir_all(parent);
        }
    }

    if (flags & O_NOFOLLOW) == 0 {
        debug_trace("open without O_NOFOLLOW");
    }

    let dbg = std::env::var("EMU_OBJC_DEBUG").is_ok();
    match options.open(&path) {
        Ok(file) => {
            let fd = {
                let state = uc.get_data_mut();
                state.file_handles.push(Some(file));
                (state.file_handles.len() - 1) as u64
            };
            if dbg { eprintln!("[open] '{path}' flags={flags:#x} create={create} -> fd={fd}"); }
            ret(uc, fd)?;
        }
        Err(e) => {
            if dbg { eprintln!("[open] '{path}' flags={flags:#x} create={create} -> ERR {e}"); }
            set_errno(uc, ENOENT)?;
            ret(uc, u64::MAX)?;
        }
    }

    Ok(())
}

fn stub_ftruncate(uc: &mut Unicorn<'_, RuntimeState>) -> Result<(), VmError> {
    let fd = arg(uc, 0)?;
    let length = arg(uc, 1)?;
    debug_trace(format!("ftruncate({fd}, {length})"));
    let fd_index = usize::try_from(fd).map_err(|_| VmError::InvalidFileDescriptor(fd))?;

    let result = {
        let state = uc.get_data_mut();
        let slot = state
            .file_handles
            .get_mut(fd_index)
            .ok_or(VmError::InvalidFileDescriptor(fd))?;
        let file = slot.as_mut().ok_or(VmError::InvalidFileDescriptor(fd))?;
        file.set_len(length)
    };

    match result {
        Ok(()) => ret(uc, 0)?,
        Err(_) => {
            set_errno(uc, ENOENT)?;
            ret(uc, u64::MAX)?;
        }
    }

    Ok(())
}

fn stub_read(uc: &mut Unicorn<'_, RuntimeState>) -> Result<(), VmError> {
    let fd = arg(uc, 0)?;
    let buf_ptr = arg(uc, 1)?;
    let count = arg(uc, 2)? as usize;

    let fd_index = usize::try_from(fd).map_err(|_| VmError::InvalidFileDescriptor(fd))?;

    let mut buffer = vec![0_u8; count];

    let read_size = {
        let state = uc.get_data_mut();
        let slot = state
            .file_handles
            .get_mut(fd_index)
            .ok_or(VmError::InvalidFileDescriptor(fd))?;
        let file = slot.as_mut().ok_or(VmError::InvalidFileDescriptor(fd))?;
        file.read(&mut buffer)
    };
    debug_trace(format!("read({fd}, 0x{buf_ptr:X}, {count})={read_size:?}"));
    match read_size {
        Ok(read_size) => {
            uc.mem_write(buf_ptr, &buffer[..read_size])?;
            ret(uc, read_size as u64)?;
        }
        Err(_) => {
            set_errno(uc, ENOENT)?;
            ret(uc, u64::MAX)?;
        }
    }

    Ok(())
}

fn stub_write(uc: &mut Unicorn<'_, RuntimeState>) -> Result<(), VmError> {
    let fd = arg(uc, 0)?;
    let buf_ptr = arg(uc, 1)?;
    let count = arg(uc, 2)? as usize;
    debug_trace(format!("write({fd}, 0x{buf_ptr:X}, {count})"));
    let fd_index = usize::try_from(fd).map_err(|_| VmError::InvalidFileDescriptor(fd))?;

    let bytes = uc.mem_read_as_vec(buf_ptr, count)?;

    let write_size = {
        let state = uc.get_data_mut();
        let slot = state
            .file_handles
            .get_mut(fd_index)
            .ok_or(VmError::InvalidFileDescriptor(fd))?;
        let file = slot.as_mut().ok_or(VmError::InvalidFileDescriptor(fd))?;
        file.write_all(&bytes)
    };

    match write_size {
        Ok(()) => ret(uc, count as u64)?,
        Err(_) => {
            set_errno(uc, ENOENT)?;
            ret(uc, u64::MAX)?;
        }
    }

    Ok(())
}

fn stub_close(uc: &mut Unicorn<'_, RuntimeState>) -> Result<(), VmError> {
    let fd = arg(uc, 0)?;
    let fd_index = usize::try_from(fd).map_err(|_| VmError::InvalidFileDescriptor(fd))?;

    let state = uc.get_data_mut();
    let slot = state
        .file_handles
        .get_mut(fd_index)
        .ok_or(VmError::InvalidFileDescriptor(fd))?;
    *slot = None;

    ret(uc, 0)?;
    Ok(())
}

fn stub_dlopen(uc: &mut Unicorn<'_, RuntimeState>) -> Result<(), VmError> {
    let path_ptr = arg(uc, 0)?;
    let path = read_c_string(uc, path_ptr, 0x1000)?;

    let library_name = path.rsplit('/').next().ok_or(VmError::EmptyPath)?;
    if std::env::var("EMU_DL_DEBUG").is_ok() { eprintln!("[dl] dlopen('{path}')"); }
    let library_index = load_library_by_name(uc, library_name)?;

    ret(uc, (library_index + 1) as u64)?;
    Ok(())
}

fn stub_dlsym(uc: &mut Unicorn<'_, RuntimeState>) -> Result<(), VmError> {
    let handle = arg(uc, 0)?;
    if handle == 0 {
        return Err(VmError::InvalidDlopenHandle(handle));
    }

    let symbol_ptr = arg(uc, 1)?;
    let symbol_name = read_c_string(uc, symbol_ptr, 0x1000)?;
    let library_index = (handle - 1) as usize;

    {
        let state = uc.get_data();
        if let Some(library) = state.loaded_libraries.get(library_index) {
            debug_trace(format!(
                "dlsym({handle:X} ({}), '{}')",
                library.name, symbol_name
            ));
        }
    }

    if std::env::var("EMU_DL_DEBUG").is_ok() { eprintln!("[dl] dlsym('{symbol_name}')"); }
    let symbol_address =
        resolve_symbol_from_loaded_library_by_name(uc, library_index, &symbol_name)?;
    debug_print(format!("Found at 0x{symbol_address:X}"));
    ret(uc, symbol_address)?;
    Ok(())
}

fn stub_dlclose(uc: &mut Unicorn<'_, RuntimeState>) -> Result<(), VmError> {
    ret(uc, 0)?;
    Ok(())
}

fn stub_gettimeofday(uc: &mut Unicorn<'_, RuntimeState>) -> Result<(), VmError> {
    let time_ptr = arg(uc, 0)?;
    let tz_ptr = arg(uc, 1)?;
    debug_trace(format!("gettimeofday(0x{time_ptr:X}, 0x{tz_ptr:X})"));
    if tz_ptr != 0 {
        return Err(VmError::UnhandledImport(format!(
            "gettimeofday tz pointer must be null, got 0x{tz_ptr:X}"
        )));
    }

    // Clock override priority: perf's process-global BATCH_TIME (set by batch loops) >
    // EMU_FAKE_TIME > EMU_FIXED_TIME_SEC/USEC (deterministic OTP inputs) > real clock.
    let batch = crate::adi::BATCH_TIME.load(std::sync::atomic::Ordering::Relaxed);
    let (sec, usec): (u64, i64) = if batch != 0 {
        (batch, 0)
    } else if let Some(v) = std::env::var("EMU_FAKE_TIME").ok().filter(|v| !v.is_empty()) {
        (v.parse().unwrap_or(0), 0)
    } else if let Ok(fx) = std::env::var("EMU_FIXED_TIME_SEC") {
        let sec = fx.parse::<u64>().unwrap_or(0);
        let usec = std::env::var("EMU_FIXED_TIME_USEC").ok().and_then(|v| v.parse::<i64>().ok()).unwrap_or(0);
        (sec, usec)
    } else {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        (now.as_secs(), now.subsec_micros() as i64)
    };

    let mut timeval = [0_u8; 16];
    timeval[0..8].copy_from_slice(&sec.to_le_bytes());
    timeval[8..16].copy_from_slice(&usec.to_le_bytes());
    debug_print(format!(
        "{{'tv_sec': {sec}, 'tv_usec': {usec}}} {} {}",
        bytes_to_hex(&timeval),
        timeval.len()
    ));

    uc.mem_write(time_ptr, &timeval)?;
    ret(uc, 0)?;

    Ok(())
}

fn stub_errno_location(uc: &mut Unicorn<'_, RuntimeState>) -> Result<(), VmError> {
    if uc.get_data().errno_address.is_none() {
        debug_print("Checking errno before first error (!)");
    }
    let errno_address = ensure_errno_address(uc)?;
    ret(uc, errno_address)?;
    Ok(())
}

fn stub_system_property_get(uc: &mut Unicorn<'_, RuntimeState>) -> Result<(), VmError> {
    let name_ptr = arg(uc, 0)?;
    let name = read_c_string(uc, name_ptr, 0x1000)?;
    debug_trace(format!("__system_property_get({name}, [...])"));
    let value_ptr = arg(uc, 1)?;
    let value = b"no s/n number\0";
    uc.mem_write(value_ptr, value)?;
    ret(uc, (value.len() - 1) as u64)?;
    Ok(())
}

fn stub_arc4random(uc: &mut Unicorn<'_, RuntimeState>) -> Result<(), VmError> {
    // EMU_ARC4_VARY=1: return a varying PRNG (xorshift) instead of a fixed constant, to test
    // whether the obfuscator's seeding needs distinct random values. Default stays fixed.
    if std::env::var("EMU_ARC4_VARY").is_ok() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static S: AtomicU64 = AtomicU64::new(0x9E3779B97F4A7C15);
        let mut x = S.load(Ordering::Relaxed);
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        S.store(x, Ordering::Relaxed);
        return ret(uc, (x & 0xFFFF_FFFF) as u64);
    }
    ret(uc, 0x1234_5678)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Allocator;

    #[test]
    fn allocator_aligns_to_pages() {
        let mut allocator = Allocator::new(0x1000_0000, 0x20_000);
        let a = allocator.alloc(1).expect("alloc 1");
        let b = allocator.alloc(0x1500).expect("alloc 2");

        assert_eq!(a, 0x1000_0000);
        assert_eq!(b, 0x1000_1000);
    }
}

fn stub_gethostuuid(uc: &mut Unicorn<'_, RuntimeState>) -> Result<(), VmError> {
    // gethostuuid(uuid_t out, const struct timespec* wait) -> 0; fill a stable 16-byte UUID.
    let out = arg(uc, 0)?;
    let mut uuid: [u8; 16] = [
        0x4D, 0x41, 0x44, 0x49, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
    ];
    if let Ok(h) = std::env::var("EMU_HOSTUUID") {
        let hx: String = h.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        for i in 0..16 { if let Ok(b)=u8::from_str_radix(&hx.get(i*2..i*2+2).unwrap_or("00"),16){ uuid[i]=b; } }
    }
    uc.mem_write(out, &uuid)?;
    ret(uc, 0)
}

/// Resolve the stub-slot address an imported data symbol was bound to (name has no leading `_`).
/// CoreADI reads these slots as the pointer VALUE of `kCFBooleanTrue`, `kCFURLIsDirectoryKey`, etc.,
/// so we must hand back the exact same slot addresses when it compares them.
fn import_slot_addr(uc: &Unicorn<'_, RuntimeState>, name: &str) -> Option<u64> {
    let state = uc.get_data();
    for lib in &state.loaded_libraries {
        if let Some(s) = lib.symbols.iter().find(|s| s.name == name) {
            return Some(s.resolved);
        }
    }
    None
}

// CFURLCreateFromFileSystemRepresentation(allocator, buffer, bufLen, isDirectory) -> CFURLRef.
// Records the guest path under a fresh opaque handle; the core later queries it via copy_prop.
fn stub_cfurl_create(uc: &mut Unicorn<'_, RuntimeState>) -> Result<(), VmError> {
    let buf = arg(uc, 1)?;
    let len = arg(uc, 2)? as usize;
    let bytes = uc.mem_read_as_vec(buf, len.min(0x1000))?;
    let path = String::from_utf8_lossy(&bytes).trim_end_matches('\0').to_string();
    let handle = {
        let state = uc.get_data_mut();
        let h = state.cfurl_next;
        state.cfurl_next += 0x10;
        state.cfurls.insert(h, path.clone());
        h
    };
    if std::env::var("EMU_OBJC_DEBUG").is_ok() {
        eprintln!("[cfurl] create('{path}') -> 0x{handle:X}");
    }
    ret(uc, handle)
}

// CFURLCopyResourcePropertyForKey(url, key, valuePtr, errorPtr) -> Boolean.
// Answers kCFURLIsDirectoryKey (real FS check), kCFURLIsHiddenKey (false), and the opaque
// kCFURLFileSecurityKey / kCFURLTypeIdentifierKey (non-null handle) so the store path proceeds.
fn stub_cfurl_copy_prop(uc: &mut Unicorn<'_, RuntimeState>) -> Result<(), VmError> {
    let url = arg(uc, 0)?;
    let key = arg(uc, 1)?;
    let out = arg(uc, 2)?;
    let path = uc.get_data().cfurls.get(&url).cloned();
    let is_dir_key = import_slot_addr(uc, "kCFURLIsDirectoryKey");
    let is_hidden_key = import_slot_addr(uc, "kCFURLIsHiddenKey");
    let fsec_key = import_slot_addr(uc, "kCFURLFileSecurityKey");
    let type_key = import_slot_addr(uc, "kCFURLTypeIdentifierKey");
    let bool_true = import_slot_addr(uc, "kCFBooleanTrue").unwrap_or(1);
    let bool_false = import_slot_addr(uc, "kCFBooleanFalse").unwrap_or(0);

    if Some(key) == is_dir_key {
        let is_dir = path
            .as_deref()
            .and_then(sandbox_path)
            .map(|p| p.is_dir())
            .unwrap_or(false);
        if std::env::var("EMU_OBJC_DEBUG").is_ok() {
            eprintln!("[cfurl] IsDirectory('{}') -> {is_dir}", path.as_deref().unwrap_or("?"));
        }
        uc.mem_write(out, &(if is_dir { bool_true } else { bool_false }).to_le_bytes())?;
        return ret(uc, 1);
    }
    if Some(key) == is_hidden_key {
        uc.mem_write(out, &bool_false.to_le_bytes())?;
        return ret(uc, 1);
    }
    if Some(key) == fsec_key || Some(key) == type_key {
        // Opaque non-null object; the core only passes it to CFFileSecuritySetMode (stubbed -> 1).
        uc.mem_write(out, &0x7F00_0000u64.to_le_bytes())?;
        return ret(uc, 1);
    }
    if std::env::var("EMU_OBJC_DEBUG").is_ok() {
        eprintln!("[cfurl] copy_prop unknown key 0x{key:X}");
    }
    ret(uc, 0)
}

fn stub_objc_msgsend(uc: &mut Unicorn<'_, RuntimeState>) -> Result<(), VmError> {
    // No objc runtime: a selref slot still points at its __objc_methname C string (rebased),
    // so arg1 is a readable selector name. Log it and answer the known load-time queries.
    let receiver = arg(uc, 0)?;
    let sel_ptr = arg(uc, 1)?;
    let sel = read_c_string(uc, sel_ptr, 128).unwrap_or_default();
    if std::env::var("EMU_OBJC_DEBUG").is_ok() {
        eprintln!("[objc] objc_msgSend(recv=0x{receiver:X}, sel='{sel}')");
    }
    // The core does [[NSProcessInfo processInfo] operatingSystem] as a platform gate.
    let _ = receiver;
    match sel.as_str() {
        // Return a non-null sentinel object so the next message has a valid receiver.
        "processInfo" | "sharedInstance" | "defaultManager" => ret(uc, 0x5000_0000),
        // -[NSProcessInfo operatingSystem] -> os-findmy-e returns 0x0D (13).
        "operatingSystem" => ret(uc, std::env::var("EMU_OS").ok().and_then(|v| v.parse().ok()).unwrap_or(13)),
        "isOperatingSystemAtLeastVersion:" => ret(uc, std::env::var("EMU_OSATLEAST").ok().and_then(|v| v.parse().ok()).unwrap_or(1)),
        _ => ret(uc, 0),
    }
}
