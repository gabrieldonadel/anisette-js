//! CPU-arch abstraction so the ELF loader, stubs, and call harness work for both the
//! AArch64 and the x86_64 Android ADI libraries. The library ABI (bionic struct layouts,
//! errno, dlopen/dlsym contract) is identical across the two — only the CPU registers,
//! relocation types, return-stub opcode, and calling convention differ.

use unicorn_engine::{RegisterARM64, RegisterX86, Unicorn};

use crate::errors::VmError;
use crate::runtime::RuntimeState;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EmuArch {
    Arm64,
    X86_64,
}

/// Integer argument register `i` (0-based) under the platform calling convention.
pub(crate) fn arg(uc: &Unicorn<'_, RuntimeState>, i: usize) -> Result<u64, VmError> {
    Ok(match uc.get_data().arch {
        EmuArch::Arm64 => uc.reg_read(
            [
                RegisterARM64::X0,
                RegisterARM64::X1,
                RegisterARM64::X2,
                RegisterARM64::X3,
                RegisterARM64::X4,
                RegisterARM64::X5,
            ][i],
        )?,
        EmuArch::X86_64 => uc.reg_read(
            [
                RegisterX86::RDI,
                RegisterX86::RSI,
                RegisterX86::RDX,
                RegisterX86::RCX,
                RegisterX86::R8,
                RegisterX86::R9,
            ][i],
        )?,
    })
}

/// Write the integer return value under the platform calling convention.
pub(crate) fn ret(uc: &mut Unicorn<'_, RuntimeState>, value: u64) -> Result<(), VmError> {
    match uc.get_data().arch {
        EmuArch::Arm64 => uc.reg_write(RegisterARM64::X0, value)?,
        EmuArch::X86_64 => uc.reg_write(RegisterX86::RAX, value)?,
    }
    Ok(())
}
