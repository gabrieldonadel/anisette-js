use std::collections::HashMap;
use std::fs::File;

use crate::allocator::Allocator;
use crate::constants::{
    LIB_ALLOC_BASE, LIB_ALLOC_SIZE, MALLOC_ADDRESS, MALLOC_SIZE, TEMP_ALLOC_BASE, TEMP_ALLOC_SIZE,
};

#[derive(Debug, Clone)]
pub(crate) struct SymbolEntry {
    pub(crate) name: String,
    pub(crate) resolved: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct LoadedLibrary {
    pub(crate) name: String,
    pub(crate) symbols: Vec<SymbolEntry>,
    pub(crate) symbols_by_name: HashMap<String, u64>,
}

#[derive(Debug)]
pub(crate) struct RuntimeState {
    pub(crate) temp_allocator: Allocator,
    pub(crate) library_allocator: Allocator,
    pub(crate) malloc_allocator: Allocator,
    pub(crate) errno_address: Option<u64>,
    pub(crate) library_blobs: HashMap<String, Vec<u8>>,
    pub(crate) loaded_libraries: Vec<LoadedLibrary>,
    pub(crate) file_handles: Vec<Option<File>>,
    pub(crate) library_root: Option<String>,
    // clean-room RE: when Some, every guest memory WRITE is recorded
    // (addr, size, value, pc_trace_index_at_write).
    pub(crate) mem_writes: Option<Vec<(u64, u32, i64, u64)>>,
    // clean-room RE: when Some, every executed instruction (pc, opcode) is recorded.
    pub(crate) pc_trace: Option<Vec<(u64, u32)>>,
    // clean-room RE: when Some, a pre-execution register snapshot [X0..X30, SP] is
    // recorded per instruction, index-aligned with pc_trace. This is the complete
    // concrete dataflow: memory-load results appear in the next snapshot's dest reg.
    pub(crate) reg_trace: Option<Vec<[u64; 32]>>,
    // clean-room RE (DFA): when Some=(target_index, reg_col, xor_mask), XOR that mask
    // into REG_SNAPSHOT[reg_col] just before the target-th executed instruction.
    // First-order masking is transparent to faults, so this faults the true value.
    pub(crate) fault: Option<(u64, usize, u64)>,
    pub(crate) fault_counter: u64,
    // perf: high-water marks of the bump allocators captured before the first OTP, so
    // per-request temp/malloc allocations can be reclaimed instead of reloading the lib.
    pub(crate) temp_mark: Option<u64>,
    pub(crate) malloc_mark: Option<u64>,
}

impl RuntimeState {
    pub(crate) fn new() -> Self {
        Self {
            temp_allocator: Allocator::new(TEMP_ALLOC_BASE, TEMP_ALLOC_SIZE),
            library_allocator: Allocator::new(LIB_ALLOC_BASE, LIB_ALLOC_SIZE),
            malloc_allocator: Allocator::new(MALLOC_ADDRESS, MALLOC_SIZE),
            errno_address: None,
            library_blobs: HashMap::new(),
            loaded_libraries: Vec::new(),
            file_handles: Vec::new(),
            library_root: None,
            mem_writes: None,
            pc_trace: None,
            reg_trace: None,
            fault: None,
            fault_counter: 0,
            temp_mark: None,
            malloc_mark: None,
        }
    }
}
