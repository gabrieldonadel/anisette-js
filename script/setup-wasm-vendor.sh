#!/usr/bin/env bash
# Prepare the patched unicorn-engine crates the wasm32 build needs, into a gitignored
# .wasm-vendor/ tree that Cargo.toml's [patch.crates-io] points at.
#
# Why this exists: for wasm the unicorn C lib is the prebuilt emscripten build (size_t = 4), but
# `unicorn-engine-sys`'s bindgen renders the `uc_mem_*` size params as `u64` (host libclang ignores
# --target=wasm32). That makes an invalid WASM module. We fix it deterministically: rewrite the
# generated bindings to `usize` and cast the matching unicorn-engine call sites. Idempotent — safe
# to re-run; it re-copies from the cargo registry each time.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDOR="${ROOT_DIR}/.wasm-vendor/x"   # extra nesting: unicorn-engine-sys/build.rs walks parent^3
SYS_VER="2.1.5"
ENGINE_VER="2.1.5"

find_crate() {
  local name="$1"
  find "${CARGO_HOME:-$HOME/.cargo}/registry/src" -maxdepth 2 -type d -name "${name}" 2>/dev/null | head -1
}

SYS_SRC="$(find_crate "unicorn-engine-sys-${SYS_VER}")"
ENGINE_SRC="$(find_crate "unicorn-engine-${ENGINE_VER}")"
if [[ -z "${SYS_SRC}" || -z "${ENGINE_SRC}" ]]; then
  echo "error: unicorn-engine(-sys) ${SYS_VER} not in the cargo registry. Run a native 'cargo fetch' first." >&2
  exit 1
fi

rm -rf "${VENDOR}"
mkdir -p "${VENDOR}"
cp -R "${SYS_SRC}" "${VENDOR}/unicorn-engine-sys"
cp -R "${ENGINE_SRC}" "${VENDOR}/unicorn-engine"
chmod -R u+w "${VENDOR}"

python3 - "${VENDOR}" <<'PY'
import sys, pathlib
vendor = pathlib.Path(sys.argv[1])

# 1) unicorn-engine-sys/build.rs: post-process the generated bindings so the uc_mem_* size params
#    are usize (matching the emscripten C lib), and stop the build script re-running on every build.
b = vendor / "unicorn-engine-sys" / "build.rs"
s = b.read_text()
anchor = '''    bindings
        .write_to_file(&bindings_rs)
        .unwrap_or_else(|_| panic!("Failed to write bindings into path: {bindings_rs:?}"));'''
inject = anchor + '''
    if std::env::var("TARGET").as_deref() == Ok("wasm32-unknown-emscripten") {
        if let Ok(src) = std::fs::read_to_string(&bindings_rs) {
            let _ = std::fs::write(&bindings_rs, src.replace("size: u64", "size: usize"));
        }
    }'''
assert anchor in s, "build.rs write_to_file anchor not found"
s = s.replace(anchor, inject, 1)
# watch_source_files() computes a path via parent^3 and panics on shallow vendored dirs; make it a
# no-op that only watches build.rs (also stops spurious regeneration overwriting our patch).
import re
s = re.sub(r"fn watch_source_files\(\) \{.*?\n\}\n",
           'fn watch_source_files() {\n    println!("cargo:rerun-if-changed=build.rs");\n}\n',
           s, count=1, flags=re.S)
b.write_text(s)

# 2) unicorn-engine/src/lib.rs: the public API keeps size: u64; cast to usize at the FFI call sites.
l = vendor / "unicorn-engine" / "src" / "lib.rs"
t = l.read_text()
for call in ("uc_mem_map_ptr", "uc_mem_map", "uc_mem_unmap", "uc_mem_protect", "uc_mmio_map"):
    t = re.sub(rf"({call}\(\s*self\.get_handle\(\),\s*address,\s*)size\b", r"\1size as _", t)
l.write_text(t)
print("patched unicorn-engine(-sys) for wasm size_t")
PY

echo "wasm vendor ready at ${VENDOR}"
