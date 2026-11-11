use std::fs;
use std::path::{Path, PathBuf};

use anisette_rs::{Adi, AdiInit, Device, ProvisioningSession, init_idbfs_for_path, sync_idbfs};
use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::json;

fn main() -> Result<()> {
    // Usage:
    // cargo run --example anisette -- <libstoreservicescore.so> <libCoreADI.so> <library_path> [dsid] [apple_root_pem]
    let storeservices_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "libstoreservicescore.so".to_string());
    let coreadi_path = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "libCoreADI.so".to_string());
    let library_path = std::env::args()
        .nth(3)
        .unwrap_or_else(|| "./anisette/".to_string());
    let dsid_raw = std::env::args().nth(4).unwrap_or_else(|| "-2".to_string());
    let apple_root_pem = std::env::args().nth(5).map(PathBuf::from);

    let _mount_path = init_idbfs_for_path(&library_path)
        .map_err(|e| anyhow::anyhow!("failed to initialize IDBFS: {e}"))?;

    fs::create_dir_all(&library_path)
        .with_context(|| format!("failed to create library path: {library_path}"))?;

    let device_path = Path::new(&library_path).join("device.json");
    let mut device = Device::load(&device_path)?;

    let storeservicescore = fs::read(&storeservices_path)
        .with_context(|| format!("failed to read {storeservices_path}"))?;
    let coreadi =
        fs::read(&coreadi_path).with_context(|| format!("failed to read {coreadi_path}"))?;

    let mut adi = Adi::new(AdiInit {
        storeservicescore,
        coreadi,
        library_path: library_path.clone(),
        provisioning_path: Some(library_path.clone()),
        identifier: None,
    })?;

    if !device.initialized {
        println!("Initializing device");
        device.initialize_defaults();
        device.persist()?;
    } else {
        println!(
            "(Device initialized: server-description='{}' device-uid='{}' adi='{}' user-uid='{}')",
            device.data.server_friendly_description,
            device.data.unique_device_identifier,
            device.data.adi_identifier,
            device.data.local_user_uuid
        );
    }

    adi.set_identifier(&device.data.adi_identifier)?;

    let dsid = if let Some(hex) = dsid_raw.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)?
    } else {
        let signed: i64 = dsid_raw.parse()?;
        signed as u64
    };

    // EMU_OFFLINE_SPIM=<file>: deterministic cpim repro — skip server, feed fixed spim.
    if let Ok(spim_file) = std::env::var("EMU_OFFLINE_SPIM") {
        let spim_b64 = std::fs::read_to_string(&spim_file)?;
        let spim = STANDARD.decode(spim_b64.trim().as_bytes())?;
        let start = adi.start_provisioning(dsid, &spim)?;
        println!("SESSION 0x{:x}", start.session);
        println!("CPIM_LEN {}", start.cpim.len());
        let hx: String = start.cpim.iter().map(|b| format!("{b:02x}")).collect();
        println!("CPIM {hx}");
        if let (Ok(pf), Ok(tf)) = (std::env::var("EMU_OFFLINE_PTM"), std::env::var("EMU_OFFLINE_TK")) {
            let ptm = STANDARD.decode(std::fs::read_to_string(&pf)?.trim().as_bytes())?;
            let tk = STANDARD.decode(std::fs::read_to_string(&tf)?.trim().as_bytes())?;
            match adi.end_provisioning(start.session, &ptm, &tk) {
                Ok(()) => println!("END_RESULT OK"),
                Err(e) => println!("END_RESULT ERR {e:?}"),
            }
        }
        return Ok(());
    }

    let is_provisioned = adi.is_machine_provisioned(dsid)?;

    if !is_provisioned {
        println!("Provisioning...");
        let mut provisioning_session =
            ProvisioningSession::new(&mut adi, &device.data, apple_root_pem)?;
        provisioning_session.provision(dsid)?;
    } else {
        println!("(Already provisioned)");
    }

    // clean-room RE: batch OTP sweep. EMU_BATCH="start:end:outfile" enumerates
    // body(counter16) for counter16 in [start,end) without reloading libs.
    // Sets the process-global clock so gettimeofday returns counter16*30.
    if let Ok(spec) = std::env::var("EMU_BATCH") {
        use std::sync::atomic::Ordering;
        let parts: Vec<&str> = spec.split(':').collect();
        let start: u64 = parts[0].parse().unwrap_or(0);
        let end: u64 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(65536);
        let outfile = parts.get(2).copied().unwrap_or("otp_table.tsv");
        // The emulated core errors after ~128 OTP requests (state accumulates), so
        // rebuild a fresh, already-provisioned Adi every REINIT calls.
        const REINIT: u64 = 100_000_000;
        let ident = device.data.adi_identifier.clone();
        let build_adi = || -> Result<Adi> {
            let ssc = fs::read(&storeservices_path)?;
            let core = fs::read(&coreadi_path)?;
            let mut a = Adi::new(AdiInit {
                storeservicescore: ssc,
                coreadi: core,
                library_path: library_path.clone(),
                provisioning_path: Some(library_path.clone()),
                identifier: None,
            })?;
            a.set_identifier(&ident)?;
            Ok(a)
        };
        let mut buf = String::new();
        let mut done = 0u64;
        for c16 in start..end {
            if done > 0 && done % REINIT == 0 {
                adi = build_adi()?;
            }
            // +65536 buckets keeps low-16 == c16 while never yielding time 0
            // (0 is the "disabled" sentinel for the global clock).
            anisette_rs::BATCH_TIME.store((c16 + 65536) * 30, Ordering::Relaxed);
            let otp = match adi.request_otp(dsid) {
                Ok(o) => o,
                Err(e) => {
                    eprintln!("retry c16={c16}: {e}");
                    adi = build_adi()?;               // fresh emulator, retry once
                    done = 0;
                    adi.request_otp(dsid)?
                }
            };
            let body: String = otp.otp.iter().skip(8).take(16)
                .map(|b| format!("{b:02x}")).collect();
            let _ = std::fmt::Write::write_fmt(&mut buf, format_args!("{c16} {body}\n"));
            done += 1;
            if c16 % 5000 == 0 {
                fs::write(outfile, &buf)?;
                eprintln!("batch: {c16}/{end} (done={done})");
            }
        }
        fs::write(outfile, &buf)?;
        eprintln!("batch DONE: {} entries -> {outfile}", end - start);
        return Ok(());
    }

    // clean-room RE (DFA): single fault. EMU_FAULT="idx:col:bit" prints the baseline
    // and faulted OTP body (fix the counter with EMU_FAKE_TIME).
    if let Ok(spec) = std::env::var("EMU_FAULT") {
        // "idx:col:maskhex" — idx,col decimal; mask hex (XORed into the register).
        let p: Vec<&str> = spec.split(':').collect();
        let idx: u64 = p[0].parse().unwrap_or(0);
        let col: usize = p[1].parse().unwrap_or(0);
        let mask: u64 = u64::from_str_radix(p[2].trim_start_matches("0x"), 16).unwrap_or(0);
        let base = adi.request_otp(dsid)?;
        let bhex: String = base.otp.iter().skip(8).take(16).map(|b| format!("{b:02x}")).collect();
        let f = adi.request_otp_faulted(dsid, idx, col, mask)?;
        let fhex: String = f.otp.iter().skip(8).take(16).map(|b| format!("{b:02x}")).collect();
        println!("BASE {bhex}");
        println!("FAULT(idx={idx},col={col},mask={mask:#x}) {fhex}");
        println!("DIFF {}", if bhex == fhex { "none" } else { "CHANGED" });
        return Ok(());
    }

    // clean-room RE (DFA): fault scan. EMU_FAULT_SCAN="lo:hi:col:bit:outfile" runs one
    // faulted OTP per target index in [lo,hi) and records the body. Rebuilds every 100.
    if let Ok(spec) = std::env::var("EMU_FAULT_SCAN") {
        let parts: Vec<&str> = spec.split(':').collect();
        let lo: u64 = parts[0].parse().unwrap_or(0);
        let hi: u64 = parts[1].parse().unwrap_or(0);
        let col: usize = parts[2].parse().unwrap_or(0);
        let bit: u32 = parts[3].parse().unwrap_or(0);
        let outfile = parts.get(4).copied().unwrap_or("fault_scan.tsv");
        let ident = device.data.adi_identifier.clone();
        let build_adi = || -> Result<Adi> {
            let ssc = fs::read(&storeservices_path)?;
            let core = fs::read(&coreadi_path)?;
            let mut a = Adi::new(AdiInit { storeservicescore: ssc, coreadi: core,
                library_path: library_path.clone(),
                provisioning_path: Some(library_path.clone()), identifier: None })?;
            a.set_identifier(&ident)?; Ok(a)
        };
        let base = adi.request_otp(dsid)?;
        let bhex: String = base.otp.iter().skip(8).take(16).map(|b| format!("{b:02x}")).collect();
        let mut buf = format!("# baseline {bhex}\n");
        let mut done = 0u64;
        for idx in lo..hi {
            if done > 0 && done % 100 == 0 { adi = build_adi()?; }
            let fmask = 1u64 << bit;
            let f = match adi.request_otp_faulted(dsid, idx, col, fmask) {
                Ok(o) => o, Err(_) => { adi = build_adi()?; done = 0;
                    match adi.request_otp_faulted(dsid, idx, col, fmask) { Ok(o)=>o, Err(_)=>{ continue } } }
            };
            let fhex: String = f.otp.iter().skip(8).take(16).map(|b| format!("{b:02x}")).collect();
            if fhex != bhex {
                let _ = std::fmt::Write::write_fmt(&mut buf, format_args!("{idx} {fhex}\n"));
            }
            done += 1;
            if idx % 2000 == 0 { fs::write(outfile, &buf)?; eprintln!("fault-scan {idx}/{hi}"); }
        }
        fs::write(outfile, &buf)?;
        eprintln!("fault-scan DONE lo={lo} hi={hi} col={col} bit={bit} -> {outfile}");
        return Ok(());
    }

    let otp = if let Ok(tag) = std::env::var("EMU_TRACE_OTP") {
        let (otp, writes, pcs, regs) = adi.request_otp_traced(dsid)?;
        let mut w = String::new();
        for (addr, size, value, pc_idx) in &writes {
            let _ = std::fmt::Write::write_fmt(
                &mut w,
                format_args!("{addr:016x} {size} {:016x} {pc_idx}\n", *value as u64),
            );
        }
        fs::write(format!("otp_writes_{tag}.txt"), w)?;
        let mut p = String::new();
        for (pc, opcode) in &pcs {
            let _ = std::fmt::Write::write_fmt(&mut p, format_args!("{pc:016x} {opcode:08x}\n"));
        }
        fs::write(format!("otp_pcs_{tag}.txt"), p)?;
        // clean-room RE: binary register trace. Layout per instruction: 32 x u64
        // little-endian = [X0..X30, SP], index-aligned with otp_pcs_{tag}.txt.
        if !regs.is_empty() {
            let mut rb: Vec<u8> = Vec::with_capacity(regs.len() * 32 * 8);
            for snap in &regs {
                for v in snap {
                    rb.extend_from_slice(&v.to_le_bytes());
                }
            }
            fs::write(format!("otp_regs_{tag}.bin"), &rb)?;
            eprintln!("TRACE: {} reg snapshots -> otp_regs_{tag}.bin ({} bytes)", regs.len(), rb.len());
        }
        eprintln!("TRACE: {} writes, {} instructions -> otp_{{writes,pcs}}_{tag}.txt", writes.len(), pcs.len());
        eprintln!("OTP_BODY: {}", otp.otp.iter().skip(8).take(16).map(|b| format!("{b:02x}")).collect::<String>());
        otp
    } else {
        adi.request_otp(dsid)?
    };
    let headers = json!({
      "X-Apple-I-MD": STANDARD.encode(otp.otp),
      "X-Apple-I-MD-M": STANDARD.encode(otp.machine_id),
    });

    let _ = sync_idbfs(false);
    println!("{}", serde_json::to_string_pretty(&headers)?);
    Ok(())
}
