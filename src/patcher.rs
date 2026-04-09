/// PIN2DMD Firmware Patcher Engine
/// Replicates the logic from patch_timer.py, patch_branch.py, patch_keygen.py, patch_all.py

use std::fmt;

// ── Constants ──────────────────────────────────────────────────────────────

const FLASH_BASE: u32 = 0x0800_0000;
const MILLIS_ADDR: u32 = 0x0802_1430;

/// Original timer threshold: 180000ms (3 minutes) in little-endian
const TIMER_ORIGINAL: [u8; 4] = [0x20, 0xBF, 0x02, 0x00];
/// Patched timer: 0xFFFFFFFF (~49.7 days)
const TIMER_PATCHED: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];

/// Expected timer patch offsets (17 render functions)
const TIMER_OFFSETS: [u32; 17] = [
    0x55204, 0x558A0, 0x55D78, 0x56310, 0x568A4, 0x56E04, 0x57360,
    0x578BC, 0x57E14, 0x5836C, 0x588C4, 0x58E1C, 0x59374, 0x59604,
    0x59898, 0x59B28, 0x59D04,
];

/// Keygen patch offset and values
const KEYGEN_OFFSET: usize = 0x52734;
const KEYGEN_ORIGINAL: [u8; 2] = [0x00, 0x23]; // movs r3, #0
const KEYGEN_PATCHED: [u8; 2] = [0x4E, 0x23];  // movs r3, #0x4E ('N')

/// Branch patch pattern: eor r3,r3,#1 / uxtb r3,r3 / cmp r3,#0 / beq ...
const BRANCH_PATTERN_PREFIX: [u8; 7] = [0x83, 0xF0, 0x01, 0x03, 0xDB, 0xB2, 0x00];
// Followed by: 0x2B, imm8, 0xD0 (BEQ), then BL to millis

/// Key verification pattern: mov r3, r0 / cmp r3, #0
const KEY_CHECK_PATTERN: [u8; 4] = [0x03, 0x46, 0x00, 0x2B];
const CLEANUP_ADDR: u32 = 0x0805_25C4;
const NOP: [u8; 2] = [0x00, 0xBF];

// ── Patch types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchType {
    Timer,
    Branch,
    Keygen,
    KeyBypass,
}

impl fmt::Display for PatchType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PatchType::Timer => write!(f, "TIMER"),
            PatchType::Branch => write!(f, "BRANCH"),
            PatchType::Keygen => write!(f, "KEYGEN"),
            PatchType::KeyBypass => write!(f, "KEY_BYPASS"),
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PatchResult {
    pub patch_type: PatchType,
    pub offset: u32,
    pub original: Vec<u8>,
    pub patched: Vec<u8>,
    pub description: String,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PatchReport {
    pub patches: Vec<PatchResult>,
    pub errors: Vec<String>,
    pub firmware_size: usize,
}

impl PatchReport {
    pub fn total_patches(&self) -> usize {
        self.patches.len()
    }
}

// ── Decoder helpers ────────────────────────────────────────────────────────

/// Decode a Thumb-2 BL instruction at `offset` and return absolute target address
fn decode_bl_target(data: &[u8], offset: usize) -> Option<u32> {
    if offset + 4 > data.len() {
        return None;
    }
    let hw1 = u16::from_le_bytes([data[offset], data[offset + 1]]);
    let hw2 = u16::from_le_bytes([data[offset + 2], data[offset + 3]]);

    // Check BL encoding: hw1 starts with 0xF0xx, hw2 with 0xF8xx-0xFFxx
    if (hw1 >> 11) != 0x1E || (hw2 >> 12) != 0xF && (hw2 >> 12) != 0xD {
        // More lenient check
    }

    let s = ((hw1 >> 10) & 1) as u32;
    let imm10 = (hw1 & 0x3FF) as u32;
    let j1 = ((hw2 >> 13) & 1) as u32;
    let j2 = ((hw2 >> 11) & 1) as u32;
    let imm11 = (hw2 & 0x7FF) as u32;

    let i1 = (!(j1 ^ s)) & 1;
    let i2 = (!(j2 ^ s)) & 1;

    let mut imm32 = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1);
    if s != 0 {
        imm32 |= 0xFE00_0000; // sign extend
    }

    let pc = FLASH_BASE + offset as u32 + 4;
    Some(pc.wrapping_add(imm32))
}

// ── Patch functions ────────────────────────────────────────────────────────

/// Apply timer patches: replace 180000ms with 0xFFFFFFFF at all 17 locations
pub fn patch_timer(data: &mut Vec<u8>) -> Vec<PatchResult> {
    let mut results = Vec::new();
    let mut offset = 0;
    let mut count = 0;

    while offset + 4 <= data.len() {
        if data[offset..offset + 4] == TIMER_ORIGINAL {
            let original = data[offset..offset + 4].to_vec();
            data[offset..offset + 4].copy_from_slice(&TIMER_PATCHED);
            count += 1;

            results.push(PatchResult {
                patch_type: PatchType::Timer,
                offset: offset as u32,
                original,
                patched: TIMER_PATCHED.to_vec(),
                description: format!(
                    "Timer #{}: 180000ms -> 0xFFFFFFFF at 0x{:05X}",
                    count, offset
                ),
            });
            offset += 4;
        } else {
            offset += 1;
        }
    }

    results
}

/// Apply branch patches: convert BEQ to unconditional B (skip millis check)
pub fn patch_branch(data: &mut Vec<u8>) -> Vec<PatchResult> {
    let mut results = Vec::new();
    let mut offset = 0;

    while offset + 14 <= data.len() {
        // Check for the pattern prefix
        if data[offset..offset + 7] == BRANCH_PATTERN_PREFIX {
            // Check cmp r3, #0
            if data[offset + 7] == 0x2B {
                let beq_offset = offset + 8;
                let imm8 = data[beq_offset];
                let cond = data[beq_offset + 1];

                // Must be BEQ (0xD0)
                if cond == 0xD0 {
                    // Verify BL target is millis()
                    let bl_offset = beq_offset + 2;
                    if bl_offset + 4 <= data.len() {
                        if let Some(target) = decode_bl_target(data, bl_offset) {
                            if target == MILLIS_ADDR || target == MILLIS_ADDR + 1 {
                                let original = vec![imm8, 0xD0];
                                data[beq_offset + 1] = 0xE0; // BEQ -> B (unconditional)

                                results.push(PatchResult {
                                    patch_type: PatchType::Branch,
                                    offset: beq_offset as u32,
                                    original,
                                    patched: vec![imm8, 0xE0],
                                    description: format!(
                                        "BEQ -> B unconditional at 0x{:05X} (skip millis call at 0x{:05X})",
                                        beq_offset, bl_offset
                                    ),
                                });
                            }
                        }
                    }
                }
            }
        }
        offset += 1;
    }

    results
}

/// Apply keygen patch: force hw validation to return 'N' (0x4E)
pub fn patch_keygen(data: &mut Vec<u8>) -> Vec<PatchResult> {
    let mut results = Vec::new();

    if KEYGEN_OFFSET + 2 <= data.len() {
        if data[KEYGEN_OFFSET..KEYGEN_OFFSET + 2] == KEYGEN_ORIGINAL {
            let original = data[KEYGEN_OFFSET..KEYGEN_OFFSET + 2].to_vec();
            data[KEYGEN_OFFSET..KEYGEN_OFFSET + 2].copy_from_slice(&KEYGEN_PATCHED);

            results.push(PatchResult {
                patch_type: PatchType::Keygen,
                offset: KEYGEN_OFFSET as u32,
                original,
                patched: KEYGEN_PATCHED.to_vec(),
                description: format!(
                    "Keygen: movs r3,#0 -> movs r3,#0x4E at 0x{:05X} (force 'N')",
                    KEYGEN_OFFSET
                ),
            });
        } else if data[KEYGEN_OFFSET..KEYGEN_OFFSET + 2] == KEYGEN_PATCHED {
            results.push(PatchResult {
                patch_type: PatchType::Keygen,
                offset: KEYGEN_OFFSET as u32,
                original: KEYGEN_PATCHED.to_vec(),
                patched: KEYGEN_PATCHED.to_vec(),
                description: "Keygen: already patched".to_string(),
            });
        }
    }

    results
}

/// Apply key bypass patches: NOP out BEQ before key file validation
pub fn patch_key_bypass(data: &mut Vec<u8>) -> Vec<PatchResult> {
    let mut results = Vec::new();
    let mut offset = 0;

    while offset + 12 <= data.len() {
        if data[offset..offset + 4] == KEY_CHECK_PATTERN {
            let beq_off = offset + 4;
            // Check for BEQ (condition byte 0xD0)
            if beq_off + 2 <= data.len() && data[beq_off + 1] == 0xD0 {
                // After BEQ, check for LDR + BL to cleanup function
                let after_beq = beq_off + 2;
                if after_beq + 6 <= data.len() {
                    // Check if there's a BL instruction nearby that targets cleanup
                    let bl_off = after_beq + 2;
                    if bl_off + 4 <= data.len() {
                        if let Some(target) = decode_bl_target(data, bl_off) {
                            if target == CLEANUP_ADDR || target == CLEANUP_ADDR + 1 {
                                let original = data[beq_off..beq_off + 2].to_vec();
                                data[beq_off..beq_off + 2].copy_from_slice(&NOP);

                                results.push(PatchResult {
                                    patch_type: PatchType::KeyBypass,
                                    offset: beq_off as u32,
                                    original,
                                    patched: NOP.to_vec(),
                                    description: format!(
                                        "Key bypass: BEQ -> NOP at 0x{:05X} (skip key validation)",
                                        beq_off
                                    ),
                                });
                            }
                        }
                    }
                }
            }
        }
        offset += 1;
    }

    results
}

// ── Main patch orchestrator ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct PatchOptions {
    pub timer: bool,
    pub branch: bool,
    pub keygen: bool,
    pub key_bypass: bool,
}

#[allow(dead_code)]
impl PatchOptions {
    pub fn all() -> Self {
        Self {
            timer: true,
            branch: true,
            keygen: true,
            key_bypass: true,
        }
    }

    pub fn none() -> Self {
        Self {
            timer: false,
            branch: false,
            keygen: false,
            key_bypass: false,
        }
    }
}

/// Apply selected patches to firmware data. Returns patched data + report.
pub fn apply_patches(original: &[u8], options: PatchOptions) -> (Vec<u8>, PatchReport) {
    let mut data = original.to_vec();
    let mut all_patches = Vec::new();
    let mut errors = Vec::new();

    if options.keygen {
        let r = patch_keygen(&mut data);
        if r.is_empty() {
            errors.push("KEYGEN: pattern not found at expected offset".into());
        }
        all_patches.extend(r);
    }

    if options.timer {
        let r = patch_timer(&mut data);
        if r.is_empty() {
            errors.push("TIMER: no 180000ms values found".into());
        }
        all_patches.extend(r);
    }

    if options.branch {
        let r = patch_branch(&mut data);
        if r.is_empty() {
            errors.push("BRANCH: no BEQ->millis patterns found".into());
        }
        all_patches.extend(r);
    }

    if options.key_bypass {
        let r = patch_key_bypass(&mut data);
        if r.is_empty() {
            errors.push("KEY_BYPASS: no key check patterns found".into());
        }
        all_patches.extend(r);
    }

    let report = PatchReport {
        patches: all_patches,
        errors,
        firmware_size: data.len(),
    };

    (data, report)
}

/// Verify if a firmware is already patched (quick check on known offsets)
pub fn analyze_firmware(data: &[u8]) -> Vec<String> {
    let mut info = Vec::new();

    info.push(format!("Firmware size: {} bytes ({:.1} KB)", data.len(), data.len() as f64 / 1024.0));

    // Check keygen
    if KEYGEN_OFFSET + 2 <= data.len() {
        if data[KEYGEN_OFFSET..KEYGEN_OFFSET + 2] == KEYGEN_PATCHED {
            info.push("Keygen: PATCHED (0x4E = 'N')".into());
        } else if data[KEYGEN_OFFSET..KEYGEN_OFFSET + 2] == KEYGEN_ORIGINAL {
            info.push("Keygen: ORIGINAL (0x00)".into());
        } else {
            info.push(format!(
                "Keygen: UNKNOWN ({:02X} {:02X})",
                data[KEYGEN_OFFSET], data[KEYGEN_OFFSET + 1]
            ));
        }
    }

    // Check first timer offset
    if let Some(&first_timer) = TIMER_OFFSETS.first() {
        let off = first_timer as usize;
        if off + 4 <= data.len() {
            if data[off..off + 4] == TIMER_PATCHED {
                info.push("Timers: PATCHED (0xFFFFFFFF)".into());
            } else if data[off..off + 4] == TIMER_ORIGINAL {
                info.push("Timers: ORIGINAL (180000ms / 3min)".into());
            } else {
                info.push(format!(
                    "Timers: UNKNOWN ({:02X}{:02X}{:02X}{:02X})",
                    data[off], data[off + 1], data[off + 2], data[off + 3]
                ));
            }
        }
    }

    // Count timer patches
    let timer_count = TIMER_OFFSETS.iter().filter(|&&off| {
        let o = off as usize;
        o + 4 <= data.len() && data[o..o + 4] == TIMER_PATCHED
    }).count();
    info.push(format!("Timer locations patched: {}/17", timer_count));

    info
}
