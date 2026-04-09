"""
Patch 4 - Crack complet (combine les 3 techniques)
Applique tous les patches en une seule passe:
  1. Force la validation hardware -> toujours 'N' (active)
  2. Etend le timer -> 0xFFFFFFFF (~49.7 jours)
  3. Saute les checks de timer -> BEQ devient B inconditionnel
  4. Bypass des verifications de cle dans chaque fonction de rendu

Resultat: firmware completement deprotege.
"""
import struct
import sys

INPUT = "PIN2DMD.bin"
OUTPUT = "PIN2DMD_cracked.bin"

BASE = 0x08000000
MILLIS_ADDR = 0x08021430
CLEANUP_ADDR = 0x080525C4


def find_all(data, pattern, start=0):
    """Trouve toutes les occurrences d'un pattern."""
    offsets = []
    idx = start
    while True:
        pos = data.find(pattern, idx)
        if pos == -1:
            break
        offsets.append(pos)
        idx = pos + 1
    return offsets


def decode_bl_target(data, offset):
    """Decode la destination d'une instruction BL Thumb-2."""
    if offset + 4 > len(data):
        return None
    hw1 = struct.unpack("<H", data[offset:offset+2])[0]
    hw2 = struct.unpack("<H", data[offset+2:offset+4])[0]
    if (hw1 & 0xF800) != 0xF000 or (hw2 & 0xD000) != 0xD000:
        return None
    s = (hw1 >> 10) & 1
    j1 = (hw2 >> 13) & 1
    j2 = (hw2 >> 11) & 1
    imm10 = hw1 & 0x3FF
    imm11 = hw2 & 0x7FF
    i1 = ~(j1 ^ s) & 1
    i2 = ~(j2 ^ s) & 1
    off = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1)
    if s:
        off = off - (1 << 25)
    return BASE + offset + 4 + off


def main():
    with open(INPUT, "rb") as f:
        data = bytearray(f.read())

    original = bytes(data)
    total_patches = 0

    print("=" * 60)
    print(" PIN2DMD FULL CRACK - Audit de securite")
    print("=" * 60)

    # ================================================================
    # PATCH 1: Forcer la validation hardware
    # ================================================================
    print("\n[1/4] Patch validation hardware (0x52734)")

    KEYGEN_OFFSET = 0x52734
    KEYGEN_OLD = bytes([0x00, 0x23])  # movs r3, #0
    KEYGEN_NEW = bytes([0x4E, 0x23])  # movs r3, #0x4E ('N')

    if data[KEYGEN_OFFSET:KEYGEN_OFFSET+2] == KEYGEN_OLD:
        data[KEYGEN_OFFSET:KEYGEN_OFFSET+2] = KEYGEN_NEW
        total_patches += 1
        print(f"      0x{KEYGEN_OFFSET:05X}: 00 23 -> 4E 23  [OK]")
    else:
        print(f"      0x{KEYGEN_OFFSET:05X}: SKIP (bytes inattendus)")

    # ================================================================
    # PATCH 2: Etendre le timer (180000ms -> 0xFFFFFFFF)
    # ================================================================
    print("\n[2/4] Patch timer (180000ms -> max)")

    TIMER_OLD = struct.pack("<I", 180000)
    TIMER_NEW = struct.pack("<I", 0xFFFFFFFF)
    timer_offsets = find_all(data, TIMER_OLD)

    for off in timer_offsets:
        data[off:off+4] = TIMER_NEW
        total_patches += 1
        print(f"      0x{off:05X}: 20 BF 02 00 -> FF FF FF FF  [OK]")

    print(f"      {len(timer_offsets)} timer(s) patche(s)")

    # ================================================================
    # PATCH 3: BEQ -> B inconditionnel (sauter le timer check)
    # ================================================================
    print("\n[3/4] Patch branches conditionnelles (BEQ -> B)")

    # Pattern: eor r3,r3,#1 / uxtb r3,r3 / cmp r3,#0 / beq / bl millis()
    BEQ_PATTERN = bytes([0x83, 0xF0, 0x01, 0x03, 0xDB, 0xB2, 0x00, 0x2B])
    beq_matches = find_all(data, BEQ_PATTERN)

    beq_count = 0
    for pos in beq_matches:
        beq_offset = pos + 8
        if beq_offset + 2 > len(data) or data[beq_offset + 1] != 0xD0:
            continue
        # Verifier que le BL apres le BEQ pointe vers millis()
        bl_offset = beq_offset + 2
        bl_target = decode_bl_target(data, bl_offset)
        if bl_target != MILLIS_ADDR:
            continue
        data[beq_offset + 1] = 0xE0
        beq_count += 1
        total_patches += 1
        print(f"      0x{beq_offset:05X}: {data[beq_offset]:02X} D0 -> {data[beq_offset]:02X} E0  [OK]")

    print(f"      {beq_count} branche(s) patchee(s)")

    # ================================================================
    # PATCH 4: Bypass de la verification de cle dans les rendus
    # ================================================================
    print("\n[4/4] Patch verification de cle dans les fonctions de rendu")

    # Pattern dans chaque fonction de rendu:
    #   bl #memcmp_or_similar  -> resultat dans r0
    #   mov r3, r0             -> 03 46
    #   cmp r3, #0             -> 00 2B
    #   beq #not_matched       -> xx D0  <-- on change en NOP (00 BF)
    # Suivi du code "matched": ldr r0, ... / bl cleanup / ldr r3, ... / movs r2, #0

    # Chercher le pattern specifique:
    # 03 46   mov r3, r0
    # 00 2B   cmp r3, #0
    # xx D0   beq (jump to not-matched)
    # xx 48   ldr r0, [pc, #xx]  (charge adresse pour cleanup)
    # F8 F7   bl prefix (appel a 0x80525c4 = cleanup/erase)
    KEY_PATTERN = bytes([0x03, 0x46, 0x00, 0x2B])

    key_patches = 0
    for pos in find_all(data, KEY_PATTERN):
        # Verifier que c'est suivi d'un BEQ
        beq_pos = pos + 4
        if beq_pos + 2 > len(data):
            continue
        if data[beq_pos + 1] != 0xD0:
            continue

        # Verifier que c'est suivi d'un ldr r0, [pc, #imm] (48xx)
        after_beq = pos + 6
        if after_beq + 2 > len(data):
            continue
        hw_after = struct.unpack("<H", data[after_beq:after_beq+2])[0]
        if (hw_after & 0xF800) != 0x4800:
            continue

        # Verifier que le bl pointe vers 0x80525c4 (cleanup function)
        bl_pos = after_beq + 2
        if bl_pos + 4 > len(data):
            continue
        dest = decode_bl_target(data, bl_pos)
        if dest is not None and dest == CLEANUP_ADDR:
            # C'est bien le pattern de verification de cle!
            # Changer le BEQ en NOP pour toujours passer par "cle valide"
            old_beq = data[beq_pos:beq_pos+2]
            data[beq_pos:beq_pos+2] = bytes([0x00, 0xBF])  # NOP
            key_patches += 1
            total_patches += 1
            print(f"      0x{beq_pos:05X}: {old_beq[0]:02X} D0 -> 00 BF (NOP)  [OK]")

    print(f"      {key_patches} verification(s) de cle patchee(s)")

    # ================================================================
    # RESUME
    # ================================================================
    diff_bytes = sum(1 for a, b in zip(original, data) if a != b)

    print("\n" + "=" * 60)
    print(f" RESUME")
    print("=" * 60)
    print(f"  Patches appliques : {total_patches}")
    print(f"  Octets modifies   : {diff_bytes}")
    print(f"  Taille fichier    : {len(data)} bytes (inchangee)")
    print()
    print(f"  [1] Validation HW : toujours 'N' (active)")
    print(f"  [2] Timer x{len(timer_offsets):2d}     : 3 min -> 49.7 jours")
    print(f"  [3] Branch x{beq_count:2d}    : timer check toujours saute")
    print(f"  [4] Key check x{key_patches:2d} : verification .key bypassee")

    with open(OUTPUT, "wb") as f:
        f.write(data)

    print(f"\n[OK] Firmware cracke -> {OUTPUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
