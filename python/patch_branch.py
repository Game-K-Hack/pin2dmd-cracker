"""
Patch 2 - Saut conditionnel -> inconditionnel (timer check uniquement)
Change BEQ (D0xx) en B (E0xx) pour sauter le timer check
dans chaque fonction de rendu.

Methode: on cible UNIQUEMENT les BEQ qui precedent un appel a millis() (0x8021430)
suivi d'une comparaison avec le seuil timer. Le pattern etendu est:

  83 F0 01 03  -> eor r3, r3, #1
  DB B2        -> uxtb r3, r3
  00 2B        -> cmp r3, #0
  xx D0        -> beq #target  <-- on change D0 en E0
  xx F0 xx F8  -> bl millis()  (0x08021430)
"""
import struct
import sys

INPUT = "PIN2DMD.bin"
OUTPUT = "PIN2DMD_patch_branch.bin"

# Pattern etendu: eor + uxtb + cmp + beq, suivi de bl (F0xx F8xx)
PATTERN_PREFIX = bytes([0x83, 0xF0, 0x01, 0x03, 0xDB, 0xB2, 0x00, 0x2B])

BASE = 0x08000000
MILLIS_ADDR = 0x08021430


def decode_bl_target(data, offset):
    """Decode la destination d'une instruction BL Thumb-2 a l'offset donne."""
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

    # Trouver les occurrences du pattern qui sont VRAIMENT liees au timer
    patches = []
    idx = 0
    while True:
        pos = data.find(PATTERN_PREFIX, idx)
        if pos == -1:
            break

        beq_offset = pos + 8  # offset du BEQ (2 bytes: imm8, D0)
        if pos + 10 <= len(data) and data[beq_offset + 1] == 0xD0:
            # Verifier que l'instruction APRES le BEQ est un BL vers millis()
            bl_offset = beq_offset + 2  # le BL est juste apres le BEQ
            bl_target = decode_bl_target(data, bl_offset)

            if bl_target == MILLIS_ADDR:
                patches.append({
                    "pattern_offset": pos,
                    "beq_offset": beq_offset,
                    "branch_byte": data[beq_offset],
                })

        idx = pos + 1

    print(f"[*] Branches BEQ timer trouvees: {len(patches)}")
    for p in patches:
        old = f"{p['branch_byte']:02X} D0"
        new = f"{p['branch_byte']:02X} E0"
        print(f"    0x{p['beq_offset']:05X}: {old} -> {new}")

    # Appliquer les patches
    for p in patches:
        data[p["beq_offset"] + 1] = 0xE0  # D0 -> E0

    # Verification
    verify_ok = True
    for p in patches:
        if data[p["beq_offset"] + 1] != 0xE0:
            print(f"[ERREUR] Patch echoue a 0x{p['beq_offset']:05X}")
            verify_ok = False

    # Stats
    diff_bytes = sum(1 for a, b in zip(original, data) if a != b)
    print(f"\n[*] Octets modifies: {diff_bytes} (attendu: {len(patches)})")
    print(f"[*] Chaque BEQ (conditionnel) -> B (inconditionnel)")
    print(f"    Le timer check est toujours saute, meme si non active")

    with open(OUTPUT, "wb") as f:
        f.write(data)

    if verify_ok and len(patches) > 0:
        print(f"\n[OK] Patch applique avec succes -> {OUTPUT}")
    else:
        print(f"\n[!] Patch applique avec avertissements -> {OUTPUT}")

    return 0 if verify_ok else 1


if __name__ == "__main__":
    sys.exit(main())
