"""
Outil de verification - Compare l'original avec les fichiers patches.
Affiche un rapport detaille de chaque modification.
"""
import struct
import sys
import os

ORIGINAL = "PIN2DMD.bin"
PATCHED_FILES = [
    ("PIN2DMD_patch_timer.bin", "Timer extend"),
    ("PIN2DMD_patch_branch.bin", "Branch bypass"),
    ("PIN2DMD_patch_keygen.bin", "Keygen force"),
    ("PIN2DMD_cracked.bin", "Full crack"),
]

# Regions connues et leur signification
KNOWN_REGIONS = {
    0x52734: "Validation HW: movs r3, #imm (retour activation)",
    0x55204: "Timer #1  (render func)",
    0x558A0: "Timer #2  (render func)",
    0x55D78: "Timer #3  (render func)",
    0x56238: "Timer #4  (render func)",
    0x566F4: "Timer #5  (render func)",
    0x56BCC: "Timer #6  (render func)",
    0x57088: "Timer #7  (render func)",
    0x57544: "Timer #8  (render func)",
    0x57A1C: "Timer #9  (render func)",
    0x57ED8: "Timer #10 (render func)",
    0x58398: "Timer #11 (render func)",
    0x58858: "Timer #12 (render func)",
    0x58D18: "Timer #13 (render func)",
    0x591D8: "Timer #14 (render func)",
    0x5969C: "Timer #15 (render func)",
    0x59A04: "Timer #16 (render func)",
    0x59D04: "Timer #17 (render func)",
}


def describe_offset(offset, diff_offsets):
    """Trouve la region connue la plus proche."""
    for region_start, desc in sorted(KNOWN_REGIONS.items()):
        if region_start <= offset < region_start + 4:
            return desc
    # Chercher dans les patterns BEQ
    for off in diff_offsets:
        pass
    return ""


def main():
    if not os.path.exists(ORIGINAL):
        print(f"[ERREUR] Fichier original introuvable: {ORIGINAL}")
        return 1

    with open(ORIGINAL, "rb") as f:
        orig = f.read()

    print("=" * 70)
    print(" VERIFICATION DES PATCHES PIN2DMD")
    print("=" * 70)
    print(f" Original: {ORIGINAL} ({len(orig)} bytes)")
    print()

    for filename, description in PATCHED_FILES:
        if not os.path.exists(filename):
            print(f"  [{description:15s}] {filename} - NON TROUVE (pas encore genere)")
            print()
            continue

        with open(filename, "rb") as f:
            patched = f.read()

        print(f"  [{description:15s}] {filename}")

        if len(orig) != len(patched):
            print(f"    [ERREUR] Taille differente: {len(orig)} vs {len(patched)}")
            print()
            continue

        # Trouver les differences
        diffs = []
        for i in range(len(orig)):
            if orig[i] != patched[i]:
                diffs.append(i)

        if not diffs:
            print(f"    [!] Aucune difference trouvee!")
            print()
            continue

        # Grouper les diffs consecutives
        groups = []
        group_start = diffs[0]
        group_end = diffs[0]
        for off in diffs[1:]:
            if off == group_end + 1:
                group_end = off
            else:
                groups.append((group_start, group_end))
                group_start = off
                group_end = off
        groups.append((group_start, group_end))

        print(f"    Octets modifies: {len(diffs)}")
        print(f"    Zones touchees:  {len(groups)}")
        print()

        for g_start, g_end in groups:
            size = g_end - g_start + 1
            old_bytes = orig[g_start:g_end+1]
            new_bytes = patched[g_start:g_end+1]
            desc = describe_offset(g_start, diffs)

            old_hex = " ".join(f"{b:02X}" for b in old_bytes)
            new_hex = " ".join(f"{b:02X}" for b in new_bytes)

            if desc:
                print(f"    0x{g_start:05X} ({size}B): {old_hex} -> {new_hex}  | {desc}")
            else:
                print(f"    0x{g_start:05X} ({size}B): {old_hex} -> {new_hex}")

        # Verifications specifiques
        print()
        checks = []

        # Check timer
        timer_val = struct.pack("<I", 180000)
        timer_max = struct.pack("<I", 0xFFFFFFFF)
        timer_orig_count = orig.count(timer_val)
        timer_patched_count = patched.count(timer_val)
        timer_max_count = patched.count(timer_max)
        if timer_patched_count < timer_orig_count:
            checks.append(f"Timers: {timer_orig_count - timer_patched_count}/{timer_orig_count} remplaces par 0xFFFFFFFF")

        # Check BEQ -> B
        beq_pattern = bytes([0x83, 0xF0, 0x01, 0x03, 0xDB, 0xB2, 0x00, 0x2B])
        beq_orig = 0
        beq_patched = 0
        for off in range(len(orig) - 10):
            if orig[off:off+8] == beq_pattern:
                if orig[off+9] == 0xD0:
                    beq_orig += 1
                if patched[off+9] == 0xE0:
                    beq_patched += 1
        if beq_patched > 0:
            checks.append(f"Branches: {beq_patched} BEQ -> B inconditionnels")

        # Check keygen
        if patched[0x52734] == 0x4E and orig[0x52734] == 0x00:
            checks.append("Validation HW: forcee a 'N' (active)")

        # Check NOP (key bypass)
        nop_count = 0
        for off in diffs:
            if patched[off:off+2] == bytes([0x00, 0xBF]):
                if orig[off+1] == 0xD0:  # etait un BEQ
                    nop_count += 1
        if nop_count > 0:
            checks.append(f"Key checks: {nop_count} BEQ -> NOP (bypass cle)")

        if checks:
            print("    Resultats:")
            for c in checks:
                print(f"      [v] {c}")
        print()

    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
