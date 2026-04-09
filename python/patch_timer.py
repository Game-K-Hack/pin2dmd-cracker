"""
Patch 1 - Timer Extension
Remplace le seuil de 180000ms (3 min) par 0xFFFFFFFF (49.7 jours)
dans les 17 fonctions de rendu.

Methode: simple recherche/remplacement binaire.
"""
import struct
import sys

INPUT = "PIN2DMD.bin"
OUTPUT = "PIN2DMD_patch_timer.bin"

TIMER_OLD = struct.pack("<I", 180000)   # 20 BF 02 00
TIMER_NEW = struct.pack("<I", 0xFFFFFFFF)  # FF FF FF FF

# Offsets attendus (vérification)
EXPECTED_OFFSETS = [
    0x55204, 0x558A0, 0x55D78, 0x56238, 0x566F4, 0x56BCC, 0x57088,
    0x57544, 0x57A1C, 0x57ED8, 0x58398, 0x58858, 0x58D18, 0x591D8,
    0x5969C, 0x59A04, 0x59D04,
]

def main():
    with open(INPUT, "rb") as f:
        data = bytearray(f.read())

    original = bytes(data)

    # Trouver toutes les occurrences
    offsets = []
    idx = 0
    while True:
        pos = data.find(TIMER_OLD, idx)
        if pos == -1:
            break
        offsets.append(pos)
        idx = pos + 1

    print(f"[*] Occurrences de 180000ms trouvees: {len(offsets)}")
    for off in offsets:
        expected = "OK" if off in EXPECTED_OFFSETS else "INATTENDU"
        print(f"    0x{off:05X} [{expected}]")

    if len(offsets) != len(EXPECTED_OFFSETS):
        print(f"[!] Attendu {len(EXPECTED_OFFSETS)}, trouve {len(offsets)}")

    # Appliquer le patch
    count = 0
    for off in offsets:
        data[off:off+4] = TIMER_NEW
        count += 1

    # Verification
    verify_ok = True
    for off in offsets:
        if data[off:off+4] != TIMER_NEW:
            print(f"[ERREUR] Patch non applique a 0x{off:05X}")
            verify_ok = False

    remaining = bytes(data).count(TIMER_OLD)
    if remaining > 0:
        print(f"[!] Il reste {remaining} occurrence(s) non patchee(s)")
        verify_ok = False

    # Stats de diff
    diff_bytes = sum(1 for a, b in zip(original, data) if a != b)
    print(f"\n[*] Octets modifies: {diff_bytes} (attendu: {count * 4} = {count}x4)")

    with open(OUTPUT, "wb") as f:
        f.write(data)

    if verify_ok:
        print(f"[OK] Patch applique avec succes -> {OUTPUT}")
        print(f"     Timer: 3 minutes -> ~49.7 jours")
    else:
        print(f"[!] Patch applique avec avertissements -> {OUTPUT}")

    return 0 if verify_ok else 1

if __name__ == "__main__":
    sys.exit(main())
