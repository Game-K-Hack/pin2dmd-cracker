"""
Patch 3 - Forcer la validation de cle
Patch la fonction de validation 0x08052714 pour toujours retourner 'N' (0x4E = active).

Methode: modifier le "default case" de la fonction switch pour retourner 0x4E
au lieu de 0 (non active).
"""
import sys

INPUT = "PIN2DMD.bin"
OUTPUT = "PIN2DMD_patch_keygen.bin"

# La fonction a 0x08052714 (offset fichier 0x52714):
#   ...
#   0x0805272a: b #0x8052734       -> 03 E0 (saute au default case)
#   0x0805272c: movs r3, #0x4e     -> 4E 23 (return 'N' = activated)
#   0x0805272e: b #0x8052736       -> 02 E0
#   0x08052730: movs r3, #0x45     -> 45 23 (return 'E' = activated)
#   0x08052732: b #0x8052736       -> 00 E0
#   0x08052734: movs r3, #0        -> 00 23 (return 0 = NOT activated) <-- CIBLE
#   0x08052736: mov r0, r3
#   ...

PATCH_OFFSET = 0x52734
PATCH_OLD = bytes([0x00, 0x23])  # movs r3, #0
PATCH_NEW = bytes([0x4E, 0x23])  # movs r3, #0x4E ('N')


def main():
    with open(INPUT, "rb") as f:
        data = bytearray(f.read())

    original = bytes(data)

    # Verifier l'etat actuel
    current = bytes(data[PATCH_OFFSET:PATCH_OFFSET+2])
    print(f"[*] Offset 0x{PATCH_OFFSET:05X}: {current[0]:02X} {current[1]:02X}", end="")

    if current == PATCH_OLD:
        print(" -> movs r3, #0 (non active) [ATTENDU]")
    elif current == PATCH_NEW:
        print(" -> movs r3, #0x4E (deja patche!)")
        return 0
    else:
        print(f" -> INATTENDU! Abandon.")
        return 1

    # Verifier le contexte (instructions autour)
    context_before = data[PATCH_OFFSET-2:PATCH_OFFSET]
    context_after = data[PATCH_OFFSET+2:PATCH_OFFSET+4]

    ok = True
    if context_before != bytes([0x00, 0xE0]):  # b #0x8052736 (ou similaire)
        print(f"[!] Contexte avant inattendu: {context_before.hex()}")
        ok = False
    if context_after != bytes([0x18, 0x46]):  # mov r0, r3
        print(f"[!] Contexte apres inattendu: {context_after.hex()}")
        ok = False

    if not ok:
        print("[!] Le contexte ne correspond pas, le binaire a peut-etre change")
        print("    Patch applique quand meme (verifier manuellement)")

    # Appliquer le patch
    data[PATCH_OFFSET:PATCH_OFFSET+2] = PATCH_NEW

    # Verification
    if data[PATCH_OFFSET:PATCH_OFFSET+2] != PATCH_NEW:
        print("[ERREUR] Patch non applique")
        return 1

    diff_bytes = sum(1 for a, b in zip(original, data) if a != b)
    print(f"\n[*] Octets modifies: {diff_bytes}")
    print(f"[*] Effet: la detection hardware retourne toujours 'N' (active)")
    print(f"[!] ATTENTION: Ce patch seul ne suffit PAS!")
    print(f"    Les 17 fonctions de rendu verifient aussi le fichier .key")
    print(f"    Combiner avec patch_timer.py ou patch_branch.py")

    with open(OUTPUT, "wb") as f:
        f.write(data)

    print(f"\n[OK] Patch applique -> {OUTPUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
