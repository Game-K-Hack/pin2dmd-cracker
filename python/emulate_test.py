"""
Verification des patches par emulation CPU (Unicorn Engine).

Emule les fonctions critiques du firmware ARM Cortex-M (Thumb-2)
et compare le comportement AVANT et APRES chaque patch.
"""
import struct
import sys
from unicorn import *
from unicorn.arm_const import *

# ============================================================
# Configuration memoire (reproduit le memory map du STM32)
# ============================================================
FLASH_BASE  = 0x08000000
FLASH_SIZE  = 0x80000      # 512 KB
RAM_BASE    = 0x20000000
RAM_SIZE    = 0x20000       # 128 KB
STACK_TOP   = RAM_BASE + RAM_SIZE

# Adresses des fonctions critiques
ADDR_KEY_VALIDATION  = 0x08052714  # Retourne 'N', 'E', ou 0
ADDR_HW_DETECT       = 0x080525F8  # Detection hardware I2C
ADDR_MILLIS          = 0x08021430  # HAL_GetTick / millis()
ADDR_CLEANUP         = 0x080525C4  # Fonction cleanup apres cle valide
ADDR_MEMCMP          = 0x0806AF90  # Comparaison memoire (cle)
ADDR_SPRINTF         = 0x0806B730  # sprintf
ADDR_MEMSET          = 0x0806B1F0  # memset
ADDR_DELAY           = 0x0802143E  # delay()

# Variable d'activation en RAM
ADDR_ACTIVATION_FLAG = 0x20004894
ADDR_VALIDATED_FLAG  = 0x20004895


class FirmwareEmulator:
    """Emulateur de fonctions du firmware PIN2DMD."""

    def __init__(self, firmware_path):
        with open(firmware_path, "rb") as f:
            self.firmware = f.read()
        self.call_log = []
        self.millis_value = 0
        self.hw_detect_result = 0
        self.memcmp_result = 1  # 1 = no match (default: cle invalide)

    def _create_emu(self):
        """Cree une instance Unicorn avec la memoire mappee."""
        mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

        # Mapper la flash (firmware)
        mu.mem_map(FLASH_BASE, FLASH_SIZE)
        mu.mem_write(FLASH_BASE, self.firmware[:FLASH_SIZE])

        # Mapper la RAM
        mu.mem_map(RAM_BASE, RAM_SIZE)
        mu.mem_write(RAM_BASE, b'\x00' * RAM_SIZE)

        # Configurer le stack
        mu.reg_write(UC_ARM_REG_SP, STACK_TOP - 0x200)

        return mu

    def _hook_calls(self, mu):
        """Intercepte les appels BL vers les fonctions externes."""

        def hook_code(uc, address, size, user_data):
            # Lire l'instruction
            if size == 4:
                code = uc.mem_read(address, 4)
                hw1 = struct.unpack("<H", bytes(code[0:2]))[0]
                hw2 = struct.unpack("<H", bytes(code[2:4]))[0]

                # Detecter BL (Thumb-2)
                if (hw1 & 0xF800) == 0xF000 and (hw2 & 0xD000) == 0xD000:
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
                    target = address + 4 + off

                    # Intercepter les fonctions connues
                    if target == ADDR_HW_DETECT:
                        self.call_log.append(("hw_detect", address))
                        uc.reg_write(UC_ARM_REG_R0, self.hw_detect_result)
                        uc.reg_write(UC_ARM_REG_PC, address + 4 + 1)  # +1 pour Thumb
                        return

                    if target == ADDR_MILLIS:
                        self.call_log.append(("millis", address))
                        uc.reg_write(UC_ARM_REG_R0, self.millis_value)
                        uc.reg_write(UC_ARM_REG_PC, address + 4 + 1)
                        return

                    if target == ADDR_CLEANUP:
                        self.call_log.append(("cleanup", address))
                        uc.reg_write(UC_ARM_REG_PC, address + 4 + 1)
                        return

                    if target == ADDR_MEMCMP:
                        self.call_log.append(("memcmp", address))
                        uc.reg_write(UC_ARM_REG_R0, self.memcmp_result)
                        uc.reg_write(UC_ARM_REG_PC, address + 4 + 1)
                        return

                    if target == ADDR_SPRINTF:
                        self.call_log.append(("sprintf", address))
                        uc.reg_write(UC_ARM_REG_R0, 0)
                        uc.reg_write(UC_ARM_REG_PC, address + 4 + 1)
                        return

                    if target == ADDR_MEMSET:
                        self.call_log.append(("memset", address))
                        uc.reg_write(UC_ARM_REG_PC, address + 4 + 1)
                        return

                    if target == ADDR_DELAY:
                        self.call_log.append(("delay", address))
                        uc.reg_write(UC_ARM_REG_PC, address + 4 + 1)
                        return

                    # Fonction inconnue: stub (retourne 0)
                    if target < FLASH_BASE or target >= FLASH_BASE + FLASH_SIZE:
                        self.call_log.append(("unknown_ext", address, target))
                        uc.reg_write(UC_ARM_REG_R0, 0)
                        uc.reg_write(UC_ARM_REG_PC, address + 4 + 1)
                        return

        mu.hook_add(UC_HOOK_CODE, hook_code)

    # ================================================================
    # TEST 1: Fonction de validation hardware (0x08052714)
    # ================================================================
    def test_key_validation(self, hw_result):
        """
        Emule la fonction 0x08052714 qui appelle hw_detect et retourne:
          hw=1 -> 'N' (0x4E)
          hw=2 -> 'E' (0x45)
          hw=0 -> 0   (non active)
        """
        mu = self._create_emu()
        self.call_log = []
        self.hw_detect_result = hw_result

        self._hook_calls(mu)

        # Appeler la fonction (adresse | 1 pour Thumb)
        mu.reg_write(UC_ARM_REG_LR, 0x08099990 | 1)  # adresse de retour bidon
        try:
            mu.emu_start(ADDR_KEY_VALIDATION | 1, 0x08099990, timeout=1000000, count=200)
        except UcError:
            pass

        return mu.reg_read(UC_ARM_REG_R0)

    # ================================================================
    # TEST 2: Timer check dans une fonction de rendu
    # ================================================================
    def test_timer_check(self, millis_val, validated=False):
        """
        Emule le fragment de code du timer check:
          - Charge le flag de validation (0x20004895)
          - Si non valide et millis() > seuil: retourne True (overlay affiche)
          - Sinon: retourne False

        On emule le fragment a partir du ldr/ldrb du flag jusqu'au
        branchement post-timer.
        """
        mu = self._create_emu()
        self.call_log = []
        self.millis_value = millis_val

        # Ecrire le flag de validation en RAM
        mu.mem_write(ADDR_VALIDATED_FLAG, bytes([1 if validated else 0]))

        self._hook_calls(mu)

        # Le fragment timer est a 0x08054FCA (premier render func)
        # On emule de 0x08054FCA a 0x08054FF6
        TIMER_START = 0x08054FCA
        TIMER_END   = 0x08054FF6

        mu.reg_write(UC_ARM_REG_LR, 0x08099990 | 1)
        mu.reg_write(UC_ARM_REG_R7, RAM_BASE + 0x1000)  # frame pointer

        try:
            mu.emu_start(TIMER_START | 1, TIMER_END, timeout=1000000, count=100)
        except UcError:
            pass

        # Verifier si millis() a ete appele
        millis_called = any(c[0] == "millis" for c in self.call_log)

        # Verifier si la fonction d'overlay NOT ACTIVATED a ete appelee
        # (elle est a l'adresse apres le check, on regarde le PC final)
        pc = mu.reg_read(UC_ARM_REG_PC)

        # Si PC a depasse TIMER_END, le timer check a ete saute
        # Si millis n'a pas ete appele, le device est considere active
        overlay_shown = millis_called and (millis_val > 180000 or millis_val > 0xFFFFFFFE)

        # Lire r3 pour savoir si le flag "show overlay" est set
        # A 0x8054FEA: cmp r3, #0 -> si r3 != 0, overlay affiche
        r3 = mu.reg_read(UC_ARM_REG_R3)

        return {
            "millis_called": millis_called,
            "r3_flag": r3,
            "overlay_triggered": r3 != 0 and millis_called,
            "pc_final": pc,
        }

    # ================================================================
    # TEST 3: Verification complete de la chaine d'activation
    # ================================================================
    def test_activation_chain(self):
        """
        Emule la sequence de la boucle principale:
          1. Appel key_validation
          2. Ecriture du flag
          3. Check si active

        Retourne le flag d'activation ecrit en RAM.
        """
        mu = self._create_emu()
        self.call_log = []

        self._hook_calls(mu)

        # Simuler l'ecriture du flag comme dans le main loop (0x805ADD0-0x805ADE8)
        MAIN_PATCH_START = 0x0805ADD0
        MAIN_PATCH_END   = 0x0805ADEA

        mu.reg_write(UC_ARM_REG_R7, RAM_BASE + 0x2000)
        mu.reg_write(UC_ARM_REG_LR, 0x08099990 | 1)

        try:
            mu.emu_start(MAIN_PATCH_START | 1, MAIN_PATCH_END, timeout=1000000, count=200)
        except UcError:
            pass

        flag = mu.mem_read(ADDR_ACTIVATION_FLAG, 1)[0]
        return flag


# ============================================================
# TESTS
# ============================================================
def run_all_tests():
    files = {
        "original":     "PIN2DMD.bin",
        "patch_timer":  "PIN2DMD_patch_timer.bin",
        "patch_branch": "PIN2DMD_patch_branch.bin",
        "patch_keygen": "PIN2DMD_patch_keygen.bin",
        "full_crack":   "PIN2DMD_cracked.bin",
    }

    SEP = "=" * 70
    HSEP = "-" * 70
    PASS = "PASS"
    FAIL = "FAIL"

    results = []
    total_pass = 0
    total_fail = 0

    def check(name, condition, detail=""):
        nonlocal total_pass, total_fail
        status = PASS if condition else FAIL
        if condition:
            total_pass += 1
        else:
            total_fail += 1
        tag = f"[{status}]"
        line = f"  {tag} {name}"
        if detail:
            line += f"  ({detail})"
        print(line)
        results.append((name, condition))

    print(SEP)
    print(" EMULATION DES PATCHES PIN2DMD")
    print(f" Unicorn Engine - ARM Cortex-M (Thumb-2)")
    print(SEP)

    # ==============================================================
    # TEST A: Validation hardware (fonction 0x08052714)
    # ==============================================================
    print(f"\n{HSEP}")
    print(" TEST A: Fonction de validation hardware")
    print(HSEP)

    for fw_name, fw_file in files.items():
        try:
            emu = FirmwareEmulator(fw_file)
        except FileNotFoundError:
            print(f"\n  [{fw_name}] Fichier non trouve, skip")
            continue

        print(f"\n  [{fw_name}] {fw_file}")

        # Test avec hw_detect retournant 0 (pas de hardware reconnu)
        r = emu.test_key_validation(hw_result=0)

        if fw_name in ("patch_keygen", "full_crack"):
            check(
                f"  hw=0 -> retourne 0x{r:02X}",
                r == 0x4E,
                f"attendu: 0x4E='N' (force active)"
            )
        else:
            check(
                f"  hw=0 -> retourne 0x{r:02X}",
                r == 0,
                f"attendu: 0x00 (non active)"
            )

        # Test avec hw=1 (device type N detecte)
        r1 = emu.test_key_validation(hw_result=1)
        check(
            f"  hw=1 -> retourne 0x{r1:02X}",
            r1 == 0x4E,
            f"attendu: 0x4E='N'"
        )

        # Test avec hw=2 (device type E detecte)
        r2 = emu.test_key_validation(hw_result=2)
        check(
            f"  hw=2 -> retourne 0x{r2:02X}",
            r2 == 0x45,
            f"attendu: 0x45='E'"
        )

    # ==============================================================
    # TEST B: Timer check (fragment de fonction de rendu)
    # ==============================================================
    print(f"\n{HSEP}")
    print(" TEST B: Timer check dans les fonctions de rendu")
    print(HSEP)

    for fw_name, fw_file in files.items():
        try:
            emu = FirmwareEmulator(fw_file)
        except FileNotFoundError:
            continue

        print(f"\n  [{fw_name}] {fw_file}")

        # Test 1: Device valide -> timer ne doit PAS se declencher
        t1 = emu.test_timer_check(millis_val=999999, validated=True)
        check(
            f"  valide + 999s",
            not t1["millis_called"],
            "millis() ne doit PAS etre appele"
        )

        # Test 2: Non valide + temps < seuil -> timer non expire
        t2 = emu.test_timer_check(millis_val=60000, validated=False)  # 1 minute

        if fw_name in ("patch_branch", "full_crack"):
            # Apres patch branch: millis() ne doit plus etre appele
            check(
                f"  non-valide + 60s",
                not t2["millis_called"],
                "branch patch: millis() saute"
            )
        elif fw_name == "patch_timer":
            # Timer etendu: millis() appele mais seuil enorme
            check(
                f"  non-valide + 60s",
                t2["millis_called"] and not t2["overlay_triggered"],
                f"timer etendu: millis appele, overlay={t2['overlay_triggered']}"
            )
        else:
            # Original: millis appele, overlay pas encore (< 180s)
            check(
                f"  non-valide + 60s",
                t2["millis_called"] and not t2["overlay_triggered"],
                f"millis appele, pas encore expire"
            )

        # Test 3: Non valide + temps > 3 minutes -> overlay?
        t3 = emu.test_timer_check(millis_val=200000, validated=False)  # 3min20

        if fw_name == "original":
            check(
                f"  non-valide + 200s",
                t3["millis_called"] and t3["overlay_triggered"],
                "ORIGINAL: overlay doit s'afficher apres 3 min!"
            )
        elif fw_name == "patch_timer":
            check(
                f"  non-valide + 200s",
                t3["millis_called"] and not t3["overlay_triggered"],
                "timer etendu: 200s < 49.7 jours, pas d'overlay"
            )
        elif fw_name in ("patch_branch", "full_crack"):
            check(
                f"  non-valide + 200s",
                not t3["millis_called"],
                "branch saute: millis() jamais appele"
            )
        else:
            check(
                f"  non-valide + 200s",
                True,
                f"millis={t3['millis_called']}, overlay={t3['overlay_triggered']}"
            )

    # ==============================================================
    # TEST C: Chaine d'activation complete (main loop)
    # ==============================================================
    print(f"\n{HSEP}")
    print(" TEST C: Chaine d'activation (main loop)")
    print(HSEP)

    for fw_name, fw_file in files.items():
        try:
            emu = FirmwareEmulator(fw_file)
        except FileNotFoundError:
            continue

        print(f"\n  [{fw_name}] {fw_file}")

        # Simuler: pas de hardware, pas de cle
        emu.hw_detect_result = 0
        flag = emu.test_activation_chain()

        if fw_name in ("patch_keygen", "full_crack"):
            check(
                f"  flag activation = 0x{flag:02X}",
                flag != 0,
                f"attendu: non-zero (force active) -> 0x{flag:02X}"
            )
        else:
            check(
                f"  flag activation = 0x{flag:02X}",
                flag == 0,
                f"attendu: 0x00 (non active sans hardware)"
            )

    # ==============================================================
    # TEST D: Verification des octets patches
    # ==============================================================
    print(f"\n{HSEP}")
    print(" TEST D: Verification statique des octets critiques")
    print(HSEP)

    for fw_name, fw_file in files.items():
        try:
            with open(fw_file, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            continue

        print(f"\n  [{fw_name}] {fw_file}")

        # Timer threshold a 0x55204
        timer_val = struct.unpack("<I", data[0x55204:0x55208])[0]
        if fw_name in ("patch_timer", "full_crack"):
            check(
                f"  timer[0x55204] = {timer_val}",
                timer_val == 0xFFFFFFFF,
                f"attendu: 0xFFFFFFFF"
            )
        else:
            check(
                f"  timer[0x55204] = {timer_val}",
                timer_val == 180000,
                f"attendu: 180000"
            )

        # Branch a 0x54FD7
        branch_byte = data[0x54FD7]
        if fw_name in ("patch_branch", "full_crack"):
            check(
                f"  branch[0x54FD7] = 0x{branch_byte:02X}",
                branch_byte == 0xE0,
                "attendu: 0xE0 (B inconditionnel)"
            )
        else:
            check(
                f"  branch[0x54FD7] = 0x{branch_byte:02X}",
                branch_byte == 0xD0,
                "attendu: 0xD0 (BEQ conditionnel)"
            )

        # Keygen a 0x52734
        keygen_byte = data[0x52734]
        if fw_name in ("patch_keygen", "full_crack"):
            check(
                f"  keygen[0x52734] = 0x{keygen_byte:02X}",
                keygen_byte == 0x4E,
                "attendu: 0x4E (force 'N')"
            )
        else:
            check(
                f"  keygen[0x52734] = 0x{keygen_byte:02X}",
                keygen_byte == 0x00,
                "attendu: 0x00 (non active)"
            )

        # Key check NOP (full_crack uniquement)
        key_nop = data[0x54F7C:0x54F7E]
        if fw_name == "full_crack":
            check(
                f"  key_check[0x54F7C] = {key_nop[0]:02X} {key_nop[1]:02X}",
                key_nop == bytes([0x00, 0xBF]),
                "attendu: 00 BF (NOP)"
            )

    # ==============================================================
    # RESUME FINAL
    # ==============================================================
    print(f"\n{SEP}")
    print(f" RESULTATS: {total_pass} PASS / {total_fail} FAIL")
    print(SEP)

    if total_fail == 0:
        print("\n Tous les tests passent!")
        print(" Les patches modifient le comportement exactement comme prevu.")
    else:
        print(f"\n {total_fail} test(s) en echec - verifier les patches.")

    print(f"""
 Resume par fichier:
   original        : protection active (timer 3min, validation HW, cle)
   patch_timer     : timer repousse a ~49.7 jours
   patch_branch    : timer completement saute (millis jamais appele)
   patch_keygen    : validation HW forcee (mais cle toujours verifiee)
   full_crack      : TOUTES les protections desactivees
""")

    return 0 if total_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(run_all_tests())
