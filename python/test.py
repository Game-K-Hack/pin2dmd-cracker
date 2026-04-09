"""
Test d'emulation PIN2DMD - Verifie si "NOT ACTIVATED" apparait.

Usage:
    python test.py PIN2DMD.bin
    python test.py PIN2DMD_cracked.bin
    python test.py PIN2DMD_patch_timer.bin
"""
import struct
import sys
import os
from unicorn import *
from unicorn.arm_const import *

# Memory map STM32
FLASH_BASE = 0x08000000
FLASH_SIZE = 0x80000
RAM_BASE   = 0x20000000
RAM_SIZE   = 0x20000
STACK_TOP  = RAM_BASE + RAM_SIZE

# Adresses connues
ADDR_MILLIS      = 0x08021430
ADDR_CLEANUP     = 0x080525C4
ADDR_HW_DETECT   = 0x080525F8
ADDR_KEY_VALID   = 0x08052714
ADDR_MEMCMP      = 0x0806AF90
ADDR_SPRINTF     = 0x0806B730
ADDR_MEMSET      = 0x0806B1F0
ADDR_DELAY       = 0x0802143E
ADDR_OVERLAY_FN  = 0x08059E7C

# RAM
ADDR_FLAG        = 0x20004894
ADDR_VALIDATED   = 0x20004895

# Timer check: debut et fin du fragment dans la 1ere fonction de rendu
TIMER_CHECK_START = 0x08054FCA
TIMER_CHECK_END   = 0x08054FF6

# Adresse de retour bidon
RETURN_ADDR = 0x08099990


def decode_bl_target(data, offset):
    """Decode BL Thumb-2 target."""
    hw1 = struct.unpack("<H", data[offset:offset+2])[0]
    hw2 = struct.unpack("<H", data[offset+2:offset+4])[0]
    if (hw1 & 0xF800) != 0xF000 or (hw2 & 0xD000) != 0xD000:
        return None
    s = (hw1 >> 10) & 1
    j1 = (hw2 >> 13) & 1
    j2 = (hw2 >> 11) & 1
    i1 = ~(j1 ^ s) & 1
    i2 = ~(j2 ^ s) & 1
    off = (s << 24) | (i1 << 23) | (i2 << 22) | ((hw1 & 0x3FF) << 12) | ((hw2 & 0x7FF) << 1)
    if s:
        off -= (1 << 25)
    return FLASH_BASE + offset + 4 + off


class Emulator:
    def __init__(self, firmware_data):
        self.fw = firmware_data
        self.millis_val = 0
        self.hw_result = 0
        self.memcmp_result = 1      # 1 = cle invalide
        self.overlay_called = False  # "NOT ACTIVATED" affiche?
        self.millis_called = False

    def _make_emu(self):
        mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        mu.mem_map(FLASH_BASE, FLASH_SIZE)
        mu.mem_write(FLASH_BASE, self.fw[:FLASH_SIZE])
        mu.mem_map(RAM_BASE, RAM_SIZE)
        mu.mem_write(RAM_BASE, b'\x00' * RAM_SIZE)
        mu.reg_write(UC_ARM_REG_SP, STACK_TOP - 0x200)
        return mu

    def _hook(self, mu):
        def on_code(uc, addr, size, _):
            if size != 4:
                return
            code = bytes(uc.mem_read(addr, 4))
            hw1 = struct.unpack("<H", code[0:2])[0]
            hw2 = struct.unpack("<H", code[2:4])[0]
            if (hw1 & 0xF800) != 0xF000 or (hw2 & 0xD000) != 0xD000:
                return
            target = decode_bl_target(self.fw, addr - FLASH_BASE)
            if target is None:
                return
            skip = addr + 4 + 1

            if target == ADDR_MILLIS:
                self.millis_called = True
                uc.reg_write(UC_ARM_REG_R0, self.millis_val)
                uc.reg_write(UC_ARM_REG_PC, skip)
            elif target == ADDR_OVERLAY_FN:
                self.overlay_called = True
                uc.reg_write(UC_ARM_REG_PC, skip)
            elif target in (ADDR_CLEANUP, ADDR_DELAY, ADDR_MEMSET, ADDR_SPRINTF):
                uc.reg_write(UC_ARM_REG_PC, skip)
            elif target == ADDR_MEMCMP:
                uc.reg_write(UC_ARM_REG_R0, self.memcmp_result)
                uc.reg_write(UC_ARM_REG_PC, skip)
            elif target == ADDR_HW_DETECT:
                uc.reg_write(UC_ARM_REG_R0, self.hw_result)
                uc.reg_write(UC_ARM_REG_PC, skip)
            elif target < FLASH_BASE or target >= FLASH_BASE + FLASH_SIZE:
                uc.reg_write(UC_ARM_REG_R0, 0)
                uc.reg_write(UC_ARM_REG_PC, skip)

        mu.hook_add(UC_HOOK_CODE, on_code)

    def run_key_validation(self, hw=0):
        """Emule la validation hardware. Retourne le flag d'activation."""
        mu = self._make_emu()
        self.hw_result = hw
        self._hook(mu)
        mu.reg_write(UC_ARM_REG_LR, RETURN_ADDR | 1)
        try:
            mu.emu_start(ADDR_KEY_VALID | 1, RETURN_ADDR, timeout=500000, count=200)
        except UcError:
            pass
        return mu.reg_read(UC_ARM_REG_R0)

    def run_timer_check(self, millis, validated=False):
        """
        Emule le timer check d'une fonction de rendu.
        Retourne True si l'overlay "NOT ACTIVATED" serait affiche.
        """
        mu = self._make_emu()
        self.millis_val = millis
        self.millis_called = False
        self.overlay_called = False
        self._hook(mu)

        mu.mem_write(ADDR_VALIDATED, bytes([1 if validated else 0]))
        mu.reg_write(UC_ARM_REG_R7, RAM_BASE + 0x1000)
        mu.reg_write(UC_ARM_REG_LR, RETURN_ADDR | 1)

        try:
            mu.emu_start(TIMER_CHECK_START | 1, TIMER_CHECK_END, timeout=500000, count=100)
        except UcError:
            pass

        return self.overlay_called


def read_timer_threshold(fw_data):
    """Lit le seuil du timer depuis le literal pool."""
    return struct.unpack("<I", fw_data[0x55204:0x55208])[0]


def main():
    if len(sys.argv) < 2:
        print("Usage: python test.py <fichier.bin>")
        print("       python test.py PIN2DMD.bin")
        print("       python test.py PIN2DMD_cracked.bin")
        return 1

    path = sys.argv[1]
    if not os.path.exists(path):
        print(f"Fichier introuvable: {path}")
        return 1

    with open(path, "rb") as f:
        fw = f.read()

    name = os.path.basename(path)
    threshold = read_timer_threshold(fw)

    print(f"{'=' * 60}")
    print(f" Emulation: {name}")
    print(f" Taille: {len(fw)} bytes")
    print(f" Timer seuil: {threshold} ms ", end="")
    if threshold == 180000:
        print("(3 minutes - original)")
    elif threshold == 0xFFFFFFFF:
        print("(~49.7 jours - patche!)")
    else:
        print(f"({threshold/60000:.1f} minutes)")
    print(f"{'=' * 60}")

    emu = Emulator(fw)

    # --- Validation hardware ---
    print(f"\n--- Validation hardware (sans I2C) ---")
    flag = emu.run_key_validation(hw=0)
    if flag == 0:
        print(f"  Resultat: 0x{flag:02X} -> NON ACTIVE")
    else:
        print(f"  Resultat: 0x{flag:02X} ('{chr(flag)}') -> ACTIVE (force!)")

    # --- Timeline du timer ---
    print(f"\n--- Timeline (device non valide, pas de fichier .key) ---")
    print(f"  {'Temps':>10s}  {'millis()':>10s}  {'Resultat'}")
    print(f"  {'-'*10}  {'-'*10}  {'-'*30}")

    test_times = [
        (0,       "0s (boot)"),
        (30000,   "30s"),
        (60000,   "1 min"),
        (120000,  "2 min"),
        (179999,  "2:59"),
        (180000,  "3:00 (seuil original)"),
        (180001,  "3:00.001"),
        (300000,  "5 min"),
        (600000,  "10 min"),
        (3600000, "1 heure"),
    ]

    triggered_at = None

    for ms, label in test_times:
        shows_overlay = emu.run_timer_check(millis=ms, validated=False)

        if shows_overlay:
            status = "<< NOT ACTIVATED >>"
            if triggered_at is None:
                triggered_at = (ms, label)
        else:
            status = "OK (pas de message)"

        # Indicateur visuel
        bar_pos = min(ms, 600000) * 20 // 600000
        bar = "#" * bar_pos + "." * (20 - bar_pos)
        print(f"  {label:>10s}  {ms:>8d}ms  [{bar}] {status}")

    # --- Timeline device valide ---
    print(f"\n--- Timeline (device VALIDE) ---")
    for ms, label in [(0, "0s"), (300000, "5 min"), (600000, "10 min")]:
        shows = emu.run_timer_check(millis=ms, validated=True)
        status = "<< NOT ACTIVATED >>" if shows else "OK (pas de message)"
        print(f"  {label:>10s}  {ms:>8d}ms  {status}")

    # --- Verdict ---
    print(f"\n{'=' * 60}")
    print(" VERDICT")
    print(f"{'=' * 60}")

    issues = []

    if flag != 0:
        issues.append("Validation HW bypassee (toujours active)")
    if threshold != 180000:
        issues.append(f"Timer modifie: {threshold}ms au lieu de 180000ms")
    if triggered_at is None:
        issues.append("Le message NOT ACTIVATED n'apparait JAMAIS")

    if not issues:
        print(f"  Protection INTACTE")
        print(f"  - Validation HW: fonctionnelle")
        print(f"  - Timer: 3 minutes")
        print(f"  - Message NOT ACTIVATED: apparait a {triggered_at[1]}")
    else:
        print(f"  Protection COMPROMISE!")
        for issue in issues:
            print(f"  - {issue}")

    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
