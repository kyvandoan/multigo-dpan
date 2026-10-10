#!/usr/bin/env python3
"""
Apple Pay DPAN reader — PN532 (UART over PL2303), EMV contactless.

v3 — key fixes after field testing:

  1. Luhn validation on every PAN candidate. The raw track-2 regex previously
     matched the ASCII text "DEBIT MASTERCARD" (hex 44454... contains digits
     and a 'D') and reported it as a 16-digit number. DPANs are Luhn-valid
     by spec, so candidates that fail Luhn are logged and rejected.
  2. Stage validation + bounded resend. Right after field activation the
     PN532 reports RF/DEP errors (status 0x06) and card responses lag
     behind the host exchanges (a stale PPSE FCI can arrive several
     exchanges late). Each stage now validates the expected response shape
     (FCI=6F, GPO=77/80, record=70) and re-sends its command until the
     response matches — which self-heals the desync.
  3. 200 ms settling delay after target detection before the first APDU.
  4. v4 — Visa support: qVSDC wallets often answer GPO with "format 1"
     (template 80: 16 bytes of amount fields, then normal TLV), which the
     TLV parser never recursed into; the GPO stage now strips that header,
     and the GENERATE AC fallback uses a typical CDOL1 when the records
     contained no 8C tag (Visa often hides the DPAN there, tag 9F6B).
"""

import serial
import time
import sys
import re

SERIAL_PORT = "/dev/ttyUSB0"  # COMx on Windows
BAUD_RATE = 115200
VERBOSE = True

PPSE = "325041592E5359532E4444463031"  # 2PAY.SYS.DDF01
FALLBACK_AIDS = [
    "A0000000041010",  # Mastercard M/Chip
    "A0000000031010",  # Visa
    "A0000000032010",  # Visa Electron / Interlink
    "A00000002501",    # Amex
]

# Typical Visa/Mastercard CDOL1 — used for the GENERATE AC fallback when
# no 8C tag was found in the records
DEFAULT_CDOL1 = bytes.fromhex("9F0206" "9F0306" "9F1A02" "9505" "5F2A02"
                              "9A03" "9C01" "9F3704")

PN532_STATUS = {
    0x00: "OK",
    0x01: "timeout - target lost or wallet session ended",
    0x02: "CRC error",
    0x03: "parity error",
    0x04: "erroneous bit count",
    0x05: "RF buffer overflow",
    0x06: "RF/DEP error - transient, often right after activation; retry",
    0x13: "RF protocol error",
    0x27: "ISO14443-4 layer error",
    0x29: "target did not answer RTOX request",
}

SW_MEANING = {
    "9000": "OK",
    "6700": "wrong length (Le/Lc)",
    "6981": "command incompatible with file structure",
    "6982": "security status not satisfied",
    "6985": "conditions of use not satisfied",
    "6A81": "function not supported",
    "6A82": "file/AID not found",
    "6A83": "record not found",
    "6A86": "incorrect P1/P2",
    "6A87": "Lc inconsistent with P1-P2",
    "6E00": "class of instruction not supported",
}


def log(msg):
    if VERBOSE:
        print(msg)


def luhn_ok(digits: str) -> bool:
    """Network token PANs (DPANs) are generated to pass Luhn."""
    if not digits.isdigit() or len(digits) < 13:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# ----------------------------------------------------------------------------
# PN532 host frames
# ----------------------------------------------------------------------------

class PN532UART:
    def __init__(self, port, baudrate=115200):
        self.ser = serial.Serial(port, baudrate=baudrate, timeout=2.0)

    def _calc_checksum(self, data: bytes) -> int:
        return (~sum(data) + 1) & 0xFF

    def send_command(self, cmd_bytes: bytes):
        length = len(cmd_bytes)
        lcs = (~length + 1) & 0xFF
        dcs = self._calc_checksum(cmd_bytes)
        frame = bytearray([0x00, 0x00, 0xFF, length, lcs])
        frame.extend(cmd_bytes)
        frame.extend([dcs, 0x00])
        self.ser.reset_input_buffer()
        self.ser.write(frame)

    def read_ack(self) -> bool:
        ack = self.ser.read(6)
        return ack == bytes([0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00])

    def read_response(self) -> bytes:
        header = self.ser.read(3)
        while header and header != bytes([0x00, 0x00, 0xFF]):
            # responses > 255 bytes use the extended frame format
            # (00 00 FF FF FF ...) which this parser does not handle
            header = header[1:] + self.ser.read(1)
        if not header:
            return b""
        length_info = self.ser.read(2)
        if len(length_info) < 2:
            return b""
        length, lcs = length_info
        if ((length + lcs) & 0xFF) != 0:
            return b""
        payload = self.ser.read(length)
        self.ser.read(2)  # DCS + postamble
        if len(payload) >= 2 and payload[0] == 0xD5:
            return payload[2:]
        return b""

    def call(self, cmd: int, params: bytes = b"") -> bytes:
        self.send_command(bytes([0xD4, cmd]) + params)
        time.sleep(0.015)
        if not self.read_ack():
            return b""
        return self.read_response()

    def wakeup_and_config(self):
        self.ser.write(bytes([0x55, 0x55, 0x00, 0x00, 0x00, 0x00]))
        time.sleep(0.05)
        self.call(0x14, bytes([0x01, 0x14, 0x01]))        # SAMConfiguration
        self.call(0x32, bytes([0x05, 0xFF, 0x01, 0x00]))  # retries
        self.call(0x32, bytes([0x01, 0x01]))             # RF field on

    def reset_field(self):
        self.call(0x32, bytes([0x01, 0x00]))  # RF off
        time.sleep(0.05)
        self.call(0x32, bytes([0x01, 0x01]))  # RF on

    def poll_target(self) -> bool:
        res = self.call(0x4A, bytes([0x01, 0x00]))
        return len(res) > 0 and res[0] >= 1

    def send_apdu(self, apdu: bytes, label: str = ""):
        """One InDataExchange. Returns (body, sw_bytes). Dumps everything."""
        res = self.call(0x40, bytes([0x01]) + apdu)
        if not res:
            log(f"    [{label}] no PN532 frame at all")
            return b"", b""
        status = res[0]
        data = res[1:]
        sw = data[-2:] if len(data) >= 2 else b""
        body = data[:-2] if len(data) >= 2 else b""
        sw_name = SW_MEANING.get(sw.hex().upper(), "?")
        log(f"    [{label}] APDU={apdu.hex().upper()}")
        log(f"    [{label}] PN532=0x{status:02X} "
            f"({PN532_STATUS.get(status, '?')})  SW={sw.hex().upper()} "
            f"({sw_name})  body={len(body)}B")
        log(f"    [{label}] RAW={data.hex().upper()}")
        return body, sw

    def exchange(self, apdu: bytes, label: str, expect, tries: int = 5,
                 delay: float = 0.07):
        """Send one APDU repeatedly until the response matches `expect`.

        expect(body, sw) -> bool. This heals the activation desync: early
        exchanges fail with PN532 RF errors and stale responses arrive
        late, so we keep re-sending the SAME stage command until the
        response has the expected shape (FCI=6F, GPO=77/80, record=70).
        """
        for i in range(1, tries + 1):
            body, sw = self.send_apdu(apdu, f"{label} try{i}")
            if expect is None:
                return body, sw
            if body and expect(body, sw):
                return body, sw
            # definitive card-side errors: don't burn the retries
            s = sw.hex().upper()
            if s in ("6E00", "6981", "6985", "6A82"):
                return body, sw
            time.sleep(delay)
        return b"", b""


# ----------------------------------------------------------------------------
# TLV / PAN helpers
# ----------------------------------------------------------------------------

def extract_tlv(data: bytes, tag: int) -> bytes:
    i = 0
    while i < len(data):
        if data[i] in (0x00, 0xFF):  # padding
            i += 1
            continue
        t = data[i]
        i += 1
        if (t & 0x1F) == 0x1F:
            if i >= len(data):
                break
            t = (t << 8) | data[i]
            i += 1
        if i >= len(data):
            break
        ln = data[i]
        i += 1
        if ln & 0x80:
            nb = ln & 0x7F
            if nb == 0 or i + nb > len(data):
                break
            ln = int.from_bytes(data[i:i + nb], byteorder="big")
            i += nb
        value = data[i:i + ln]
        truncated = i + ln > len(data)
        if t == tag:
            return value
        if (t if t < 0x100 else (t >> 8)) & 0x20:  # constructed
            found = extract_tlv(value, tag)
            if found:
                return found
        if truncated:
            break
        i += ln
    return b""


def extract_all_tlv(data: bytes, tag: int) -> list:
    """Non-recursive scan for every occurrence of a 1- or 2-byte tag."""
    out = []
    i = 0
    while i < len(data):
        if data[i] in (0x00, 0xFF):
            i += 1
            continue
        t = data[i]
        i += 1
        if (t & 0x1F) == 0x1F:
            if i >= len(data):
                break
            t = (t << 8) | data[i]
            i += 1
        if i >= len(data):
            break
        ln = data[i]
        i += 1
        if ln & 0x80:
            nb = ln & 0x7F
            if nb == 0 or i + nb > len(data):
                break
            ln = int.from_bytes(data[i:i + nb], byteorder="big")
            i += nb
        if t == tag:
            out.append(data[i:i + ln])
        if i + ln > len(data):
            break
        i += ln
    return out


def _pan_from_track2_hex(hexs: str):
    m = re.search(r"(\d{13,19})D(\d{4})", hexs)
    return (m.group(1), m.group(2)) if m else (None, None)


def find_pan(*payloads):
    """Return (pan, expiry, source) — Luhn-validated.

    Candidates that look like PANs but fail Luhn (e.g. ASCII application
    labels whose hex contains long digit runs) are logged and skipped.
    """
    candidates = []

    for name, tag in (("5A", 0x5A), ("57", 0x57),
                      ("9F6B", 0x9F6B), ("56", 0x56)):
        for p in payloads:
            if not p:
                continue
            v = extract_tlv(p, tag)
            if not v:
                continue
            hexs = v.hex().upper()
            if name == "5A":
                pan = hexs.rstrip("F")
                if 13 <= len(pan) <= 19 and pan.isdigit():
                    exp = extract_tlv(p, 0x5F24)
                    exp_s = f"{exp[1]:02d}/{exp[0]:02d}" if len(exp) >= 2 else "?"
                    candidates.append((pan, exp_s, f"tag 5A"))
            elif name == "56":  # Track 1 is ASCII
                m = re.search(r"%?B(\d{13,19})\^", v.decode("ascii", "ignore"))
                if m:
                    candidates.append((m.group(1), "?", "tag 56"))
            else:  # 57 / 9F6B: packed track-2 nibbles
                pan, exp = _pan_from_track2_hex(hexs)
                if pan:
                    candidates.append((pan, exp, f"tag {name}"))

    for p in payloads:  # raw scan (last resort — needs Luhn even more)
        if p:
            pan, exp = _pan_from_track2_hex(p.hex().upper())
            if pan:
                candidates.append((pan, exp, "raw track-2 scan"))

    for pan, exp, src in candidates:
        if luhn_ok(pan):
            return pan, exp, src
        log(f"    [!] rejecting candidate {pan} ({src}): Luhn check failed")
    return None, None, None


def build_dol_data(dol_bytes: bytes) -> bytes:
    """Fill a PDOL/CDOL template with plausible terminal values."""
    defaults = {
        0x9F66: bytes.fromhex("26000000"),  # Terminal Transaction Qualifiers
        0x9F02: bytes(6),                   # amount, authorized = 0
        0x9F03: bytes(6),                   # amount, other = 0
        0x9F1A: bytes.fromhex("0704"),      # terminal country: VN
        0x95:  bytes(5),                    # terminal verification results
        0x5F2A: bytes.fromhex("0704"),      # currency: VND
        0x9A:  bytes.fromhex("260810"),     # transaction date (example)
        0x9C:  b"\x00",                     # transaction type: purchase
        0x9F37: bytes(4),                   # unpredictable number
        0x9F35: b"\x22",                    # terminal type
        0x9F45: b"\x00\x00",                # data authentication code
        0x9F4C: bytes(8),                   # ICC dynamic number
        0x9F7C: bytes.fromhex("0140000000000000"),
    }
    out = bytearray()
    i = 0
    while i < len(dol_bytes):
        t = dol_bytes[i]
        i += 1
        if (t & 0x1F) == 0x1F:
            if i >= len(dol_bytes):
                break
            t = (t << 8) | dol_bytes[i]
            i += 1
        if i >= len(dol_bytes):
            break
        ln = dol_bytes[i]
        i += 1
        val = defaults.get(t, bytes(ln))
        out.extend(val[:ln].ljust(ln, b"\x00"))
    return bytes(out)


# ----------------------------------------------------------------------------
# EMV flow
# ----------------------------------------------------------------------------

def _is_fci(body, sw):        return body[0] == 0x6F
def _is_gpo(body, sw):        return body[0] in (0x77, 0x80)
def _is_record(body, sw):     return body[0] == 0x70


def emv_read_dpan(nfc: PN532UART):
    # 0. let the wallet's NFC stack settle after activation
    time.sleep(0.2)

    # 1. SELECT PPSE — validated (must be a 6F FCI), resent until coherent
    ppse_apdu = bytes.fromhex("00A404000E") + bytes.fromhex(PPSE) + b"\x00"
    ppse_body, _ = nfc.exchange(ppse_apdu, "SELECT PPSE", _is_fci)
    aids = extract_all_tlv(ppse_body, 0x4F) if ppse_body else []
    print(f"[+] PPSE advertised AIDs: "
          f"{[a.hex().upper() for a in aids] or '(none parsed — using fallbacks)'}")
    if aids:
        candidates = aids + [bytes.fromhex(a) for a in FALLBACK_AIDS]
    else:
        candidates = [bytes.fromhex(a) for a in FALLBACK_AIDS]
    seen = set()
    candidates = [a for a in candidates
                  if not (a in seen or seen.add(a))]

    for aid in candidates:
        # 2. SELECT AID — validated FCI (or empty 9000, some kernels do that)
        sel = bytes([0x00, 0xA4, 0x04, 0x00, len(aid)]) + aid + b"\x00"
        aid_body, sw = nfc.exchange(
            sel, f"SELECT {aid.hex().upper()}",
            lambda b, s: b[:1] == b"\x6F" or (b == b"" and s.hex() == "9000"))
        if sw.hex().upper() == "6A82":
            print(f"[-] AID {aid.hex().upper()} not present, trying next")
            continue

        # 3. GET PROCESSING OPTIONS — validated (template 77 or 80)
        pdol = extract_tlv(aid_body, 0x9F38)
        pdol_val = build_dol_data(pdol)
        gpo_payload = bytes([0x83, len(pdol_val)]) + pdol_val
        gpo = (bytes([0x80, 0xA8, 0x00, 0x00, len(gpo_payload)])
               + gpo_payload + b"\x00")
        gpo_body, sw = nfc.exchange(gpo, "GPO", _is_gpo)
        if not gpo_body or gpo_body[0] not in (0x77, 0x80):
            print("[-] GPO did not return a coherent response, next AID")
            continue

        # Visa/qVSDC wallets often answer GPO in "format 1" (template 80):
        # 16 bytes of amount fields followed by normal TLV (57, 94, ...)
        scan_gpo = gpo_body[16:] if gpo_body[0] == 0x80 else gpo_body
        pan, exp, src = find_pan(gpo_body, scan_gpo)
        if pan:
            return pan, exp, src, f"{src} in GPO response"

        # 4. READ RECORDS per AFL — validated (template 70)
        afl = extract_tlv(scan_gpo, 0x94)
        cdol1 = b""
        if afl and len(afl) >= 4:
            print(f"[+] AFL={afl.hex().upper()} -> reading records")
            for k in range(0, len(afl) - 3, 4):
                sfi = afl[k] >> 3
                for r in range(afl[k + 1], afl[k + 2] + 1):
                    p2 = (sfi << 3) | 0x04
                    body, sw = nfc.exchange(
                        bytes([0x00, 0xB2, r, p2, 0x00]),
                        f"READ REC SFI{sfi} #{r}",
                        lambda b, s: b[:1] == b"\x70"
                        or s.hex().upper() in ("6A83", "6A81"),
                        tries=3)
                    if not body or body[0] != 0x70:
                        continue
                    cdol1 = extract_tlv(body, 0x8C) or cdol1
                    pan, exp, src = find_pan(body)
                    if pan:
                        return pan, exp, src, f"{src} in record SFI{sfi}#{r}"

        # 5. GENERATE AC fallback (what a terminal sends at the end of every
        #    transaction; its response can carry track-2 data — Visa often
        #    only exposes the DPAN there, as tag 9F6B)
        if not cdol1:
            cdol1 = DEFAULT_CDOL1  # records had no 8C — try the typical set
        cdol_val = build_dol_data(cdol1)
        gen = (bytes([0x80, 0xAE, 0x80, 0x00, len(cdol_val)])
               + cdol_val + b"\x00")
        body, _ = nfc.exchange(gen, "GENERATE AC (ARQC, amt=0)",
                               lambda b, s: b[:1] == b"\x77", tries=3)
        pan, exp, src = find_pan(body)
        if pan:
            return pan, exp, src, f"{src} in GENERATE AC response"
    return None, None, None, "no Luhn-valid PAN in any response"


def main():
    nfc = PN532UART(SERIAL_PORT, BAUD_RATE)
    print("[*] Initializing PN532...")
    nfc.wakeup_and_config()
    print("[*] Ready. Double-click Apple Pay and hold near the antenna.")
    attempt = 0
    while True:
        sys.stdout.write(".")
        sys.stdout.flush()
        if nfc.poll_target():
            attempt += 1
            print(f"\n[+] Target detected (attempt {attempt})")
            try:
                pan, exp, src, where = emv_read_dpan(nfc)
            except Exception as e:
                print(f"[-] Flow error: {e!r}")
                pan = None
            if pan:
                print("\n" + "=" * 46)
                print(f"  16-digit number : {pan}  (Luhn-valid)")
                print(f"  Expiry          : {exp}")
                print(f"  Found via       : {where}")
                print("  Confirm last 4 digits == the Device Account")
                print("=" * 46 + "\n")
                return
            print("[-] Attempt finished without a PAN. Re-double-click the "
                  "side button for the next attempt...")
            nfc.reset_field()
        time.sleep(0.15)


if __name__ == "__main__":
    main()
