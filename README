# Apple Pay DPAN Reader (PN532)

Extract the **16-digit Device Account Number (DPAN)** from a card stored in Apple Pay, using a PN532 NFC reader connected over USB-serial. Built to link a tokenized wallet to **MultiGo**, the official Ho Chi Minh City public transit app, which matches travel history by card number.

When you add a card to Apple Pay, the physical card number (FPAN) is replaced by a device-specific token (DPAN). Apps like MultiGo that correlate taps by card number can only match your Apple Pay travel if they are given the **DPAN** — and Apple does not display it anywhere. Over NFC, however, the wallet presents the DPAN to any EMV reader during the transaction handshake. This script acts as a minimal EMV contactless terminal and captures it.

> ⚠️ **Use only with your own cards.** Reading payment credentials from cards you do not own may be illegal in your jurisdiction.

---

## Hardware Requirements

| Component | Notes |
|---|---|
| PN532 NFC module (NFC Shield v3 or compatible) | Must support the UART/HSU interface |
| PL2303 USB-to-UART adapter | CP210x/CH340 adapters also work |
| 4 jumper wires (female-female) | GND, VCC, TX, RX |
| Computer with a free USB port | Linux, macOS, or Windows |
| iPhone or Apple Watch | With the card already added to Apple Pay |

**Wiring**

| PN532 | PL2303 |
|---|---|
| GND | GND |
| VCC | 3.3 V (5 V works on most modules) |
| TXD | RXD |
| RXD | TXD |

Set the module's DIP switches to **UART (HSU) mode** (on Elechouse V3 modules: switch 1 OFF, switch 2 ON). Baud rate: **115200**.

---

## Installation

1. **Python 3.8+** and `pyserial`:

   ```bash
   pip install pyserial
   ```

2. Download the script (`multigo-apple-pay.py`) and set your serial port in the constants at the top:

   ```python
   SERIAL_PORT = "/dev/ttyUSB0"
   BAUD_RATE = 115200
   ```

3. **Linux only** — grant yourself access to the serial port:

   ```bash
   sudo usermod -aG dialout $USER   # then log out and back in
   ```

4. Verify the adapter is visible: `ls /dev/ttyUSB*` (Linux), `ls /dev/cu.usbserial*` (macOS).

---

## Usage

1. Run the script:

   ```bash
   python3 multigo-apple-pay.py
   ```

   It prints `[*] Ready. Double-click Apple Pay and hold near the antenna.`

2. **On the iPhone/Watch: open Wallet and swipe to the card you want to read.** Each double-click session presents only the card shown on screen — if your default card is another one, you will read that one instead.

3. **Double-click the side button** (Face ID/Touch ID confirmation) and hold the device flat against the reader antenna until the logs finish.

4. The script runs a full EMV handshake and prints the result:

   ```
   16-digit number : 5417571234567890  (Luhn-valid)
   Expiry          : 09/28
   Found via       : tag 57 in record SFI1#1
   ```

5. **Verify before use:** compare the last 4 digits against the *Device Account Number* shown in Wallet → card details. Only use the number if they match.

6. Enter the 16-digit DPAN into MultiGo's card registration/linkage.

**Timing notes:** double-click sessions are short. If an attempt ends without a result, re-double-click and hold again — the script keeps polling and starts a fresh attempt automatically.

---

## How It Works

The script implements a minimal EMV contactless terminal through the PN532:

1. **Field poll** — `InListPassiveTarget` (ISO 14443-A) detects the activated wallet.
2. **SELECT PPSE** (`2PAY.SYS.DDF01`) — the wallet's directory; lists the available payment applications (AIDs).
3. **SELECT AID** — picks the payment app, e.g. Mastercard M/Chip (`A0000000041010`) or Visa (`A0000000031010`).
4. **GET PROCESSING OPTIONS (GPO)** — with a terminal data template; returns the Application File Locator (AFL), sometimes the card data itself. Handles both response formats: template `77` (Mastercard-style) and format 1 / template `80` (Visa-style, 16-byte amount header).
5. **READ RECORD** — reads the files the AFL points to. The DPAN typically appears in tag `57` (Track 2 Equivalent Data) or `5A` (Application PAN); Visa may instead return it only in tag `9F6B` inside the **GENERATE AC** response, which the script requests as a fallback with a zero-amount cryptogram.
6. **Validation** — every candidate must pass a **Luhn check** before being reported, which filters out false positives (e.g. ASCII application labels that decode to digit-like hex).

**Robustness measures**: right after activation, Apple devices respond slowly and the PN532 can report RF errors (`status 0x06`) while card responses lag several exchanges behind. Each stage therefore validates the expected response shape (FCI `6F`, GPO `77`/`80`, record `70`) and re-sends its command until the response is coherent, plus a 200 ms settling delay after detection.

**Why it can't be used for fraud:** the exchange yields only the static DPAN digits. All transaction cryptograms are dynamic and bound to terminal data — nothing captured here can authorize a payment. The DPAN is also rejected for card-not-present use.

---

## Supported Platforms

| Area | Support |
|---|---|
| Wallet devices | iPhone, Apple Watch |
| Card networks | Mastercard (M/Chip) — tested working; Visa (qVSDC, incl. format-1 GPO + GENERATE AC fallback) — supported; Amex and others — untested |
| Reader hardware | PN532-based modules over UART (PL2303/CP210x/CH340 USB-serial adapters) |
| Host OS | Linux, macOS, Windows (Python 3.8+, `pyserial`) |
| Serial port | Up to 255-byte response frames (extended PN532 frames are not parsed) |

Not supported: Android/Google Wallet tokens, reader modules other than PN532, I2C/SPI connection modes (UART only).

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `PN532=0x06` on early exchanges, stale responses | Wallet's NFC stack not ready after activation | Normal — the script resends until coherent; keep the device flat on the antenna |
| PPSE advertises no AIDs / wrong card read | Default card presented instead of the intended one | Swipe to the desired card in Wallet *before* double-clicking |
| `SW=6982` (security status not satisfied) | Wallet withholding data before cryptogram generation | Script falls back to GENERATE AC; if that also fails, the issuer may mask the DPAN |
| `SW=6700/6985` on Visa GPO | Terminal Transaction Qualifiers value not accepted | Adjust the `9F66` default (`26000000`) in `build_dol_data` |
| Candidate rejected with "Luhn check failed" | False positive (e.g. "DEBIT MASTERCARD" label hex) | Informational only — keep scanning |
| No serial port found | Driver or permissions | Install PL2303 driver; on Linux add yourself to `dialout` |
| Records return nothing, GPO fine | Response exceeded 255 bytes or wallet session ended mid-flow | Re-double-click; keep total flow under ~20 s |

---

