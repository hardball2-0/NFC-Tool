# wCopy / nsccn NFC reader – HID protocol (static analysis of nfcPro_x64.exe)

Confidence: **H** = read straight from the code, **M** = strong inference, **G** = guess.
**VERIFIED** = confirmed on the user's 0416:B030 "wCopy NFC108-IDIC V705N7".

## 1. Transport

* USB HID through hidapi (statically linked). Tried in this order: 0416:B030, 0416:B031, 2518:6022, 2518:6018 (open 0x4A5D0; reconnect 0x4C060 uses a different order). The device is opened in blocking mode (`dev->blocking = 1`).
* Report size: 64 bytes, report ID 0 (input/output caps are 65 including the ID byte, VERIFIED).
* Model handling: the PID is saved to global 0x871909C, and the only code that touches it is the open function. **No command differs between the 4 VID/PIDs** in this binary (H).
* Leftover code: the send function calls ClearCommError/PurgeComm on the hid_device pointer. They do nothing useful and can be dropped.

## 2. Frame format (send 0x453F0, receive inline / 0x45330)

Host → device (the 64 bytes after the report-ID byte; on Windows write 65 bytes = `00` + frame, zero-padded):

| off | value |
|---|---|
| 0 | `01` (direction: host → device) |
| 1 | `LL` = total frame length = payload_len + 6 |
| 2..3 | seq, u16 LE. Starts at 0 and goes up by 2 after every send (global 0x8718F72) |
| 4..4+n-1 | payload (n ≤ 0x30, longer payloads are cut to 48) |
| 4+n | `CK` = ~(sum of bytes 0..3+n) & 0xFF |
| 5+n | `FE` |

Device → host (hid_read_timeout, 65-byte buffer, 2000 ms timeout; the app requires exactly 64 bytes back):

| off | value |
|---|---|
| 0 | `02` (direction: device → host) |
| 1 | `LL` total length |
| 2..3 | seq = request seq + 1 (VERIFIED) |
| 4..LL-3 | payload (LL-6 bytes) |
| LL-2 | `CK` = ~(sum of bytes 0..LL-3) |
| LL-1 | `FD` |

The checksum covers byte 0 in both directions (VERIFIED with live frames and the PN532 path at 0x4A6C0, which checks `resp[0]==2`, the checksum and `FD`). Most vendor-command wrappers skip the checksum check and only look at `LL` and payload[0].

### Payload conventions
* Every payload starts `FF 00 <CMD> ...` (an ACR122-style pseudo-APDU: CLA=FF, INS=00).
* Vendor responses usually look like `payload[0] = N` (number of data bytes), then N data bytes. A few also end in `90 00`. Wrappers usually test `LL == N+7 && payload[0] == N`.
* Seen with no card present: payload `FD` (LL=7) after `6B 30`, so it looks like an error/no-card status (VERIFIED value; meaning M).
* The version commands return raw ASCII payload with no count byte.

### Worked examples (VERIFIED)
```
>> 00 | 01 09 00 00 FF 00 68 8E FE 00…00            (65 bytes incl. report id)
<< 02 1E 01 00 "wCopy NFC108-IDIC V705N7" 5F FD
>> 00 | 01 09 02 00 FF 00 69 8B FE
<< 02 12 03 00 "T39699261487" 44 FD
>> 00 | 01 0A 04 00 FF 00 6B 30 56 FE
<< 02 07 05 00 FD F4 FD                               (no card)
```
Checksum check: 01+09+00+00+FF+00+68 = 0x171, so ~0x71 = 0x8E.

## 3. Command table

### 3.1 Device / info
| RVA | Payload | Response | Meaning | Conf |
|---|---|---|---|---|
| 45980 | `FF 00 68` | ASCII, LL-6 bytes | firmware/model string | H, VERIFIED |
| 45A90 | `FF 00 69` | ASCII | serial / second version string | H, VERIFIED |
| 45750 | sends 68, then 69 | — | builds the `"<68> - <69>"` version string | H |
| 45BA0(rdx=ms) | `FF 00 40 50 04 T 01 01 01`, T=max(1, ms/10) | ignored | buzzer/LED (ACR122 `FF 00 40 P2 04 T1 T2 rep link` form) | H layout / M meaning |
| 4C120 / 43C00 | `FF 00 9A 5A A5 54 69 61 6E` ("Z¥Tian") | LL=0x0C, payload `02 90 00 …` means OK | vendor "magic"/unlock handshake. Purpose unknown. No direct callers (reached indirectly). **Not sent live.** | H bytes / G meaning |

### 3.2 ISO14443A fast scan (vendor)
| RVA | Payload | Response | Conf |
|---|---|---|---|
| 46110 | `FF 00 6B 30` | LL=0x19, p[0]=0x12, p[1..2]=ATQA, p[3]=SAK, p[4]=UID len (4/7/10), p[5..]=UID, p[0x11..0x12]=`90 00`. Returns the UID length; any other length gives the 16 raw bytes. No card gives `FD`. | H, no-card VERIFIED |
| 463C0(cl=0/1) | `FF 00 6B 31 xx` | LL=0x29, p[0]=0x22, ATQA/SAK/len/UID as above, 16 data bytes at p[0x11..0x20], p[0x21..0x22]=`90 00` | H layout. Meaning of xx (0/1) and the 16 bytes: G. The caller 0x525E0 runs xx=0 and xx=1 and compares the two |

### 3.3 PN532 passthrough (all MIFARE Classic / NTAG / magic-card work)
Wrapper 0x4A6C0: payload `FF 00 00 00 Lc D4 <PN532 cmd + params>` with Lc = n+1. The response payload is `D5 <cmd+1> <data…> 90 00`. The wrapper checks D5 and cmd+1 and returns data+SW (LL-8 bytes) (H). This is the ACR122U "direct transmit" format, so the app contains libnfc's pn53x layer (H: register numbers and the property state machine match libnfc).

PN532 commands the app uses (H):
* `08 hh ll vv` WriteRegister (0x4A8A0) → expects `90 00`.
* `06 hh ll` ReadRegister (0x4A9F0, read-modify-write helper) → `vv 90 00`.
* `32 01 00/01` RFConfiguration, RF field off/on (0x4AE20 init: off, sleep 10 ms, on).
* `32 05 00 01 02` RFConfiguration, MaxRetries.
* `12 xx` SetParameters.
* `40 01 …` InDataExchange and `42 …` InCommunicateThru (0x4B140 transceive bytes, 0x4B7F0 transceive bits).
* Registers touched: 0x6302 TxMode, 0x6303 RxMode (CRC on/off), 0x6305 TxAuto, 0x630D ManualRCV (parity off), 0x633D BitFraming, 0x6336/0x633A/0x633C (Error/FIFOLevel/Control, read after a raw exchange).

**Crypto attacks** (darkside/mfcuk, nested/mfoc, hardnested, FM11RF08S; strings in 0x33CC0) all run on the PC. The reader only provides raw frames:
* Nonces and encrypted answers come from `D4 42` InCommunicateThru, with parity/CRC handling disabled through 0x630D/0x6302/0x6303 (libnfc "handle_parity/handle_crc" off).
* Short frames (7-bit REQA/WUPA, 4-bit NACK) use BitFraming 0x633D and Control 0x633C (bits received).
* After an exchange, 0x4B7F0 reads Error (0x6336) so that parity-error / NACK conditions reach the darkside code (M).
Your own app can do the same: run a libnfc-style pn53x stack on top of the `FF 00 00 00 Lc D4…` wrapper.

### 3.4 125 kHz read
| RVA | Payload | Response | Conf |
|---|---|---|---|
| 46B40 via 435F0 | `FF 00 65 05 1E f0 f1 f2 f3 00 00 00 00` (13 bytes; f = carrier frequency u32 LE, default 125000 = `48 E8 01 00`. The UI also offers 175k/250k/300k/375k/500k from the table at 0x85AD0) | LL=0x0C, p[0]=5, p[1..5] = EM4100 5-byte ID | H layout / M meaning |
| 46D90 via 43620 | `FF 00 6A 01 00 08` (u16 LE param 0x0800), up to 5 tries with 10 ms between them; the app reads twice and compares | LL=0x0E, p[0]=7, p[1]=type byte, p[2..7] = 6 raw bytes. The PC decodes them as HID Prox: sentinel bit gives the length (26–37 bits, returned as 0x1A–0x25) and Wiegand parity is checked. Return 1 when raw[0]=9 and raw[1]=1, 2 for other non-zero raw[0] (other formats, G) | H layout / M meaning |

### 3.5 125 kHz chip-level family (writing/cloning) – summary only
All these functions use the template `FF 00 66 00 1E <freq u32 LE> <op> <args…>`, and most reply `LL=0x0C, p[0]=5` (OK + 5 bytes) or `LL=7, p[0]=0` (OK, no data). The ops seen are 00, 01, 12, 13, 1F, 21, 22, 32, 33, 34, 3F, 40–47 and 4F. They are used by the LF clone/write routines 0x10FC0 / 0x64600 / 0x6B970, which go through T5577/EM4305-class chips one after another and then read the ID back with §3.4.
* 46 xx (0x48C50) returns 40 raw demodulated samples per call (xx = 0x00, 0x28). The PC thresholds and decodes them (H).
These change tag contents, so they were not tested live and are documented only at this level. Exact argument layouts can be read from functions 46A40, 46C80, 47E40–482D0, 48570–48C50, 497E0–4A4B0 in drv.txt.

### 3.6 Device storage (0x85 family) – writes reader flash, never send
`FF 00 85 <sub> …`: 10 = erase(addr u16, len u16, fill), 12 = write(addr u16, len u16, ≤40 bytes data), 32 = commit(u32 addr 0x800, u16 len 0x200, u16 flag), 33 xx = select area (4, 6), 34 = finish, 01 = store a key record (UID4, ATQA, SAK, sector count).
They are used for:
* the 512-byte settings block: "X7-V3.10" header, RF parameters, checksum from 0x46910;
* uploading recovered MIFARE keys after a crack (0x33CC0), probably for offline copying (M).

## 4. Network
No reader command carries network data. The uploads to Chinese servers happen in other app code, not in this protocol.
