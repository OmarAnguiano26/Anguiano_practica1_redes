# 🔐 MySSN over IP — Encryption & Integrity Layer

> A custom C protocol layer providing **AES-128 CBC encryption** and **CRC32 integrity validation** over TCP/IP, implemented on a FRDM-K64F board using LwIP + FreeRTOS.

[![Status](https://img.shields.io/badge/status-active-brightgreen)](https://github.com/OmarAnguiano26/Anguiano_practica1_redes)
[![Platform](https://img.shields.io/badge/platform-FRDM--K64F-orange)](https://github.com/OmarAnguiano26/Anguiano_practica1_redes)
[![Language](https://img.shields.io/badge/language-C-lightgrey)](https://github.com/OmarAnguiano26/Anguiano_practica1_redes)
[![TCP/IP](https://img.shields.io/badge/stack-LwIP-blue)](https://github.com/OmarAnguiano26/Anguiano_practica1_redes)
[![RTOS](https://img.shields.io/badge/RTOS-FreeRTOS-green)](https://github.com/OmarAnguiano26/Anguiano_practica1_redes)

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Stack Architecture](#-stack-architecture)
- [Hardware & Tools](#-hardware--tools)
- [File Structure](#-file-structure)
- [API Reference](#-api-reference)
- [Implementation](#-implementation)
- [Network Configuration](#-network-configuration)
- [Results](#-results)
- [Conclusions](#-conclusions)
- [Contribute](#-want-to-contribute)
- [Author](#-author)

---

## 📖 Overview

This project implements a custom **Encryption and Integrity Layer (EIL)** in C that sits between a TCP echo application and the LwIP stack. It provides two core security services:

- **AES-128 CBC encryption** to protect message confidentiality
- **CRC32 integrity validation** to detect data corruption or tampering

The layer is implemented as a C library composed of three modules (`EIL`, `myssn_aes`, `myssn_crc`) and validated by communicating a **FRDM-K64F** board over Ethernet with a PC Python client.

> **Course:** Networks for Embedded Systems — ITESO A.C., Universidad Jesuita de Guadalajara  

---

## ✅ Features

- AES-128 CBC encryption/decryption using [tiny-AES-c](https://github.com/kokke/tiny-AES-c)
- Zero-padding to align messages to 16-byte AES block boundaries
- CRC32 validation using the NXP `fsl_crc` SDK driver (polynomial `0x04C11DB7`, seed `0xFFFFFFFF`)
- CRC appended as the last 4 bytes of every transmitted frame
- Bidirectional communication — board receives, decrypts, validates, echoes back
- Board IP statically configured at `192.168.0.102`

---

## 🏗 Stack Architecture

```
┌──────────────────────────────────┐
│        TCP Echo App              │  tcpecho_init() / tcpecho task
├──────────────────────────────────┤
│   Encryption & Integrity Layer   │  EIL_send() / EIL_receive()
│   ┌────────────┬───────────┐     │
│   │ myssn_aes  │ myssn_crc │     │  AES-128 CBC + CRC32
│   └────────────┴───────────┘     │
├──────────────────────────────────┤
│         LwIP (netconn API)       │  TCP sockets
├──────────────────────────────────┤
│         FreeRTOS                 │  Task scheduler
├──────────────────────────────────┤
│      ENET driver (NXP SDK)       │  PHY: KSZ8081
└──────────────────────────────────┘
```

---

## 🔧 Hardware & Tools

| Component | Description |
|---|---|
| **MCU Board** | NXP FRDM-K64F (ARM Cortex-M4) |
| **TCP/IP Stack** | LwIP via mcuXpresso SDK |
| **RTOS** | FreeRTOS |
| **Encryption** | AES-128 CBC — [tiny-AES-c](https://github.com/kokke/tiny-AES-c) |
| **Integrity** | CRC32 — NXP `fsl_crc` SDK driver |
| **PC Client** | Python (socket library) |
| **PHY** | KSZ8081 via MDIO |
| **IDE** | mcuXpresso IDE |

---

## 📁 File Structure

```
Anguiano_practica1_redes/
├── source/
│   ├── EIL.c                      # Encryption & Integrity Layer — core logic
│   ├── EIL.h                      # EIL public API
│   ├── myssn_aes.c                # AES-128 CBC wrapper (encrypt / decrypt)
│   ├── myssn_aes.h                # AES module types and API
│   ├── myssn_crc.c                # CRC32 wrapper using fsl_crc driver
│   ├── myssn_crc.h                # CRC module API
│   ├── aes.c / aes.h              # tiny-AES-c library
│   ├── lwip_tcpecho_freertos.c    # Main entry point + LwIP/FreeRTOS init
│   └── lwipopts.h                 # LwIP configuration options
├── lwip/                          # LwIP stack source
├── freertos/                      # FreeRTOS kernel
├── drivers/                       # NXP SDK peripheral drivers
└── README.md
```

---

## 📐 API Reference

### `EIL.h` — Public Interface

#### `EIL_InitCRC32`
```c
void EIL_InitCRC32(void);
```
Initializes the CRC32 peripheral with the standard CRC-32 configuration. Must be called before any send/receive operation.

---

#### `EIL_Init_AES`
```c
struct AES_ctx EIL_Init_AES(void);
```
Initializes the AES-128 context with a fixed 128-bit key and a zeroed IV. Returns the `AES_ctx` struct used in all subsequent encrypt/decrypt calls.

| Key | Value |
|---|---|
| Key | `01 02 03 04 05 06 07 08 09 00 01 02 03 04 05 06` |
| IV  | `00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00` |
| Mode | AES-128 CBC |

---

#### `EIL_receive`
```c
err_t EIL_receive(struct netconn *conn, struct AES_ctx ctx, uint8_t *data_buff);
```

| Property | Value |
|---|---|
| **Param (in)** | `conn` — active netconn socket |
| **Param (in)** | `ctx` — initialized AES context |
| **Param (out)** | `data_buff` — buffer where the decrypted plaintext is written |
| **Return** | `err_t` — LwIP error code (`ERR_OK` on success) |

**Behavior:**
1. Receives a TCP frame via `netconn_recv`.
2. Extracts the last 4 bytes as the received CRC32.
3. Computes CRC32 over the received payload (excluding CRC bytes).
4. Compares computed vs received CRC — prints result to console.
5. Decrypts the payload using AES-128 CBC.
6. Writes the decrypted data to `data_buff`.

---

#### `EIL_send`
```c
err_t EIL_send(struct netconn *conn, struct AES_ctx ctx, uint8_t *data);
```

| Property | Value |
|---|---|
| **Param (in)** | `conn` — active netconn socket |
| **Param (in)** | `ctx` — initialized AES context |
| **Param (in)** | `data` — plaintext string to send |
| **Return** | `err_t` — LwIP error code (`ERR_OK` on success) |

**Behavior:**
1. Re-initializes CRC32 to clear previous state.
2. Encrypts `data` with AES-128 CBC (zero-padded to 16-byte boundary).
3. Computes CRC32 over the encrypted payload.
4. Appends the 4-byte CRC at the end of the encrypted buffer.
5. Sends the complete frame over TCP via `netconn_write`.

---

### Frame Structure

```
┌───────────────────────────────────┬────────────────┐
│  AES-128 CBC Encrypted Payload    │  CRC32 (4 B)   │
│  (padded to multiple of 16 bytes) │  little-endian │
└───────────────────────────────────┴────────────────┘
```

---

### Internal Modules

#### `myssn_aes` — AES Wrapper

```c
struct AES_ctx myssn_AES_Init(void);
AES_struct_data myssn_Encrypt(struct AES_ctx ctx, uint8_t *data);
AES_struct_data myssn_Decrypt(struct AES_ctx ctx, AES_struct_data Encrypted_msg);
```

Uses `AES_struct_data` to carry both the (padded) payload and its length:

```c
typedef struct {
    uint8_t  padded_data[256];  // Encrypted or decrypted payload
    uint32_t pad_len;           // Length after padding (multiple of 16)
} AES_struct_data;
```

Encryption zero-pads the input to the next 16-byte boundary before calling `AES_CBC_encrypt_buffer`.

#### `myssn_crc` — CRC32 Wrapper

```c
void     myssn_InitCrc32(void);
uint32_t myssn_CRC32(uint8_t *data, uint8_t len);
```

Configures the NXP CRC peripheral with the standard CRC-32 parameters:

| Parameter | Value |
|---|---|
| Polynomial | `0x04C11DB7` |
| Seed | `0xFFFFFFFF` |
| Reflect in/out | `true` |
| XOR out | `0xFFFFFFFF` |
| Result | `kCrcFinalChecksum` |

---

## 🌐 Network Configuration

The board is statically configured with the following network parameters:

| Parameter | Value |
|---|---|
| IP Address | `192.168.0.102` |
| Subnet Mask | `255.255.255.0` |
| Gateway | `192.168.0.100` |
| MAC Address | `02:12:13:10:15:11` |
| TCP Port | `7` (echo) |

---

## 💻 Implementation — Processing Flow

```
TX Path (EIL_send):
  plaintext
    → zero-pad to 16-byte boundary
    → AES-128 CBC encrypt
    → CRC32 over ciphertext
    → append CRC32 (4 bytes, little-endian)
    → netconn_write (TCP)

RX Path (EIL_receive):
  netconn_recv (TCP)
    → split last 4 bytes as received CRC
    → CRC32 over ciphertext → compare
    → AES-128 CBC decrypt
    → write plaintext to data_buff
```

---

## 📊 Results

The EIL layer was validated by sending messages from a Python PC client to the board and echoing them back through the full encrypt → CRC → send → receive → CRC check → decrypt pipeline. CRC match results and decrypted payloads were printed to the serial console via `PRINTF`.

---

## 🔍 Conclusions

- Integrating multiple security modules (AES + CRC) into a clean layered API required careful separation between the transport layer (LwIP netconn) and the security logic (EIL).
- The NXP `fsl_crc` driver must be re-initialized before each CRC computation to reset the seed, otherwise results accumulate from previous calls.
- AES-128 CBC requires input lengths to be multiples of 16 — zero-padding was the simplest solution in a resource-constrained embedded environment.
- The tiny-AES-c library proved to be a lightweight and straightforward option for Cortex-M targets where a full mbedTLS stack would be excessive.
- This project reinforced the importance of reading the full SDK documentation, especially for peripheral initialization sequences.

---

## 🚀 Want to Contribute?

**Fork it → Improve it → Share it**

### Ideas for contributions

- 🔑 Add support for dynamic key exchange (e.g. ECDH handshake before communication)
- 🔄 Replace the static IV with a randomly generated one per session
- 📦 Add fragmentation support for payloads larger than 256 bytes
- 🧪 Build a loopback test mode using the board's own DAC/ADC for self-validation
- 📡 Port the EIL layer to another TCP/IP stack (FreeRTOS+TCP, STM32 Ethernet)
- 🔒 Add AES-256 support as a compile-time option


[![Fork this repo](https://img.shields.io/badge/Fork%20this%20repo-%F0%9F%8D%B4%20Contribute-blue?style=for-the-badge)](https://github.com/OmarAnguiano26/Anguiano_practica1_redes/fork)

---

## 👤 Author

**Omar Alejandro Anguiano Najar**  
🔗 [github.com/OmarAnguiano26](https://github.com/OmarAnguiano26)

**Institution:** ITESO A.C., Universidad Jesuita de Guadalajara  
**Program:** Embedded Systems Specialization — Networks for Embedded Systems  

---

## 📄 License

This project is for academic purposes. See [LICENSE](LICENSE) for details.
