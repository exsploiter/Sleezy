# Security Policy & Architecture Guide

Sleezy is built with a defense-in-depth, local-first cryptographic philosophy. Steganography without strong cryptography is merely obscurity; Sleezy bridges mathematical steganography with modern authenticated encryption, strict memory-hard key derivation, and defense against container-level exploits.

This document outlines the security architecture of Sleezy, supported versions, vulnerability disclosure procedures, and operator best practices.

---

## 🛡️ Supported Versions

Security updates, patches, and fixes are actively maintained for the following versions:

| Version | Supported | Status |
|---|:---:|---|
| **v1.2.x** | ✅ | **Current Stable Release** (Active Security Support) |
| **v1.1.x** | ⚠️ | Critical Fixes Only |
| **< v1.1** | ❌ | End of Life (Upgrade Recommended) |

---

## 🚨 Reporting a Vulnerability

We welcome responsible, coordinated vulnerability disclosures from security researchers, cryptanalysts, and the open-source community.

### Disclosure Process
If you discover a security vulnerability (such as a cryptographic weakness, memory corruption, path traversal, or authentication bypass), **please do not open a public issue or discussion.**

1. **Email Disclosure**: Send a detailed report to the security maintainers at:
   - **Email**: `security@sleezy.dev` *(or open a private GitHub Security Advisory via the repository's Security tab)*
2. **Encrypted Communication**: If submitting sensitive exploit material or proofs-of-concept, you may request our PGP public key prior to sending.
3. **Information to Include**:
   - A clear description of the vulnerability and attack vector.
   - Affected carrier plugins, CLI flags, or cryptographic routines.
   - Complete, reproducible proof-of-concept (PoC) commands or scripts.
   - Potential impact (e.g., plaintext recovery, carrier corruption, arbitrary file overwrite).
   - Any proposed remediation or patch.

### Response SLA & Timeline
- **Initial Acknowledgement**: Within **24–48 hours** of report receipt.
- **Triage & Validation**: Within **5 business days**, confirming severity and scope.
- **Remediation & Patch**: Target release within **14 business days** depending on complexity.
- **Public Disclosure**: Coordinated public disclosure occurs only after an advisory and patched release have been published.

---

## 🏛️ Security Architecture & Cryptographic Primitives

Sleezy does not rely on ad-hoc or unauthenticated embedding. Every payload is subjected to a strict pipeline of authenticated encryption, cryptographic key derivation, and keyed spatial dispersion.

```text
[Payload Input] ──► [Manifest Container] ──► [Zstd / Deflate]
                                                    │
                                                    ▼
[Argon2id KDF] ──► [XChaCha20-Poly1305 / AES-256-GCM]
         │                                  │
         ▼                                  ▼
[Keyed PRNG Scatter] ◄────────────── [Ciphertext + Nonce]
         │
         ▼
[Carrier Plugin Embedding (LSB / Homoglyph / Archive)]
         │
         ▼
[Immediate In-Memory Self-Verification (SHA-256 + HMAC)]
```

### 1. Authenticated Encryption with Associated Data (AEAD)
All embedded payloads are encrypted using modern authenticated ciphers providing both **confidentiality** and **authenticity/integrity**:
- **XChaCha20-Poly1305** (Default when `PyNaCl` is installed):
  - 256-bit symmetric key.
  - 192-bit extended nonce (RFC 8439 derivative), completely eliminating nonce-reuse risks under random generation.
  - Poly1305 128-bit MAC tag.
- **AES-256-GCM** (NIST SP 800-38D fallback):
  - 256-bit symmetric key.
  - 96-bit cryptographically random nonce generated via OS-level CSPRNG (`secrets.token_bytes`).
  - GCM authentication tag for tamper resistance.

### 2. Memory-Hard Key Derivation (Argon2id)
Passphrases are transformed into cryptographic key material using **Argon2id** (RFC 9106, Winner of the Password Hashing Competition):
- Combines the side-channel resistance of Argon2i with the GPU/ASIC memory-hardness of Argon2d.
- **Default Parameters**:
  - Memory Cost: $2^{16}\text{ KiB} = 64\text{ MiB}$ (configurable up to $2^{24}\text{ KiB} = 16\text{ GiB}$).
  - Time Cost: 3 iterations (configurable from 1 to 32).
  - Parallelism: 4 threads (configurable from 1 to 64).
  - Salt: 16 bytes generated from `secrets.token_bytes(16)`.
- **Key Material Partitioning**:
  - Argon2id produces a raw 64-byte digest.
  - The first 32 bytes (`digest[:32]`) form the symmetric AEAD key.
  - The second 32 bytes (`digest[32:]`) initialize the Fisher-Yates PRNG scatter engine.

### 3. Stream-Hashed Keyfiles (Two-Factor Protection)
Operators may supply an optional independent keyfile alongside their passphrase (`--keyfile <path>`):
- The keyfile is processed using fixed **64 KiB chunked SHA-256 streaming**.
- Arbitrarily large keyfiles (even multi-gigabyte disk images or media files) can be utilized without risk of out-of-memory crashes or denial of service.
- The resulting digest is cryptographically combined with the passphrase:
  $$\text{Secret} = \text{Passphrase} \mathbin{\Vert} \texttt{"::KEYFILE::"} \mathbin{\Vert} \text{SHA256}(\text{Keyfile})$$

### 4. Keyed PRNG Spatial Scatter
Sequential LSB embedding in carrier files creates localized statistical anomalies detectable by steganalysis tools:
- Sleezy uses the 32-byte secondary key from the KDF as an internal PRNG seed (`random.Random(seed_int)`).
- Carrier coordinates (pixels, audio sample words, character positions) are shuffled using the **Fisher-Yates algorithm** across the entire available carrier capacity.
- Bits are dispersed non-sequentially, flattening localized density changes and defeating basic sequential scanning attacks.

### 5. In-Memory Self-Verification
Before any modified carrier file is persisted to disk:
- Sleezy extracts the embedded payload in-memory or inside an isolated OS temporary directory (`tempfile.TemporaryDirectory`).
- Decryption and MAC verification are performed.
- The SHA-256 digest of the extracted payload is validated against the container manifest.
- If verification fails for any reason, the output carrier is discarded immediately with exit code `6` (`EXIT_VERIFY_FAILED`).

---

## 🔒 Hardened Container & Archive Security

When packaging and extracting payloads (especially directories, multi-file payloads, or archives), Sleezy enforces strict input validation and boundary protections:

### 1. Path Traversal & "Zip/Tar-Slip" Mitigation
- **Filename Sanitization**: Payload names from untrusted container manifests pass through `_sanitize_filename()`, which strips path separators (`/`, `\`), null bytes (`\x00`), and directory traversal tokens (`..`).
- **Windows Reserved Devices**: Filenames matching Windows legacy device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`) are automatically prefixed (`safe_<name>`) to prevent OS-level system locks.
- **Strict Boundary Confinement**: Target paths are resolved and strictly validated via `target.is_relative_to(output_directory_resolved)`. Any attempt to write outside the extraction destination aborts immediately with an error.
- **Archive Member Validation (`_safe_extract_tar`)**:
  - Rejects special device nodes (character devices, block devices, named pipes/FIFOs).
  - Detects and rejects symbolic links and hard links whose targets resolve outside the extraction root.
  - Python 3.12+ safe extraction filter (`filter="data"`) is enforced.

### 2. Decompression Bomb Protection
To prevent uncompressed payload bombs from exhausting host memory:
- Both `deflate` (`zlib`) and `zstandard` engines enforce a hard **2 GiB ceiling** (`MAX_DECOMPRESSED_SIZE = 2 * 1024 * 1024 * 1024`).
- Any compressed payload expanding beyond this threshold raises an immediate security exception.

### 3. Resource Exhaustion & DoS Boundaries
Maliciously forged carrier headers are rejected at the parsing layer:
- **Ciphertext Size Limit**: Maximum allowed ciphertext length is capped at 16 GiB.
- **Manifest Length Limit**: Container manifest header is capped at 10 MiB.
- **KDF Parameter Sanity Checks**:
  - Time cost: $1 \le tc \le 32$.
  - Memory exponent: $8 \le mce \le 24$ (256 KiB to 16 GiB).
  - Parallelism: $1 \le par \le 64$.
- Attempts to supply out-of-bound parameters trigger `EXIT_UNSUPPORTED` without executing key derivation or memory allocation.

### 4. Side-Channel Timing Defense
All cryptographic checks—including checksum verification, magic byte validation, and manifest digest comparison—use constant-time comparison via Python's `hmac.compare_digest()` to eliminate timing side-channel leaks.

### 5. Profile Injection Prevention
Custom profile names (`--profile <name>`) are strictly validated against `^[a-zA-Z0-9_\-]+$`, preventing directory traversal or arbitrary configuration file manipulation.

---

## 🌐 Privacy & Network Architecture

- **100% Offline & Local Execution**: Sleezy contains zero telemetry, zero analytics, and zero network calls.
- **Airgap Compatible**: No external network dependencies, DNS lookups, or remote license checks. All operations occur purely in local memory and storage.
- **Clean Ephemeral Artifacts**: Temporary extraction checks operate within ephemeral directories managed by the operating system and are wiped upon completion.

---

## ⚠️ Steganographic Threat Model & Operational Limitations

Operators must understand the real-world operational constraints of steganography:

### 1. Capacity vs. Detectability Trade-Off
- Steganography does not create infinite hidden storage. Embedding at higher bits-per-channel (e.g., 3 or 4 bits in `image.lsb`) drastically increases carrier modification rates.
- For maximum deniability and anti-steganalysis resilience, use `--profile max-stealth` (1 bit/channel, high carrier-to-payload ratio) and check detectability via `sleezy analyze`.

### 2. Lossy Transcoding & Recompression
- Sleezy's image carrier plugin operates on **lossless formats** (PNG, BMP, TIFF, lossless WebP).
- Transmitting steganographic images through platforms that recompress or transcode media (such as WhatsApp, Twitter/X, Discord, or JPEG conversion) will destroy LSB payload bits.
- To transmit across lossy channels, consider container archives (`archive.comment`), whitespace carriers, or raw binary append methods.

### 3. Host Process Memory
- In standard user-space Python, passphrases and unencrypted payload buffers may reside temporarily in process memory until garbage collected.
- High-security operators should run Sleezy on encrypted filesystems (e.g., LUKS, BitLocker) and avoid swap paging to unencrypted storage.

---

## 💡 Operator Best Practices

1. **Always Use a Keyfile in Hostile Environments**: Combining a passphrase with a separate keyfile (`--keyfile key.bin`) prevents brute-force attacks even if the passphrase is compromised or shoulder-surfed.
2. **Increase Argon2 Memory for Long-Term Archival**: When storing long-term sensitive payloads, increase KDF parameters:
   ```bash
   sleezy embed --carrier photo.png --payload secret.doc --passphrase "..." --kdf-mem 20 --kdf-time 5
   ```
3. **Verify Carriers with the Steganalysis Suite**: Before publishing or transmitting a carrier, inspect it using the built-in diagnostic suite:
   ```bash
   sleezy analyze --carrier output.png --bitplane
   ```
   Ensure the Chi-Square ($\chi^2$) and Shannon entropy tests report low detectability risk.
