![image](https://github.com/ytaxx/TherapistEncrypter/blob/main/therapist.png)

# TherapistEncrypt

> A compact, standalone C++ command-line utility providing a hardened, memory-hard encrypt/decrypt primitive and a small message mode. Designed for local file encryption and simple secure message storage.

See the implementation in [main.cpp](main.cpp).

**Table of Contents**
- **Overview**: What this program does and goals
- **Features**: Key capabilities
- **How it works**: High-level cryptographic design
- **File format**: On-disk layout for encrypted blobs
- **Usage**: CLI and interactive examples
- **Build**: How to compile locally
- **Security notes**: Threat model and caveats
- **Contributing** and **License**

**Overview**
- **Purpose**: TherapistEncrypt is a single-file C++ program that encrypts and decrypts binary data using a modern, self-contained, double-pass cipher with a memory-hard key derivation. It also includes a small interactive "message" mode for quickly hiding short text messages into timestamped files.
- **Design goal**: Prioritise a compact, audit-friendly implementation with hardened key stretching and authenticated encryption via a 256-bit MAC.

**Features**
- **Two versions supported**: Legacy V4 (kept for compatibility) and hardened V5 (default for new encryption).
- **Memory-hard KDF**: V5 uses a 1 MiB scratch area and 131,072 iterations to derive per-salt key schedules.
- **Double encryption**: V5 applies two independent encryption passes with separate salts.
- **Chaff padding**: Adds random padding to obfuscate plaintext length within limits.
- **256-bit MAC**: Custom 4x64-bit cascaded MAC with constant-time comparison.
- **CTR-like block mode**: 128-bit block size with a custom block cipher core and CTR counter generation derived from salt.
- **Interactive message mode**: Quickly write or read timestamped message files (written as `file_*` in the executable directory).
- **Anti-debug / self-protection**: Runtime checks to detect debuggers and optional Windows elevation handling.

**How it works (high level)**

- Input: arbitrary binary data + passphrase.
- Key derivation (V5): the passphrase and a generated 32-byte salt are mixed into an 8-word internal state, expanded into a 1 MiB scratch buffer and shuffled in a memory-hard loop (131,072 iterations) to produce a hardened key schedule.
- Cipher core (V5): a 32-round Feistel-like block cipher uses dual S-box substitution, key-dependent mixing, and sentinel constants. Encryption runs in CTR-like mode to produce stream keystream blocks which are XORed with plaintext.
- Double-pass encryption: the plaintext is first padded with randomized chaff, encrypted with a key schedule derived from salt1, then the result is encrypted again with an independently derived key schedule from salt2.
- MAC: a 256-bit cascaded MAC is computed over the original plaintext (not the padded or double-encrypted data) using both salts and the passphrase; stored alongside salts so decryption can verify authenticity.
- Output format: header magic + version + salt lengths + mac length + salt1 + salt2 + mac + ciphertext.
- Decryption: verifies header and version, reads salts and mac, reverses double encryption, removes chaff padding, computes MAC on recovered plaintext and compares in constant time.

**File format (encrypted blob)**
- Header: 4 bytes magic. For V5 this is `{'T','P','C','5'}`.
- Version: 1 byte (V5 = `5`).
- Salt length: 1 byte (V5 uses `32`).
- MAC length: 1 byte (V5 uses `32`).
- Payload layout (V5): `[salt1 (32)] [salt2 (32)] [mac (32)] [ciphertext (N)]`.

The program will also accept V4-formatted blobs (legacy) for decryption.

**Usage**

Build (simple):

```bash
g++ -std=c++17 -O2 -o main main.cpp
```

Basic command-line usage:

- Encrypt a file (non-interactive):

```bash
./main input.bin my-passphrase
# produces input.bin.encrypt
```

- Decrypt a file (non-interactive):

```bash
./main decrypt input.bin.encrypt my-passphrase
# produces input.bin (or input.bin.decrypted if original name unavailable)
```

- Run in interactive mode (menu):

```bash
./main
```

Interactive menu options include: encrypt, decrypt, and a message mode to write/read short timestamped messages saved as `file_*` in the executable directory.

Message mode (interactive):
- Choose the message option, type a short message and a passphrase — the program will create a `file_<timestamp>` containing the encrypted payload. To read, choose the stored session and provide the passphrase.

Notes on paths and output names:
- By default encrypting `foo` produces `foo.encrypt`.
- Decrypting an input ending with `.encrypt` strips that suffix when possible, otherwise it writes `<input>.decrypted`.

**Build & platform notes**
- The code is written portable C++ and includes Windows-specific helpers (console UTF-8 setup, privilege elevation). On Windows, the program requests administrator privileges in certain scenarios via a relaunch; this behaviour can be disabled with the `THERAPIST_DISABLE_SELF_PROTECTION` environment variable.
- The provided simple build command uses `g++`. On Windows with MinGW or MSYS you can use the same command; with MSVC create a project or compile using `cl` with equivalent flags.

**Security notes & threat model**
- TherapistEncrypt is intended for local file encryption where the attacker does not control the runtime environment. It includes anti-debug checks and other self-protection measures, but these should not be relied on for protecting secrets on compromised systems.
- KDF parameters (1 MiB memory, 131,072 iterations) are deliberately expensive to slow offline brute-force attacks. These parameters are compile-time constants and can be adjusted in source if you need different trade-offs.
- The MAC covers the original plaintext and uses a 256-bit custom construction. While designed for robustness, treat the implementation as a custom crypto primitive — for high-assurance projects prefer well-reviewed authenticated encryption libraries (e.g., libsodium, OpenSSL AEAD) unless you plan an external audit.
- Always protect your passphrase: if it is weak, the attacker can brute-force the derived key despite the memory-hard KDF.

**Where to look in the source**
- Main program and primitives: [main.cpp](main.cpp)
- Key areas:
  - KDF and key schedule: `deriveHardenedSchedule` (V5)
  - Block cipher: `encryptBlockV5` / `decryptBlockV5`
  - CTR-like stream: `applyEnhancedCipher`
  - Double-pass encryption / MAC assembly: `encryptPayloadV5` / `decryptPayloadV5`
  - Legacy support: `decryptPayloadV4`

**Contributing**
- If you want to improve the project, please open issues or PRs.
- Suggested work: add unit tests for format parsing, verify MAC / KDF properties, and add optional integration with standard crypto libs for AEAD.

**TODOS**

**High priority**

- Streamed, chunked I/O: change readBinaryFile/writeBinaryFile and the main pipeline to process fixed-size buffers rather than load entire files into memory — reduces memory use and enables pipelining for double-pass encryption. See main.cpp.
- Parallelize KDF derivation: deriveHardenedSchedule is expensive and called twice for salt1/salt2 in encryptPayloadV5; run these two derivations concurrently to save wall-clock time. See main.cpp.
- Pipeline double-pass encryption: create a two-stage pipeline (ks1 encrypt -> queue -> ks2 encrypt -> write) so you can stream and avoid storing full pass1. See encryptPayloadV5 / applyEnhancedCipher in main.cpp.

**Medium priority**

- Parallelize CTR-mode across block ranges: split ciphertext into N segments and compute keystream/XOR per thread (compute segment counter = base + (start/kBlockSize)). See applyEnhancedCipher in main.cpp.
- Vectorize/word-wise MAC: change computeHardenedMac from byte-by-byte feed to word/64-bit processing to reduce loop overhead.
- Expose KDF parameters: make kKdfIterations and kKdfMemoryBytes adjustable via CLI/env so users can trade speed vs hardness.

**Lower priority**

- Align KDF buffer and prefetch inner-loop reads; consider mlock/VirtualLock to keep scratch from swapping (requires privileges).
- Implement SIMD S-box (AVX2/NEON) fallback for applySBoxToWord (highest speed on supported CPUs, but complex and needs careful testing).
- Add microbenchmarks and CI (PGO/LTO build profiles) to measure improvements and integrate profiling runs.
- Replace custom MAC with a standard fast MAC (BLAKE2b/HMAC) only if acceptable for protocol goals.
- Add progress reporting for long operations and an option to run in lower-cost KDF mode for fast runs.

**License**
- MIT. License text is in [LICENSE](LICENSE).
