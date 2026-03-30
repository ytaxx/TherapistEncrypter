![image](https://github.com/ytaxx/TherapistEncrypter/blob/main/therapist.png)

# TherapistEncrypter

A single-file, self-contained C++17 command-line encryptor. This repository implements a compact, audit-friendly double-pass cipher with a memory-hard key derivation and streaming file I/O. It is intended for local file encryption and a small interactive message mode.

See the implementation in [main.cpp](main.cpp).

## Current status

- Single-file C++17 implementation: `main.cpp` contains the full program (no external libraries required).
- Streaming chunked I/O: file-mode encryption/decryption streams data in 64 KiB chunks to avoid full-file buffering (`encryptFileStreamToFile` / `decryptFileStreamToFile`).
- Hardened KDF (V5): memory-hard key stretching using a 1 MiB scratch area and 131,072 iterations (`deriveHardenedSchedule`).
- Double-pass V5 encryption with independent salts (salt1/salt2) and legacy V4 decryption support.
- Incremental 256-bit MAC (4 × u64) with constant-time comparison; MAC is computed over the original plaintext and written into the header after streaming the ciphertext.
- Optimizations: 64-bit word operations, memcpy-based LE load/store, precomputed 64-bit S-box lane tables (`SBoxPair::fwd64`), 64-bit XOR hot-paths in CTR loops.

## Build

Recommended (highest-performance, GCC/Clang):

```bash
g++ -std=c++17 -O3 -march=native -flto -DNDEBUG -o therapist main.cpp
```

Portable / quick build:

```bash
g++ -std=c++17 -O2 -pipe -o therapist main.cpp
```

Notes:
- On Windows with MinGW/MSYS these commands work similarly. For MSVC create a Visual Studio project or compile with `cl` and equivalent optimization flags.
- If you enable future threaded features (parallel CTR segmentation, thread pools), you may need to add `-pthread` on POSIX systems.
- For profile-guided optimizations (PGO), build with `-fprofile-generate` and then `-fprofile-use` as usual for your toolchain.

## Usage

Non-interactive encrypt (simple):

```bash
./therapist input.bin "my passphrase"
# -> writes: input.bin.encrypt
```

Non-interactive decrypt:

```bash
./therapist decrypt input.bin.encrypt "my passphrase"
# -> writes: input.bin (or input.bin.decrypted if original name cannot be restored)
```

Interactive mode (menu, message mode):

```bash
./therapist
```

Interactive menu includes: encrypt, decrypt, and a message mode that stores short timestamped encrypted messages as files named `file_<timestamp>` next to the executable.

Behavior notes:
- Invoking with two arguments treats the first as an input path and the second as the passphrase (encrypt).
- Invoking with `decrypt <path> <pass>` performs decryption.

## File format (V5)

- Header magic: 4 bytes `{'T','P','C','5'}`
- Version: 1 byte (5)
- Salt length: 1 byte (32)
- MAC length: 1 byte (32)
- Layout: `[salt1 (32)] [salt2 (32)] [mac (32)] [ciphertext (N)]`

V4 (legacy) blobs are still accepted for decryption.

## Implementation highlights & where to look

- Source: [main.cpp](main.cpp)
- Key functions/types:
  - `deriveHardenedSchedule` -- memory-hard KDF (V5)
  - `encryptPayloadV5` / `decryptPayloadV5` -- in-memory double-pass flows
  - `encryptFileStreamToFile` / `decryptFileStreamToFile` -- streaming file-mode flows (64 KiB chunks)
  - `applyEnhancedCipher` / `applyEnhancedCipherChunk` -- CTR-style streaming cipher
  - `computeHardenedMac`, `macInit`, `macFeedBuffer`, `macFinalize` -- incremental MAC helpers
  - `SBoxPair::fwd64` and `applySBoxToWord` -- precomputed 64-bit S-box lane tables

## Security notes & threat model

- The implementation is designed for local file encryption with a focus on auditability and hardening via an expensive KDF. It is self-contained but implements custom primitives -- for high-assurance projects, prefer using vetted AEAD libraries (e.g., libsodium or OpenSSL) or subject this implementation to independent review.
- Default KDF parameters are intentionally expensive: 1 MiB memory and 131,072 iterations (compile-time constants in `main.cpp`). Adjust them in source if you need a different performance/security trade-off.
- The MAC covers the original plaintext; decryption verifies the MAC in constant time. On Windows the program performs optional anti-debug checks; these are defense-in-depth and not a substitute for secure runtime environments.

## Roadmap / TODO (high-impact items)

- Vectorize / widen MAC computation (word-wise or SIMD). (not started)
- Align and prefetch KDF memory; consider `mlock`/platform APIs to reduce swapping. (not started)
- Expose KDF parameters via CLI/env for easier tuning. (not started)
- Add microbench harness and profiling hooks; enable PGO workflow. (not started)
- Add unit tests and CI including format tests and basic fuzzing. (not started)
- Consider optional SIMD S-box (AVX2/NEON) fallback for heavy CPU workloads. (not started)

If you'd like, I can implement the top-priority item (parallel CTR segmentation for multi-core throughput) next.

## Contributing

- Bug reports, patches, and PRs welcome. Changes that improve auditability, add tests, or integrate standard AEAD backends are especially appreciated.

## License

MIT -- see [LICENSE](LICENSE).
