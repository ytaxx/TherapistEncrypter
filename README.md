# TherapistEncrypter (still in dev)

A single-file, self-contained C++17 command-line encryption tool. No external dependencies required - just compile and run or download the latest compiled program.

See the full implementation in [main.cpp](main.cpp).

![image](https://github.com/ytaxx/TherapistEncrypter/blob/v0.2.0/img/1.png)

## Features

- **Single-file C++17** - the entire program lives in `main.cpp`, no libraries to install
- **V6 encrypted format** - embeds original filename and date inside the ciphertext
- **Double-pass Feistel cipher** - 32-round SBox-based block cipher in CTR mode, applied twice with independent salts
- **Memory-hard KDF** - 131,072 iterations over a 1 MiB scratch buffer (tunable via CLI or environment)
- **256-bit cascaded MAC** - 4×64-bit FNV-like chains with constant-time verification
- **Interactive menu** - encrypt files, decrypt files, write/read encrypted messages
- **Built-in self-test** - 16 tests covering crypto primitives, payloads, authentication, file I/O, and message helpers
- **Backward compatible** - reads V5 encrypted files (no metadata) (V4 removed)
- **Secure memory** - RAII key wiping, locked memory support, secure zero on all sensitive buffers

## Build

```bash
g++ -std=c++17 -O2 -pipe -static -static-libgcc -static-libstdc++ -o therapist.exe main.cpp
```

On Windows with MinGW, the same command works. No `-pthread` needed - Windows threading uses the native API.

Run the self-test:

```bash
./therapist --self-test
```

## Usage

### Non-interactive

Encrypt a file:

```bash
./therapist input.pdf "my passphrase"
# -> input.pdf.encrypted
```

Decrypt a file:

```bash
./therapist decrypt input.pdf.encrypted "my passphrase"
# -> input.pdf (restored from embedded metadata)
```

### Interactive mode

```bash
./therapist
```

Menu options:
1. **Encrypt a file** - prompts for path, passphrase, optional output name

![image](https://github.com/ytaxx/TherapistEncrypter/blob/v0.2.0/img/5.png)

2. **Decrypt a file** - prompts for path, passphrase; restores original filename

![image](https://github.com/ytaxx/TherapistEncrypter/blob/v0.2.0/img/6.png)

3. **Write an encrypted message** - encrypts a typed message to a timestamped file

![image](https://github.com/ytaxx/TherapistEncrypter/blob/v0.2.0/img/3.png)

4. **Read an encrypted message** - lists available message files, decrypts and displays with typewriter animation

![image](https://github.com/ytaxx/TherapistEncrypter/blob/v0.2.0/img/4.png)

5. **Run self-test** - runs all 16 built-in tests

![image](https://github.com/ytaxx/TherapistEncrypter/blob/v0.2.0/img/2.png)

### CLI options

| Option | Description |
|---|---|
| `--self-test` | Run comprehensive self-test and exit |
| `--kdf-iterations=N` | Override KDF iteration count |
| `--kdf-memory=SIZE` | Override KDF memory (e.g., `2M`, `512K`) |

Environment variables `THERAPIST_KDF_ITERATIONS` and `THERAPIST_KDF_MEMORY_BYTES` also work.

## File format (V6)

```
[4 bytes: "TPC6"] [version: 6] [salt_len: 32] [mac_len: 32]
[salt1: 32 bytes] [salt2: 32 bytes] [MAC: 32 bytes]
[ciphertext]
```

The ciphertext contains an augmented payload with random chaff, the original filename, date, and the actual file data - all encrypted with the double-pass cipher.

V5 files (`TPC5` header) are still accepted for decryption but lack embedded metadata.

## Key functions

| Function | Purpose |
|---|---|
| `deriveHardenedSchedule` | Memory-hard KDF producing round keys + MAC seeds |
| `encryptPayload` / `decryptPayload` | Full encrypt/decrypt with V6 format |
| `encryptBlockV5` | 32-round Feistel block cipher |
| `applyCipher` | Double-pass CTR mode |
| `computeHardenedMac` | 256-bit cascaded MAC |
| `buildAugmentedV6` / `parseAugmentedV6` | Chaff + metadata + plaintext packing |
| `runSelfTest` | Comprehensive 16-test validation suite |

## Security notes

- Custom cipher implementation - designed for auditability and self-containment. For high-assurance use, prefer vetted libraries (libsodium, OpenSSL) or get this reviewed independently.
- KDF defaults are intentionally expensive (1 MiB, 131K iterations). Adjust via CLI flags if needed.
- MAC covers original plaintext; verification is constant-time.
- All key material is securely zeroed via RAII destructors.
- Passphrase length warning at < 8 characters.

## Contributing

- Bug reports, patches, and PRs welcome. Changes that improve auditability, add tests, or integrate standard AEAD backends are especially appreciated.

## License

MIT - see [LICENSE](LICENSE).
