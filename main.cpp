#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <unordered_set>

#ifndef _WIN32
#include <thread>
#endif

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <malloc.h>
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
using HINTERNET = LPVOID;
using INTERNET_PORT = WORD;

constexpr INTERNET_PORT kInternetDefaultHttpsPort = 443;
constexpr DWORD kWinHttpAccessTypeDefaultProxy = 0;
constexpr DWORD kWinHttpFlagSecure = 0x00800000;
constexpr DWORD kWinHttpQueryStatusCode = 19;
constexpr DWORD kWinHttpQueryFlagNumber = 0x20000000;
constexpr DWORD kHttpStatusOk = 200;

using WinHttpOpenFn = HINTERNET (WINAPI*)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
using WinHttpConnectFn = HINTERNET (WINAPI*)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
using WinHttpOpenRequestFn = HINTERNET (WINAPI*)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR const*, DWORD);
using WinHttpSetTimeoutsFn = BOOL (WINAPI*)(HINTERNET, int, int, int, int);
using WinHttpSendRequestFn = BOOL (WINAPI*)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
using WinHttpReceiveResponseFn = BOOL (WINAPI*)(HINTERNET, LPVOID);
using WinHttpQueryHeadersFn = BOOL (WINAPI*)(HINTERNET, DWORD, LPCWSTR, LPVOID, LPDWORD, LPDWORD);
using WinHttpQueryDataAvailableFn = BOOL (WINAPI*)(HINTERNET, LPDWORD);
using WinHttpReadDataFn = BOOL (WINAPI*)(HINTERNET, LPVOID, DWORD, LPDWORD);
using WinHttpCloseHandleFn = BOOL (WINAPI*)(HINTERNET);
#else
#include <dirent.h>
#include <sys/mman.h>
#include <utime.h>
#endif

namespace therapist {

// the newly added comments made by AI, I was lazy to explain things more (commit 55d34d0)


// ---------------------------------------------------------------------------
//  types
// ---------------------------------------------------------------------------
using ByteVector = std::vector<std::uint8_t>; // alias for binary buffers (vector of bytes)

// ---------------------------------------------------------------------------
//  constants
// ---------------------------------------------------------------------------
// v6 (current default -- adds embedded filename + date)
constexpr std::array<std::uint8_t, 4> kMagicV6 = {'T', 'P', 'C', '6'}; // file format magic for v6
constexpr std::uint8_t kVersionV6 = 6; // version byte for v6 format

struct AppVersion {
    int major;
    int minor;
    int patch;
    std::string preRelease; // optional pre-release label (e.g. "pre3", "rc1")
};

struct RemoteVersionInfo {
    bool checked = false;
    bool succeeded = false;
    bool outdated = false;
    AppVersion latestVersion{0, 0, 0, ""};
    std::string downloadUrl;
    std::string versionInfoUrl;
    std::string errorMessage;
    // (SHA256 verification removed)
};

// application identity / version (single edit point)
constexpr const char* kAppExeName = "therapist";
constexpr const char* kAppVersionText = "0.2.0pre4"; // update this one place for compiled default
// default current version text. you can override at runtime with
// the THERAPIST_CURRENT_VERSION environment variable
constexpr const char* kCurrentVersionText = kAppVersionText;
static AppVersion kCurrentAppVersion{0, 0, 0, ""};
constexpr const char* kDefaultVersionInfoUrl =
    "https://raw.githubusercontent.com/ytaxx/TherapistEncrypter/refs/heads/v0.2.0pre3/version.txt";
constexpr const char* kDefaultReleaseUrl =
    "https://github.com/ytaxx/TherapistEncrypter/releases";
constexpr int kVersionResolveTimeoutMs = 2000;
constexpr int kVersionConnectTimeoutMs = 3000;
constexpr int kVersionSendTimeoutMs = 2000;
constexpr int kVersionReceiveTimeoutMs = 3000;

constexpr std::size_t kSaltSize     = 32;
constexpr std::size_t kMacSize      = 32;   // 4 x u64
constexpr std::size_t kRounds       = 32;
constexpr std::size_t kBlockSize    = 16;
constexpr std::size_t kChaffMin     = 16;
constexpr std::size_t kChaffMax     = 48;
constexpr std::size_t kDateLen      = 10;   // "dd-mm-yyyy"

// default KDF tuning (overridable via env / CLI)
constexpr std::size_t kKdfIterDefault  = 131072;
constexpr std::size_t kKdfMemDefault   = 1048576; // 1 MiB
static std::size_t gKdfIterations  = kKdfIterDefault;
static std::size_t gKdfMemoryBytes = kKdfMemDefault;

// ---------------------------------------------------------------------------
//  user-configurable settings
// ---------------------------------------------------------------------------
struct EncryptionSettings {
    std::size_t kdfIterations          = kKdfIterDefault;
    std::size_t kdfMemoryBytes         = kKdfMemDefault;
    std::size_t chaffMin               = kChaffMin;
    std::size_t chaffMax               = kChaffMax;
    bool        spoofTimestamps        = true;
    bool        deleteSourceAfterEncrypt = false;
    int         minPasswordLength      = 1;
    bool        requireUppercase        = false;
    bool        requireLowercase        = false;
    bool        requireDigit            = false;
    bool        requireSpecial          = false;
    bool        confirmWeakPasswords    = true;
    bool        showDetails             = true;
};

static EncryptionSettings gSettings;
static RemoteVersionInfo gRemoteVersionInfo;

inline int compareAppVersion(const AppVersion& left, const AppVersion& right) {
    if (left.major != right.major) return left.major < right.major ? -1 : 1;
    if (left.minor != right.minor) return left.minor < right.minor ? -1 : 1;
    if (left.patch != right.patch) return left.patch < right.patch ? -1 : 1;
    // handle pre-release: a release (empty preRelease) is considered greater
    if (left.preRelease.empty() && right.preRelease.empty()) return 0;
    if (left.preRelease.empty()) return 1;  // left is release, right is pre-release
    if (right.preRelease.empty()) return -1; // left pre-release < release

    // both have pre-release labels: try to compare intelligently
    if (left.preRelease == right.preRelease) return 0;

    // split alpha prefix and numeric suffix (e.g. "pre3" -> "pre", 3)
    auto splitAlphaNum = [](const std::string& s) {
        std::size_t i = s.size();
        while (i > 0 && std::isdigit(static_cast<unsigned char>(s[i-1]))) --i;
        std::string prefix = s.substr(0, i);
        long long num = -1;
        if (i < s.size()) {
            try { num = std::stoll(s.substr(i)); } catch (...) { num = -1; }
        }
        return std::make_pair(prefix, num);
    };

    auto L = splitAlphaNum(left.preRelease);
    auto R = splitAlphaNum(right.preRelease);
    if (L.first != R.first) return L.first < R.first ? -1 : 1;
    if (L.second != R.second) {
        if (L.second == -1) return -1;
        if (R.second == -1) return 1;
        return L.second < R.second ? -1 : 1;
    }
    return left.preRelease < right.preRelease ? -1 : 1;
}

inline bool isProgramOutdated() {
    return gRemoteVersionInfo.succeeded && gRemoteVersionInfo.outdated;
}

inline std::string formatAppVersion(const AppVersion& version) {
    std::string s = std::to_string(version.major) + "." +
           std::to_string(version.minor) + "." +
           std::to_string(version.patch);
    if (!version.preRelease.empty()) s += version.preRelease;
    return s;
}

// block cipher whitening constants (derived from pi and e)
constexpr std::uint64_t kWhitenA =
    0x3141592653589793ULL ^ 0x2718281828459045ULL;
constexpr std::uint64_t kWhitenB =
    0x6A09E667F3BCC908ULL ^ 0xBB67AE8584CAA73BULL;

// ---------------------------------------------------------------------------
//  colors & symbols
// ---------------------------------------------------------------------------
namespace Color {
    constexpr const char* reset     = "\033[0m";
    constexpr const char* bold      = "\033[1m";
    constexpr const char* dim       = "\033[2m";
    constexpr const char* underline = "\033[4m";
    // theme
    constexpr const char* title     = "\033[1;38;5;214m";
    constexpr const char* accent    = "\033[38;5;214m";
    constexpr const char* muted     = "\033[38;5;244m";
    constexpr const char* label     = "\033[38;5;249m";
    constexpr const char* input     = "\033[38;5;255m";
    constexpr const char* border    = "\033[38;5;240m";
    // status
    constexpr const char* ok        = "\033[38;5;82m";
    constexpr const char* okBold    = "\033[1;38;5;82m";
    constexpr const char* warn      = "\033[38;5;208m";
    constexpr const char* warnBold  = "\033[1;38;5;208m";
    constexpr const char* error     = "\033[38;5;196m";
    constexpr const char* errorBold = "\033[1;38;5;196m";
    constexpr const char* info      = "\033[38;5;75m";
    constexpr const char* infoBold  = "\033[1;38;5;75m";
}

namespace Sym {
    // ASCII fallbacks; upgraded to Unicode at runtime if terminal supports it
    const char* check = "+";
    const char* cross = "x";
    const char* warn  = "!";
    const char* dot   = "*";
    const char* arrow = ">";
    const char* dash  = "-";
}

static bool gUnicodeSupported = false;

inline void initSymbols() {
    if (gUnicodeSupported) {
        Sym::check = "\xe2\x9c\x93";
        Sym::cross = "\xe2\x9c\x97";
        Sym::warn  = "\xe2\x9a\xa0";
        Sym::dot   = "\xe2\x80\xa2";
        Sym::arrow = "\xe2\x96\xba";
        Sym::dash  = "\xe2\x94\x80";
    }
}

// ---------------------------------------------------------------------------
//  s-box (256-byte permutation, deterministic PRNG)
// ---------------------------------------------------------------------------
struct SBoxPair {
    std::array<std::uint8_t, 256> fwd; // forward permutation s-box (byte -> byte)
    std::array<std::uint8_t, 256> inv; // inverse permutation for undoing s-box
    std::array<std::array<std::uint64_t, 256>, 8> fwd64{}; // precomputed 64-bit lane values
};

inline SBoxPair buildSBoxPair() {
    SBoxPair p;
    for (int i = 0; i < 256; ++i)
        p.fwd[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(i); // initialize identity permutation
    std::uint32_t rng = 0x7A3B9E1DU; // lcg seed used for deterministic shuffle
    for (int i = 255; i > 0; --i) {
        rng = rng * 1103515245U + 12345U; // advance lcg
        int j = static_cast<int>(((rng >> 16) & 0x7FFFU) %
                                 static_cast<unsigned>(i + 1)); // pick index from 0..i
        std::swap(p.fwd[static_cast<std::size_t>(i)],
                  p.fwd[static_cast<std::size_t>(j)]); // swap to shuffle
    }
    for (int i = 0; i < 256; ++i)
        p.inv[p.fwd[static_cast<std::size_t>(i)]] =
            static_cast<std::uint8_t>(i); // build inverse mapping
    for (int lane = 0; lane < 8; ++lane) {
        const unsigned shift = static_cast<unsigned>(lane * 8U);
        for (int b = 0; b < 256; ++b)
            p.fwd64[static_cast<std::size_t>(lane)][static_cast<std::size_t>(b)] =
                static_cast<std::uint64_t>(p.fwd[static_cast<std::size_t>(b)]) << shift; // precompute lane shifted values
    }
    return p;
}

inline const SBoxPair& sbox() {
    static const SBoxPair instance = buildSBoxPair();
    return instance;
}

// ---------------------------------------------------------------------------
//  primitive helpers
// ---------------------------------------------------------------------------
inline std::uint64_t rotl64(std::uint64_t v, unsigned s) { // rotate-left 64-bit
    s &= 63U;
    return s ? (v << s) | (v >> (64U - s)) : v;
}

#if defined(_MSC_VER)
#include <intrin.h>
#pragma intrinsic(_byteswap_uint64)
static inline std::uint64_t bswap64(std::uint64_t x) { return _byteswap_uint64(x); }
#elif defined(__GNUC__) || defined(__clang__)
static inline std::uint64_t bswap64(std::uint64_t x) { return __builtin_bswap64(x); }
#else
static inline std::uint64_t bswap64(std::uint64_t x) {
    return ((x & 0xFF00000000000000ULL) >> 56) |
           ((x & 0x00FF000000000000ULL) >> 40) |
           ((x & 0x0000FF0000000000ULL) >> 24) |
           ((x & 0x000000FF00000000ULL) >>  8) |
           ((x & 0x00000000FF000000ULL) <<  8) |
           ((x & 0x0000000000FF0000ULL) << 24) |
           ((x & 0x000000000000FF00ULL) << 40) |
           ((x & 0x00000000000000FFULL) << 56);
}
#endif

#if defined(_MSC_VER) || defined(__i386__) || defined(__x86_64__) || \
    (defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && \
     __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#define PLATFORM_LE 1
#else
#define PLATFORM_LE 0
#endif

inline std::uint64_t load64LE(const std::uint8_t* d) { // load 64-bit little-endian into host-order
    std::uint64_t v;
    std::memcpy(&v, d, 8);
#if PLATFORM_LE
    return v;
#else
    return bswap64(v);
#endif
}

inline void store64LE(std::uint8_t* d, std::uint64_t v) { // store 64-bit value as little-endian bytes
#if PLATFORM_LE
    std::memcpy(d, &v, 8);
#else
    std::uint64_t t = bswap64(v);
    std::memcpy(d, &t, 8);
#endif
}

inline void incrementCounter(std::array<std::uint8_t, kBlockSize>& ctr) { // increment 128-bit counter stored as two 64-bit little-endian words
    std::uint64_t lo = load64LE(ctr.data());
    std::uint64_t hi = load64LE(ctr.data() + 8);
    ++lo; // low word increments first
    if (lo == 0ULL) ++hi; // propagate carry to high word
    store64LE(ctr.data(), lo);
    store64LE(ctr.data() + 8, hi);
}

inline std::uint64_t applySBoxToWord(std::uint64_t w, const SBoxPair& sb) { // apply s-box to each byte lane using precomputed fwd64
    std::uint64_t r = 0;
    for (unsigned i = 0; i < 8U; ++i) {
        std::uint8_t b = static_cast<std::uint8_t>((w >> (i * 8U)) & 0xFFU); // extract byte i
        r |= sb.fwd64[i][static_cast<std::size_t>(b)]; // or in pre-shifted substitution value
    }
    return r;
}

// ---------------------------------------------------------------------------
//  csprng (os entropy - no std::random_device)
// ---------------------------------------------------------------------------
// fill buffer with cryptographically secure random bytes.
// uses BCryptGenRandom (preferred) or RtlGenRandom (fallback) on windows,
// or /dev/urandom on unix.
// this is the single point of entropy for the program.
// does not use std::random_device because it is not guaranteed secure.
inline void fillCryptoRandom(std::uint8_t* buf, std::size_t len) {
    if (len == 0) return;
#ifdef _WIN32
    // --- primary: BCryptGenRandom (available on Vista+/Server 2008+) ---
    using BCryptGenRandomPtr = LONG(WINAPI*)(PVOID, PUCHAR, ULONG, ULONG);
    static BCryptGenRandomPtr bcryptFn = []() -> BCryptGenRandomPtr {
        HMODULE mod = GetModuleHandleW(L"bcrypt.dll");
        if (!mod) mod = LoadLibraryW(L"bcrypt.dll");
        if (!mod) return nullptr;
        return reinterpret_cast<BCryptGenRandomPtr>(
            GetProcAddress(mod, "BCryptGenRandom"));
    }();
    constexpr ULONG BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x00000002;
    if (bcryptFn) {
        std::size_t off = 0;
        while (off < len) {
            ULONG chunk = static_cast<ULONG>(
                std::min<std::size_t>(len - off, 0xFFFFFFFFUL));
            LONG status = bcryptFn(nullptr, buf + off, chunk,
                                   BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            if (status < 0) // NTSTATUS failure
                throw std::runtime_error("BCryptGenRandom failed");
            off += chunk;
        }
        return;
    }
    // --- fallback: RtlGenRandom (SystemFunction036 in advapi32) ---
    using RtlGenRandomPtr = BOOLEAN(WINAPI*)(PVOID, ULONG);
    static RtlGenRandomPtr rtlFn = []() -> RtlGenRandomPtr {
        HMODULE mod = GetModuleHandleW(L"advapi32.dll");
        if (!mod) mod = LoadLibraryW(L"advapi32.dll");
        if (!mod) return nullptr;
        return reinterpret_cast<RtlGenRandomPtr>(
            GetProcAddress(mod, "SystemFunction036"));
    }();
    if (rtlFn) {
        std::size_t off = 0;
        while (off < len) {
            ULONG chunk = static_cast<ULONG>(
                std::min<std::size_t>(len - off, 0xFFFFFFFFUL));
            if (!rtlFn(buf + off, chunk))
                throw std::runtime_error("RtlGenRandom failed");
            off += chunk;
        }
        return;
    }
#else
    // fallback on unix-like systems: read from /dev/urandom
    std::ifstream urand("/dev/urandom", std::ios::binary);
    if (urand) {
        urand.read(reinterpret_cast<char*>(buf),
                    static_cast<std::streamsize>(len));
        if (static_cast<std::size_t>(urand.gcount()) == len) return;
    }
#endif
    throw std::runtime_error("no cryptographic random source available");
}

inline ByteVector generateSalt(std::size_t size) {
    // generate a random salt of the requested size
    // returns a byte vector filled with secure random bytes
    ByteVector salt(size);
    fillCryptoRandom(salt.data(), size); // fill salt bytes from csprng
    return salt;
}

// ---------------------------------------------------------------------------
//  secure memory helpers
// ---------------------------------------------------------------------------
// secureZero: overwrite a memory region with zeros using a volatile pointer
// to reduce the chance the compiler optimizes the wipe away.
// secureWipe: helper wrappers to clear ByteVector and std::string instances
// and shrink capacity where possible.
// lockMemory / unlockMemory: try to pin pages to avoid swapping sensitive data
// to disk; behavior depends on the underlying OS implementation.
inline void secureZero(void* p, std::size_t n) {
    if (!p || n == 0) return;
    // use volatile pointer to reduce chance compiler elides zeroing
    volatile std::uint8_t* vp = reinterpret_cast<volatile std::uint8_t*>(p);
    for (std::size_t i = 0; i < n; ++i) vp[i] = 0; // overwrite each byte with zero
}

inline void secureWipe(ByteVector& v) {
    if (!v.empty()) { secureZero(v.data(), v.size()); v.clear(); v.shrink_to_fit(); }
}

inline void secureWipe(std::string& s) {
    if (!s.empty()) { secureZero(&s[0], s.size()); s.clear(); s.shrink_to_fit(); }
}

inline bool lockMemory(void* p, std::size_t sz) {
#ifdef _WIN32
    return VirtualLock(p, static_cast<SIZE_T>(sz)) != 0; // try to pin pages on windows
#else
    return mlock(p, sz) == 0; // try to lock memory on unix-like systems
#endif
}

inline void unlockMemory(void* p, std::size_t sz) {
#ifdef _WIN32
    VirtualUnlock(p, static_cast<SIZE_T>(sz)); // release pinned pages on windows
#else
    munlock(p, sz); // release lock on unix-like systems
#endif
}

// portable aligned allocation
#if defined(_MSC_VER)
inline void* alignedAlloc(std::size_t align, std::size_t sz) {
    if (align < sizeof(void*)) align = sizeof(void*);
    return _aligned_malloc(sz, align);
}
inline void alignedFree(void* p) { if (p) _aligned_free(p); }
#elif defined(_WIN32)
// MinGW: safe manual alignment via overallocation with overflow checks
inline void* alignedAlloc(std::size_t align, std::size_t sz) {
    if (align < sizeof(void*)) align = sizeof(void*);
    // ensure alignment is a power of two
    if ((align & (align - 1)) != 0) return nullptr;
    // check for overflow before computing total allocation size
    std::size_t overhead = align + sizeof(void*);
    if (sz > SIZE_MAX - overhead) return nullptr;
    std::size_t total = sz + overhead;
    void* raw = std::malloc(total);
    if (!raw) return nullptr;
    std::uintptr_t rawAddr = reinterpret_cast<std::uintptr_t>(raw) + sizeof(void*);
    std::uintptr_t alignedAddr = (rawAddr + align - 1) & ~(align - 1);
    void** aligned = reinterpret_cast<void**>(alignedAddr);
    aligned[-1] = raw;
    return aligned;
}
inline void alignedFree(void* p) {
    if (p) std::free(reinterpret_cast<void**>(p)[-1]);
}
#else
inline void* alignedAlloc(std::size_t align, std::size_t sz) {
    if (align < sizeof(void*)) align = sizeof(void*);
    void* p = nullptr;
    if (posix_memalign(&p, align, sz) != 0) return nullptr;
    return p;
}
inline void alignedFree(void* p) { free(p); }
#endif

#if defined(__GNUC__) || defined(__clang__)
inline void prefetchRange(const void* p, std::size_t sz) {
    const char* c = static_cast<const char*>(p);
    for (std::size_t off = 0; off < sz; off += 64)
        __builtin_prefetch(c + off, 0, 3);
}
#else
inline void prefetchRange(const void*, std::size_t) {}
#endif

// raii aligned buffer with optional memory lock and guaranteed zero-on-destruct
// - constructs an aligned memory block of the requested size and alignment
// - optionally attempts to lock the pages into memory to reduce swapping
// - on destruction the buffer is zeroed, unlocked, and freed
// - throws std::bad_alloc if allocation fails
struct ScopedBuffer {
    void* ptr = nullptr;
    std::size_t size = 0;
    bool locked = false;

    ScopedBuffer(std::size_t align, std::size_t bytes, bool tryLock = false)
        : size(bytes)
    {
        ptr = alignedAlloc(align, size);
        if (!ptr) throw std::bad_alloc();
        if (tryLock) locked = lockMemory(ptr, size);
        prefetchRange(ptr, size);
    }

    ~ScopedBuffer() {
        if (ptr) {
            secureZero(ptr, size); // wipe buffer before freeing
            if (locked) unlockMemory(ptr, size); // unlock if we pinned pages
            alignedFree(ptr); // free aligned allocation
        }
    }

    ScopedBuffer(const ScopedBuffer&) = delete;
    ScopedBuffer& operator=(const ScopedBuffer&) = delete;
};

// ---------------------------------------------------------------------------
//  key schedule
// ---------------------------------------------------------------------------
// hardened key schedule holds per-round subkeys and mac seeds
// - rka, rkb, rkc: arrays of 64-bit round keys (one entry per round)
// - macSeeds: seeds used to initialize the mac computation lanes
struct HardenedKeySchedule {
    std::array<std::uint64_t, 32> rka{};
    std::array<std::uint64_t, 32> rkb{};
    std::array<std::uint64_t, 32> rkc{};
    std::array<std::uint64_t, 4>  macSeeds{};
};

// raii wiper for HardenedKeySchedule
struct ScopedKS {
    HardenedKeySchedule& ks;
    explicit ScopedKS(HardenedKeySchedule& k) : ks(k) {}
    ~ScopedKS() { secureZero(&ks, sizeof(ks)); }
    ScopedKS(const ScopedKS&) = delete;
    ScopedKS& operator=(const ScopedKS&) = delete;
};

// memory-hard key derivation
// derive a hardened key schedule from a password and a salt.
// phases:
// - phase 1: mix password and salt into a small internal state.
// - phase 2: expand that state into a large scratch buffer to consume memory.
// - phase 3: run many iterations of memory-hard mixing to slow down attackers.
// - phase 4: extract round keys and mac seeds into the returned schedule.
// sensitive intermediate state is zeroed before returning.
HardenedKeySchedule deriveHardenedSchedule(const std::string& pass,
                                           const ByteVector& salt)
{
    // phase 1: initial state from password + salt
    std::array<std::uint64_t, 8> st = {{
        0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL,
        0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
        0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
        0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL
    }};

    auto stir = [&](std::uint8_t byte, std::size_t idx) {
        st[idx & 7] ^= static_cast<std::uint64_t>(byte) * 0x9E3779B185EBCA87ULL;
        st[idx & 7] = rotl64(st[idx & 7], 11U) + st[(idx + 1U) & 7U];
        st[(idx + 3U) & 7U] ^= st[idx & 7];
    };

    stir(static_cast<std::uint8_t>(pass.size() & 0xFFU), 0);
    stir(static_cast<std::uint8_t>((pass.size() >> 8U) & 0xFFU), 1);
    stir(static_cast<std::uint8_t>(salt.size() & 0xFFU), 2);
    stir(static_cast<std::uint8_t>((salt.size() >> 8U) & 0xFFU), 3);

    for (std::size_t i = 0; i < pass.size(); ++i)
        stir(static_cast<std::uint8_t>(pass[i]), i + 4U); // mix each password byte into state
    for (std::size_t i = 0; i < salt.size(); ++i)
        stir(salt[i], i + pass.size() + 4U); // mix each salt byte into state

    for (int p = 0; p < 3; ++p)
        for (int j = 0; j < 8; ++j) {
            st[j] ^= rotl64(st[(j + 1) & 7], 17U) + 0xC2B2AE3D27D4EB4FULL;
            st[j] = rotl64(st[j], static_cast<unsigned>((j * 7 + 5) % 64));
        }

    // phase 2: expand into scratch buffer
    // clamp to a sane upper bound (2 GiB) to prevent OOM from misconfiguration
    constexpr std::size_t kKdfMemMax = std::size_t{2} * 1024 * 1024 * 1024;
    std::size_t rawMem = gKdfMemoryBytes;
    if (rawMem > kKdfMemMax) rawMem = kKdfMemMax;
    std::size_t memBytes = (rawMem / 8U) * 8U;
    const std::size_t words = memBytes / 8U;
    if (words <= 8U) throw std::invalid_argument("KDF memory too small");

    const char* lockEnv = std::getenv("THERAPIST_KDF_MLOCK");
    bool tryLock = lockEnv && lockEnv[0] != '\0';

    ScopedBuffer scratch(64, memBytes, tryLock);
    std::uint64_t* mem = static_cast<std::uint64_t*>(scratch.ptr);

    {
        // spread initial state across the scratch memory to consume kdf memory
        // this writes evolving state words into the scratch buffer
        std::size_t p = 0;
        for (std::size_t i = 0; i < words; ++i) {
            st[p & 7U] = rotl64(st[p & 7U], 17U) ^ st[(p + 3U) & 7U];
            st[p & 7U] += 0xC2B2AE3D27D4EB4FULL;
            mem[i] = st[p & 7U]; // store evolving state word into scratch
            ++p;
        }
    }

    // phase 3: memory-hard mixing
    for (std::size_t iter = 0; iter < gKdfIterations; ++iter) {
        std::size_t idx = static_cast<std::size_t>(st[iter & 7U] % (words - 8U));
        for (int j = 0; j < 8; ++j) {
            std::uint64_t mv = mem[idx + static_cast<std::size_t>(j)];
            st[j] ^= mv;
            st[j] = rotl64(st[j],
                static_cast<unsigned>((iter + static_cast<std::size_t>(j)) * 7U + 5U) % 64U);
            st[j] += st[(j + 1) & 7] ^ 0x9E3779B97F4A7C15ULL;
            mem[idx + static_cast<std::size_t>(j)] = st[j];
        }
    }

    // phase 4: extract round keys
    HardenedKeySchedule ks{};
    for (std::size_t r = 0; r < kRounds; ++r) {
        st[r & 7U] ^= rotl64(st[(r + 1U) & 7U], 23U) +
                       (r + 1U) * 0x9E3779B97F4A7C15ULL;
        st[r & 7U] = rotl64(st[r & 7U],
                             static_cast<unsigned>((r * 5U + 17U) % 64U));
        ks.rka[r] = st[r & 7U];

        st[(r + 3U) & 7U] ^= st[r & 7U] + 0xC6BC279692B5CC83ULL;
        st[(r + 3U) & 7U] = rotl64(st[(r + 3U) & 7U],
                                    static_cast<unsigned>((r * 11U + 29U) % 64U));
        ks.rkb[r] = st[(r + 3U) & 7U];

        st[(r + 5U) & 7U] ^= st[(r + 3U) & 7U] * 0x517CC1B727220A95ULL;
        st[(r + 5U) & 7U] = rotl64(st[(r + 5U) & 7U],
                                    static_cast<unsigned>((r * 7U + 13U) % 64U));
        ks.rkc[r] = st[(r + 5U) & 7U];
    }

    for (int i = 0; i < 4; ++i) {
        st[i] ^= st[i + 4] + 0x2718281828459045ULL;
        ks.macSeeds[i] = st[i];
    }

    secureZero(st.data(), sizeof(st));
    return ks;
}

// ---------------------------------------------------------------------------
//  block cipher
// ---------------------------------------------------------------------------
// enhanced round function for the block cipher.
// - input: a 64-bit half-block and three round keys.
// - operations: s-box substitution, rotations, nonlinear mixing, key adds.
// - goal: provide diffusion and confusion inside each round.
inline std::uint64_t enhancedRoundFunction(std::uint64_t half,
                                           std::uint64_t keyA,
                                           std::uint64_t keyB,
                                           std::uint64_t keyC)
{
    const auto& sb = sbox();
    half ^= keyA; // xor with round key a
    half = applySBoxToWord(half, sb); // non-linear byte substitution
    half = rotl64(half, 19U); // rotate for diffusion
    half += keyB; // add round key b
    half ^= rotl64(half, 41U); // rotate and xor for mixing
    half *= 0xD6E8FEB86659CDD9ULL; // nonlinear multiply to spread bits
    half ^= (half >> 33U); // xor top with shifted bottom for avalanche
    half = applySBoxToWord(half ^ keyC, sb); // s-box after xor with key c
    half = rotl64(half, 13U) ^ rotl64(half, 29U); // dual rotations and xor
    half += keyA ^ keyC; // fold keys back in
    half ^= (half >> 37U); // final xor/shift mixing
    return half;
}

// encrypt a single 128-bit block in-place (two 64-bit halves: L, R)
// - initial whitening uses kWhitenA and kWhitenB to mix key material.
// - the main loop runs kRounds rounds of the round function; each round
//   is a feistel-like round that mixes the halves using enhancedRoundFunction.
// - final whitening is applied after the rounds.
inline void encryptBlock(std::uint64_t& L, std::uint64_t& R,
                           const HardenedKeySchedule& ks)
{
    // initial whitening - xor inputs with first-round keys and whiten constants
    L ^= ks.rka[0] ^ kWhitenA;
    R ^= ks.rkb[0] ^ kWhitenB;
    for (std::size_t r = 0; r < kRounds; ++r) {
        // feistel round: compute f based on right half and round keys
        std::uint64_t f = enhancedRoundFunction(R, ks.rka[r], ks.rkb[r], ks.rkc[r]);
        std::uint64_t nL = R; // save current right as new left
        R = L ^ f; // new right is left xor f(right)
        L = nL; // rotate halves
    }
    // final whitening - mix in last round keys and swap whiten constants
    L ^= ks.rka[kRounds - 1] ^ kWhitenB;
    R ^= ks.rkb[kRounds - 1] ^ kWhitenA;
}

// ---------------------------------------------------------------------------
//  ctr mode cipher (symmetric - encrypt = decrypt)
// ---------------------------------------------------------------------------
// initialize a 128-bit counter from the given salt
// - uses a deterministic mixing of salt bytes into two 64-bit words
// - result is used as the initial ctr value for ctr mode keystream generation
inline std::array<std::uint8_t, kBlockSize> initCtrFromSalt(const ByteVector& salt) {
    std::array<std::uint8_t, kBlockSize> ctr{};
    // starting mix seeds for ctr initialization
    std::uint64_t sL = 0x6A09E667F3BCC909ULL;
    std::uint64_t sR = 0xBB67AE8584CAA73BULL;
    for (std::size_t i = 0; i < salt.size(); ++i) {
        // mix salt byte into sL using byte shifts and a small rotation
        sL ^= static_cast<std::uint64_t>(salt[i]) << ((i % 8U) * 8U);
        sL = rotl64(sL, 9U);
        // mix salt byte into sR using an offset to decorrelate lanes
        sR ^= static_cast<std::uint64_t>(salt[i]) << (((i + 3U) % 8U) * 8U);
        sR = rotl64(sR, 13U);
    }
    // write the two 64-bit words into the 128-bit counter (little-endian)
    store64LE(ctr.data(), sL);
    store64LE(ctr.data() + 8, sR);
    return ctr;
}

void applyCipher(const ByteVector& in, ByteVector& out,
                 const HardenedKeySchedule& ks,
                 const ByteVector& salt)
{
    // apply stream cipher generated from block cipher in ctr mode.
    // - ctr is initialized deterministically from the salt so encryption is
    //   repeatable for the same salt and key schedule.
    // - encrypt and decrypt are the same operation in ctr mode: xor with keystream.
    // - keystream blocks are produced by encryptBlock applied to the counter.
    out.resize(in.size());
    auto ctr = initCtrFromSalt(salt);
    std::array<std::uint8_t, kBlockSize> ksBuf{};
    std::size_t off = 0;
    while (off < in.size()) {
        std::uint64_t l = load64LE(ctr.data());
        std::uint64_t r = load64LE(ctr.data() + 8);
        encryptBlock(l, r, ks); // produce one keystream block by encrypting ctr
        store64LE(ksBuf.data(), l); // store keystream low 64 bits
        store64LE(ksBuf.data() + 8, r); // store keystream high 64 bits
        std::size_t chunk = std::min<std::size_t>(kBlockSize, in.size() - off); // bytes to process this iteration
        const std::size_t fullWords = chunk / 8;
        for (std::size_t j = 0; j < fullWords; ++j) {
            std::uint64_t win = 0, ksw = 0;
            std::memcpy(&win, in.data() + off + j * 8, 8);
            std::memcpy(&ksw, ksBuf.data() + j * 8, 8);
            win ^= ksw;
            std::memcpy(out.data() + off + j * 8, &win, 8);
        }
        for (std::size_t i = fullWords * 8; i < chunk; ++i)
            out[off + i] = static_cast<std::uint8_t>(in[off + i] ^ ksBuf[i]);
        incrementCounter(ctr);
        off += chunk;
    }
}

// ---------------------------------------------------------------------------
//  256-bit cascaded mac
// ---------------------------------------------------------------------------
struct Mac256 { std::uint64_t h[4]; };

// constant-time comparison for mac values to reduce timing leakage
inline bool constantTimeMacEq(const Mac256& a, const Mac256& b) {
    volatile std::uint64_t diff = 0;
    diff |= a.h[0] ^ b.h[0];
    diff |= a.h[1] ^ b.h[1];
    diff |= a.h[2] ^ b.h[2];
    diff |= a.h[3] ^ b.h[3];
    return diff == 0;
}

namespace {
    constexpr std::uint64_t kMacPrimes[4] = {
        0x100000001B3ULL, 0x1000000016FULL,
        0x10000000233ULL, 0x10000000259ULL
    };

    // feed a single byte into the mac state
    // the state is 4 x 64-bit lanes, each mixed with different primes
    inline void macFeedByte(Mac256& mac, std::uint8_t byte) {
        for (int i = 0; i < 4; ++i) {
            mac.h[i] ^= byte; // xor incoming byte into lane i
            mac.h[i] *= kMacPrimes[i]; // multiply by lane prime to scramble
            mac.h[i] ^= (mac.h[i] >> 33U); // xor with shifted bits for diffusion
        }
        // cross-mix lanes to increase avalanche between the 4 words
        mac.h[0] ^= rotl64(mac.h[3], 7U);
        mac.h[1] ^= rotl64(mac.h[0], 11U);
        mac.h[2] ^= rotl64(mac.h[1], 17U);
        mac.h[3] ^= rotl64(mac.h[2], 23U);
    }

    // feed a contiguous buffer into the mac
    inline void macFeedBuffer(Mac256& mac, const std::uint8_t* buf, std::size_t len) {
        for (std::size_t i = 0; i < len; ++i)
            macFeedByte(mac, buf[i]);
    }

    // initialize mac state from password, two salts and plaintext length
    // this establishes the starting state before feeding the plaintext bytes
    inline Mac256 macInit(const std::string& pass,
                          const ByteVector& salt1,
                          const ByteVector& salt2,
                          std::uint32_t plainSize)
    {
        Mac256 mac;
        mac.h[0] = 0xCBF29CE484222325ULL;
        mac.h[1] = 0x6C62272E07BB0142ULL;
        mac.h[2] = 0xAF63BD4C8601B7DFULL;
        mac.h[3] = 0x340E1D2B2C67F689ULL;

        macFeedByte(mac, static_cast<std::uint8_t>(pass.size() & 0xFFU));
        macFeedByte(mac, static_cast<std::uint8_t>((pass.size() >> 8U) & 0xFFU));
        for (unsigned char ch : pass) macFeedByte(mac, static_cast<std::uint8_t>(ch)); // include password bytes in mac
        for (std::uint8_t b : salt1) macFeedByte(mac, b);
        macFeedByte(mac, 0xFFU);
        for (std::uint8_t b : salt2) macFeedByte(mac, b);
        macFeedByte(mac, 0xFEU);
        macFeedByte(mac, static_cast<std::uint8_t>(plainSize & 0xFFU));
        macFeedByte(mac, static_cast<std::uint8_t>((plainSize >> 8U) & 0xFFU));
        macFeedByte(mac, static_cast<std::uint8_t>((plainSize >> 16U) & 0xFFU));
        macFeedByte(mac, static_cast<std::uint8_t>((plainSize >> 24U) & 0xFFU));
        return mac;
    }

    inline void macFinalize(Mac256& mac) {
        for (int round = 0; round < 8; ++round)
            for (int i = 0; i < 4; ++i) {
                mac.h[i] ^= rotl64(mac.h[(i + 1) & 3], 19U); // mix in neighbor lanes
                mac.h[i] *= kMacPrimes[i]; // multiply by lane-specific prime
                mac.h[i] ^= (mac.h[i] >> 29U); // xor with shifted value for further mixing
            }
    }
} // anon

Mac256 computeHardenedMac(const ByteVector& plain,
                          const std::string& pass,
                          const ByteVector& salt1,
                          const ByteVector& salt2)
{
    Mac256 mac = macInit(pass, salt1, salt2, static_cast<std::uint32_t>(plain.size()));
    if (!plain.empty()) macFeedBuffer(mac, plain.data(), plain.size());
    macFinalize(mac);
    return mac;
}

// ---------------------------------------------------------------------------
//  chaff + metadata helpers
// ---------------------------------------------------------------------------
struct FileMetadata {
    std::string originalName;
    std::string date; // "dd-mm-yyyy"
};

// current date as "dd-mm-yyyy"
inline std::string currentDateString() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
#if defined(_MSC_VER)
    localtime_s(&tm, &t);
#else
    if (std::tm* tmp = std::localtime(&t)) tm = *tmp;
#endif
#else
    localtime_r(&t, &tm);
#endif
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%02d-%02d-%04d",
                  tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900);
    return std::string(buf, kDateLen);
}

// build augmented payload: chaff + metadata + plaintext (v6)
// layout (in order):
// - 2-byte little-endian chaff length, then chaff bytes
// - 2-byte little-endian name length, then name bytes
// - fixed-length date field (kDateLen bytes)
// - plaintext bytes
// chaff length is chosen from gSettings.chaffMin..chaffMax using secure randomness
ByteVector buildAugmentedV6(const ByteVector& plain, const FileMetadata& meta) {
    std::uint8_t rndByte[1];
    fillCryptoRandom(rndByte, 1); // one random byte used to pick chaff length
    std::size_t chMin = gSettings.chaffMin;
    std::size_t chMax = gSettings.chaffMax;
    if (chMin > chMax) std::swap(chMin, chMax);
    if (chMax == 0) chMax = 1;
    std::size_t chaffLen = chMin +
        (static_cast<std::size_t>(rndByte[0]) % (chMax - chMin + 1));

    // truncate name if needed
    std::string name = meta.originalName;
    if (name.size() > 0xFFFF) name.resize(0xFFFF);
    std::string date = meta.date;
    if (date.size() < kDateLen) date.resize(kDateLen, '0');
    if (date.size() > kDateLen) date.resize(kDateLen);

    ByteVector aug;
    aug.reserve(2 + chaffLen + 2 + name.size() + kDateLen + plain.size());

    // chaff header (2-byte LE length) + random chaff
    aug.push_back(static_cast<std::uint8_t>(chaffLen & 0xFFU)); // chaff len low byte
    aug.push_back(static_cast<std::uint8_t>((chaffLen >> 8U) & 0xFFU)); // chaff len high byte
    aug.resize(2 + chaffLen);
    fillCryptoRandom(aug.data() + 2, chaffLen); // fill chaff bytes with secure random data

    // metadata: name length (2-byte LE) + name + date
    std::size_t nl = name.size();
    aug.push_back(static_cast<std::uint8_t>(nl & 0xFFU));
    aug.push_back(static_cast<std::uint8_t>((nl >> 8U) & 0xFFU));
    aug.insert(aug.end(), name.begin(), name.end());
    aug.insert(aug.end(), date.begin(), date.end());

    // plaintext
    aug.insert(aug.end(), plain.begin(), plain.end());
    return aug;
}

// parse v6 augmented payload: extract metadata and plaintext
// performs bounds checks on chaff and metadata to detect corruption or wrong passphrase
ByteVector parseAugmentedV6(const ByteVector& aug, FileMetadata& meta) {
    if (aug.size() < 2)
        throw std::runtime_error("authentication failed: wrong passphrase or corrupted data");

    // read chaff (16-bit little-endian length)
    std::size_t chaffLen = static_cast<std::size_t>(aug[0]) |
                           (static_cast<std::size_t>(aug[1]) << 8U);
    if (chaffLen > 1024 || 2 + chaffLen > aug.size())
        throw std::runtime_error("authentication failed: wrong passphrase or corrupted data");

    std::size_t pos = 2 + chaffLen;

    // read metadata
    if (pos + 2 > aug.size())
        throw std::runtime_error("authentication failed: wrong passphrase or corrupted data");
    std::size_t nameLen = static_cast<std::size_t>(aug[pos]) |
                          (static_cast<std::size_t>(aug[pos + 1]) << 8U);
    pos += 2;

    if (pos + nameLen + kDateLen > aug.size())
        throw std::runtime_error("authentication failed: wrong passphrase or corrupted data");

    meta.originalName.assign(aug.begin() + pos, aug.begin() + pos + nameLen);
    pos += nameLen;
    meta.date.assign(aug.begin() + pos, aug.begin() + pos + kDateLen);
    pos += kDateLen;

    return ByteVector(aug.begin() + pos, aug.end());
}



// ---------------------------------------------------------------------------
//  encrypt / decrypt payloads
// ---------------------------------------------------------------------------
struct DecryptResult {
    ByteVector plaintext;
    FileMetadata meta; // populated for V6
    std::uint8_t version = 0;
};

// always encrypts as v6 (with embedded filename and date)
// process:
// - generate two independent salts
// - build augmented payload (chaff + metadata + plaintext)
// - derive ks1 from passphrase and salt1 and encrypt the augmented payload
// - derive ks2 from passphrase and salt2 and encrypt pass1 to produce ciphertext
// - compute mac over the original plaintext and both salts
// - assemble output: magic(4) + version(1) + saltLen(1) + macLen(1) + salt1 + salt2 + mac + ciphertext
ByteVector encryptPayload(const ByteVector& plain,
                          const std::string& passphrase,
                          const FileMetadata& meta)
{
    ByteVector salt1 = generateSalt(kSaltSize); // salt for first encryption pass
    ByteVector salt2 = generateSalt(kSaltSize); // salt for second encryption pass

    ByteVector augmented = buildAugmentedV6(plain, meta);

    // first encryption pass: augmented -> pass1
    auto ks1 = deriveHardenedSchedule(passphrase, salt1);
    ScopedKS w1(ks1);
    ByteVector pass1;
    applyCipher(augmented, pass1, ks1, salt1);

    // second encryption pass: pass1 -> pass2
    auto ks2 = deriveHardenedSchedule(passphrase, salt2);
    ScopedKS w2(ks2);
    ByteVector pass2;
    applyCipher(pass1, pass2, ks2, salt2);

    // MAC over original plaintext
    Mac256 mac = computeHardenedMac(plain, passphrase, salt1, salt2);

    // assemble output bytes in order: magic, version, saltLen, macLen, salt1, salt2, mac, ciphertext
    ByteVector output;
    output.reserve(4 + 3 + kSaltSize * 2 + kMacSize + pass2.size());
    output.insert(output.end(), kMagicV6.begin(), kMagicV6.end());
    output.push_back(kVersionV6);
    output.push_back(static_cast<std::uint8_t>(kSaltSize));
    output.push_back(static_cast<std::uint8_t>(kMacSize));
    output.insert(output.end(), salt1.begin(), salt1.end());
    output.insert(output.end(), salt2.begin(), salt2.end());
    for (int i = 0; i < 4; ++i)
        for (int shift = 56; shift >= 0; shift -= 8)
            output.push_back(static_cast<std::uint8_t>((mac.h[i] >> shift) & 0xFFU));
    output.insert(output.end(), pass2.begin(), pass2.end());

    secureWipe(augmented);
    secureWipe(pass1);
    secureWipe(pass2);
    return output;
}

// auto-detect payload format; returns plaintext and metadata (v6 only)
// decrypt flow:
// - validate header and version
// - extract salt lengths, mac length, salts and stored mac
// - reverse double encryption using ks2 then ks1
// - parse augmented payload to recover metadata and plaintext
// - verify mac over recovered plaintext and salts using constant-time compare
// - throw on any validation or authentication failure
DecryptResult decryptPayload(const ByteVector& input,
                             const std::string& passphrase)
{
    const std::size_t baseHdr = 4 + 3; // magic(4) + version(1) + saltLen(1) + macLen(1)
    if (input.size() < baseHdr)
        throw std::invalid_argument("encrypted data is too short");

    // detect version (only v6 supported)
    bool isV6 = std::equal(kMagicV6.begin(), kMagicV6.end(), input.begin());
    if (!isV6) {
        if (input.size() >= 4 &&
            input[0] == 'T' && input[1] == 'P' && input[2] == 'C' &&
            std::isdigit(static_cast<unsigned char>(input[3])) != 0 &&
            static_cast<std::uint8_t>(input[3] - '0') > kVersionV6) {
            throw std::runtime_error(
                "encrypted data uses a newer format; this program is outdated, "
                "please download the latest for flawless usage");
        }
        throw std::runtime_error("encrypted data header mismatch");
    }

    std::uint8_t version = input[4]; // version byte from header
    if (version != kVersionV6) {
        if (version > kVersionV6) {
            throw std::runtime_error(
                "encrypted data uses a newer format; this program is outdated, "
                "please download the latest for flawless usage");
        }
        throw std::runtime_error("unsupported encrypted data version");
    }

    std::uint8_t saltLen = input[5]; // length of each salt in bytes
    std::uint8_t macLen  = input[6]; // length of mac in bytes
    if (saltLen == 0 || macLen == 0 || macLen != kMacSize)
        throw std::runtime_error("corrupted encrypted data header");

    std::size_t totalHdr = baseHdr + static_cast<std::size_t>(saltLen) * 2U +
                           static_cast<std::size_t>(macLen);
    if (input.size() < totalHdr)
        throw std::runtime_error("encrypted data truncated");

    ByteVector salt1(input.begin() + baseHdr,
                     input.begin() + baseHdr + saltLen);
    ByteVector salt2(input.begin() + baseHdr + saltLen,
                     input.begin() + baseHdr + saltLen * 2);

    Mac256 storedMac{};
    std::size_t macOff = baseHdr + static_cast<std::size_t>(saltLen) * 2U;
    for (int i = 0; i < 4; ++i) {
        storedMac.h[i] = 0;
        for (int j = 0; j < 8; ++j)
            storedMac.h[i] = (storedMac.h[i] << 8U) |
                static_cast<std::uint64_t>(input[macOff + static_cast<std::size_t>(i) * 8U +
                                           static_cast<std::size_t>(j)]);
    }

    ByteVector cipher(input.begin() + totalHdr, input.end());

    // reverse double encryption: undo pass 2, then pass 1
    auto ks2 = deriveHardenedSchedule(passphrase, salt2);
    ScopedKS w2(ks2);
    ByteVector pass1;
    applyCipher(cipher, pass1, ks2, salt2);

    auto ks1 = deriveHardenedSchedule(passphrase, salt1);
    ScopedKS w1(ks1);
    ByteVector augmented;
    applyCipher(pass1, augmented, ks1, salt1);

    // parse augmented and extract plaintext
    DecryptResult result;
    result.version = version;
    result.plaintext = parseAugmentedV6(augmented, result.meta);

    // verify MAC
    Mac256 computed = computeHardenedMac(result.plaintext, passphrase, salt1, salt2);
    if (!constantTimeMacEq(computed, storedMac))
        throw std::runtime_error("authentication failed: wrong passphrase or corrupted data");

    secureWipe(pass1);
    secureWipe(augmented);
    return result;
}

// ---------------------------------------------------------------------------
//  file i/o
// ---------------------------------------------------------------------------
// read and write utilities for binary files
// - readBinaryFile: read entire file into a ByteVector, works with unknown sizes
// - writeBinaryFile: write a ByteVector to disk, truncating the target file
// both functions throw std::runtime_error on failure
ByteVector readBinaryFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("unable to open file: " + path);
    f.seekg(0, std::ios::end);
    std::streamoff sz = f.tellg();
    if (sz < 0) {
        f.clear();
        f.seekg(0, std::ios::beg);
        return ByteVector{std::istreambuf_iterator<char>(f),
                          std::istreambuf_iterator<char>()};
    }
    f.seekg(0, std::ios::beg);
    // preallocate a buffer of the file size and read into it
    ByteVector data(static_cast<std::size_t>(sz));
    if (!data.empty()) {
        f.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (static_cast<std::size_t>(f.gcount()) != data.size())
            throw std::runtime_error("failed to read file: " + path);
    }
    return data;
}

void writeBinaryFile(const std::string& path, const ByteVector& data) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) throw std::runtime_error("unable to open output file: " + path);
    // write all bytes from the vector to the file (truncating existing file)
    f.write(reinterpret_cast<const char*>(data.data()),
            static_cast<std::streamsize>(data.size()));
    if (!f) throw std::runtime_error("failed to write file: " + path);
}

// set creation/modification timestamps for encrypted outputs to 02/08/2009
void setEncryptedFileTimestamps(const std::string& path) {
#ifdef _WIN32
    HANDLE h = CreateFileA(path.c_str(), FILE_WRITE_ATTRIBUTES,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    SYSTEMTIME st{};
    st.wYear = 2009; st.wMonth = 8; st.wDay = 2;
    st.wHour = 0; st.wMinute = 0; st.wSecond = 0; st.wMilliseconds = 0;
    FILETIME ft;
    if (SystemTimeToFileTime(&st, &ft)) {
        // set creation, access and write times to the same value
        SetFileTime(h, &ft, &ft, &ft);
    }
    CloseHandle(h);
#else
    struct tm tm{};
    tm.tm_year = 2009 - 1900;
    tm.tm_mon  = 8 - 1;
    tm.tm_mday = 2;
    tm.tm_hour = 0; tm.tm_min = 0; tm.tm_sec = 0;
    time_t t = mktime(&tm);
    if (t != (time_t)-1) {
        struct utimbuf timesp;
        timesp.actime = t;
        timesp.modtime = t;
        utime(path.c_str(), &timesp);
    }
#endif
}

bool fileExists(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    return static_cast<bool>(f);
}

std::string extractFilename(const std::string& path) {
    auto pos = path.find_last_of("\\/");
    if (pos != std::string::npos) return path.substr(pos + 1);
    return path;
}

std::string buildEncryptedPath(const std::string& inputPath) {
    return inputPath + ".encrypted";
}

std::string buildDecryptedPath(const std::string& inputPath,
                               const std::string& originalName)
{
    // prefer original name from metadata (sanitize to prevent path traversal)
    if (!originalName.empty()) {
        std::string safeName = originalName;
        auto slashPos = safeName.find_last_of("\\/");
        if (slashPos != std::string::npos)
            safeName = safeName.substr(slashPos + 1);
        if (safeName.empty() || safeName == "." || safeName == "..")
            safeName = "decrypted_output";
        // resolve into same directory as input
        auto pos = inputPath.find_last_of("\\/");
        if (pos != std::string::npos)
            return inputPath.substr(0, pos + 1) + safeName;
        return safeName;
    }
    // fallback: strip .encrypted
    if (inputPath.size() > 10 &&
        inputPath.substr(inputPath.size() - 10) == ".encrypted")
        return inputPath.substr(0, inputPath.size() - 10);
    // also handle legacy .encrypt extension
    if (inputPath.size() > 8 &&
        inputPath.substr(inputPath.size() - 8) == ".encrypt")
        return inputPath.substr(0, inputPath.size() - 8);
    return inputPath + ".decrypted";
}

std::string executableDirectory(int argc, char* argv[]) {
#ifdef _WIN32
    char buf[MAX_PATH];
    DWORD len = GetModuleFileNameA(nullptr, buf, static_cast<DWORD>(sizeof(buf)));
    if (len > 0 && len < sizeof(buf)) {
        std::string p(buf, len);
        auto pos = p.find_last_of("\\/");
        if (pos != std::string::npos) return p.substr(0, pos);
    }
#endif
    if (argc > 0 && argv[0]) {
        std::string p(argv[0]);
        auto pos = p.find_last_of("\\/");
        if (pos != std::string::npos) return p.substr(0, pos);
    }
    return ".";
}

bool isAbsolutePath(const std::string& p) {
    if (p.empty()) return false;
#ifdef _WIN32
    if (p.size() > 2 && std::isalpha(static_cast<unsigned char>(p[0])) &&
        p[1] == ':' && (p[2] == '\\' || p[2] == '/'))
        return true;
    if (p.size() > 1 && p[0] == '\\' && p[1] == '\\') return true;
#endif
    return p[0] == '/';
}

std::string joinPath(const std::string& dir, const std::string& name) {
    if (dir.empty() || dir == ".") return name;
    char last = dir.back();
    if (last == '/' || last == '\\') return dir + name;
#ifdef _WIN32
    return dir + "\\" + name;
#else
    return dir + "/" + name;
#endif
}

std::string resolveRelativeToExe(const std::string& exeDir,
                                 const std::string& userPath) {
    if (isAbsolutePath(userPath)) return userPath;
    return joinPath(exeDir, userPath);
}

std::string trimCopy(const std::string& text) {
    auto b = text.begin(), e = text.end();
    while (b != e && std::isspace(static_cast<unsigned char>(*b))) ++b;
    while (e != b && std::isspace(static_cast<unsigned char>(*(e - 1)))) --e;
    return std::string(b, e);
}

#ifdef _WIN32
std::wstring utf8ToWide(const std::string& text) {
    if (text.empty()) return std::wstring();
    int length = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, nullptr, 0);
    if (length <= 0) {
        return std::wstring(text.begin(), text.end());
    }
    std::wstring wide(static_cast<std::size_t>(length - 1), L'\0');
    if (!wide.empty()) {
        MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, &wide[0], length);
    }
    return wide;
}
#endif

bool parseAppVersionText(const std::string& text, AppVersion& version) {
    std::string cleaned = trimCopy(text);
    if (cleaned.empty()) return false;
    // accept leading 'v' or 'V' (strip if present)
    if (cleaned[0] == 'v' || cleaned[0] == 'V')
        cleaned.erase(cleaned.begin());

    // parse format: MAJOR.MINOR.PATCH[pre-release]
    // parse major.minor.patch numeric fields
    const char* s = cleaned.c_str();
    char* tail = nullptr;
    long maj = std::strtol(s, &tail, 10);
    if (tail == s || *tail != '.') return false;
    s = tail + 1;
    long min = std::strtol(s, &tail, 10);
    if (tail == s || *tail != '.') return false;
    s = tail + 1;
    long pat = std::strtol(s, &tail, 10);
    if (tail == s) return false;

    // optional pre-release label follows the numeric parts
    std::string pre;
    if (*tail != '\0') {
        pre = std::string(tail);
        // strip leading '-' or '+' if present to normalize label
        if (!pre.empty() && (pre[0] == '-' || pre[0] == '+')) pre.erase(pre.begin());
        pre = trimCopy(pre);
    }

    if (maj < 0 || min < 0 || pat < 0) return false;
    version.major = static_cast<int>(maj);
    version.minor = static_cast<int>(min);
    version.patch = static_cast<int>(pat);
    version.preRelease = pre;
    return true;
}

bool parseVersionFileText(const std::string& body,
                          AppVersion& latestVersion,
                          std::string& downloadUrl)
{
    std::istringstream input(body);
    std::string versionLine;
    if (!std::getline(input, versionLine))
        return false;
    if (!parseAppVersionText(versionLine, latestVersion))
        return false;

    std::string urlLine;
    if (std::getline(input, urlLine))
        downloadUrl = trimCopy(urlLine);
    else
        downloadUrl.clear();

    if (downloadUrl.empty())
        downloadUrl = kDefaultReleaseUrl;
    return true;
}

std::string getVersionInfoUrl() {
    const char* env = std::getenv("THERAPIST_VERSION_URL");
    if (env && env[0] != '\0')
        return trimCopy(env);
    return kDefaultVersionInfoUrl;
}

#ifdef _WIN32
struct WinHttpApi {
    HMODULE module = nullptr;
    WinHttpOpenFn open = nullptr;
    WinHttpConnectFn connect = nullptr;
    WinHttpOpenRequestFn openRequest = nullptr;
    WinHttpSetTimeoutsFn setTimeouts = nullptr;
    WinHttpSendRequestFn sendRequest = nullptr;
    WinHttpReceiveResponseFn receiveResponse = nullptr;
    WinHttpQueryHeadersFn queryHeaders = nullptr;
    WinHttpQueryDataAvailableFn queryDataAvailable = nullptr;
    WinHttpReadDataFn readData = nullptr;
    WinHttpCloseHandleFn closeHandle = nullptr;

    bool load() {
        if (module) return true;
        module = LoadLibraryW(L"winhttp.dll");
        if (!module) return false;

        open = reinterpret_cast<WinHttpOpenFn>(GetProcAddress(module, "WinHttpOpen"));
        connect = reinterpret_cast<WinHttpConnectFn>(GetProcAddress(module, "WinHttpConnect"));
        openRequest = reinterpret_cast<WinHttpOpenRequestFn>(GetProcAddress(module, "WinHttpOpenRequest"));
        setTimeouts = reinterpret_cast<WinHttpSetTimeoutsFn>(GetProcAddress(module, "WinHttpSetTimeouts"));
        sendRequest = reinterpret_cast<WinHttpSendRequestFn>(GetProcAddress(module, "WinHttpSendRequest"));
        receiveResponse = reinterpret_cast<WinHttpReceiveResponseFn>(GetProcAddress(module, "WinHttpReceiveResponse"));
        queryHeaders = reinterpret_cast<WinHttpQueryHeadersFn>(GetProcAddress(module, "WinHttpQueryHeaders"));
        queryDataAvailable = reinterpret_cast<WinHttpQueryDataAvailableFn>(GetProcAddress(module, "WinHttpQueryDataAvailable"));
        readData = reinterpret_cast<WinHttpReadDataFn>(GetProcAddress(module, "WinHttpReadData"));
        closeHandle = reinterpret_cast<WinHttpCloseHandleFn>(GetProcAddress(module, "WinHttpCloseHandle"));

        if (open && connect && openRequest && setTimeouts && sendRequest &&
            receiveResponse && queryHeaders && queryDataAvailable && readData && closeHandle) {
            return true;
        }

        FreeLibrary(module);
        module = nullptr;
        open = nullptr;
        connect = nullptr;
        openRequest = nullptr;
        setTimeouts = nullptr;
        sendRequest = nullptr;
        receiveResponse = nullptr;
        queryHeaders = nullptr;
        queryDataAvailable = nullptr;
        readData = nullptr;
        closeHandle = nullptr;
        return false;
    }
};

bool parseHttpsUrlParts(const std::string& url,
                        std::wstring& host,
                        INTERNET_PORT& port,
                        std::wstring& path)
{
    const std::string prefix = "https://";
    // must start with "https://" otherwise reject
    if (url.rfind(prefix, 0) != 0)
        return false;

    std::string remainder = url.substr(prefix.size());
    // split into host[:port] and path parts
    std::size_t slashPos = remainder.find('/');
    std::string hostPort = slashPos == std::string::npos
        ? remainder
        : remainder.substr(0, slashPos);
    std::string pathPart = slashPos == std::string::npos
        ? "/"
        : remainder.substr(slashPos);
    if (hostPort.empty())
        return false;

    port = kInternetDefaultHttpsPort;
    std::size_t colonPos = hostPort.rfind(':');
    // optional :port suffix handling
    if (colonPos != std::string::npos) {
        std::string portText = hostPort.substr(colonPos + 1);
        hostPort = hostPort.substr(0, colonPos);
        if (hostPort.empty() || portText.empty())
            return false;
        try {
            unsigned long parsedPort = std::stoul(portText);
            if (parsedPort == 0 || parsedPort > 65535UL)
                return false;
            port = static_cast<INTERNET_PORT>(parsedPort);
        } catch (...) {
            return false;
        }
    }

    if (hostPort.empty())
        return false;

    host.assign(hostPort.begin(), hostPort.end());
    path.assign(pathPart.begin(), pathPart.end());
    return true;
}

bool fetchHttpsTextWinHttp(const std::string& url,
                           std::string& body,
                           std::string& error)
{
    std::wstring host;
    std::wstring path;
    INTERNET_PORT port = kInternetDefaultHttpsPort;
    // parse url into host, port and path parts
    if (!parseHttpsUrlParts(url, host, port, path)) {
        error = "invalid version URL";
        return false;
    }

    static WinHttpApi api;
    // load winhttp functions dynamically to avoid static dependency
    if (!api.load()) {
        error = "winhttp.dll is unavailable";
        return false;
    }

    std::wstring ua = utf8ToWide(std::string("TherapistVersionCheck/") + kAppVersionText);
    // open a winhttp session handle
    HINTERNET session = api.open(ua.c_str(),
                                 kWinHttpAccessTypeDefaultProxy,
                                 nullptr,
                                 nullptr,
                                 0);
    if (!session) {
        error = "unable to start WinHTTP session";
        return false;
    }

    bool success = false;
    HINTERNET connect = nullptr;
    HINTERNET request = nullptr;
    do {
        // set conservative timeouts for resolve/connect/send/receive
        if (!api.setTimeouts(session,
                             kVersionResolveTimeoutMs,
                             kVersionConnectTimeoutMs,
                             kVersionSendTimeoutMs,
                             kVersionReceiveTimeoutMs)) {
            error = "unable to set WinHTTP timeouts";
            break;
        }

        // establish connection to host:port
        connect = api.connect(session, host.c_str(), port, 0);
        if (!connect) {
            error = "unable to connect to version host";
            break;
        }

        // open a simple GET request over https
        request = api.openRequest(connect,
                                  L"GET",
                                  path.c_str(),
                                  nullptr,
                                  nullptr,
                                  nullptr,
                                  kWinHttpFlagSecure);
        if (!request) {
            error = "unable to open HTTPS request";
            break;
        }

        const wchar_t* headers = L"Cache-Control: no-cache\r\nPragma: no-cache\r\n";
        // send the request and await response
        if (!api.sendRequest(request,
                             headers,
                             static_cast<DWORD>(-1L),
                             nullptr,
                             0,
                             0,
                             0)) {
            error = "unable to send version request";
            break;
        }
        if (!api.receiveResponse(request, nullptr)) {
            error = "unable to receive version response";
            break;
        }

        // read and validate http status code
        DWORD statusCode = 0;
        DWORD statusSize = sizeof(statusCode);
        if (!api.queryHeaders(request,
                              kWinHttpQueryStatusCode | kWinHttpQueryFlagNumber,
                              nullptr,
                              &statusCode,
                              &statusSize,
                              nullptr)) {
            error = "unable to read version response status";
            break;
        }
        if (statusCode != kHttpStatusOk) {
            error = "version check returned HTTP " + std::to_string(statusCode);
            break;
        }

        // read response body in chunks until none left
        body.clear();
        while (true) {
            DWORD available = 0;
            if (!api.queryDataAvailable(request, &available)) {
                error = "unable to query version response size";
                break;
            }
            if (available == 0) {
                success = true;
                break;
            }

            std::vector<char> buffer(available);
            DWORD bytesRead = 0;
            if (!api.readData(request, buffer.data(), available, &bytesRead)) {
                error = "unable to read version response body";
                break;
            }
            body.append(buffer.data(), bytesRead); // append chunk to body
        }
    } while (false);

    if (request) api.closeHandle(request);
    if (connect) api.closeHandle(connect);
    api.closeHandle(session);
    return success;
}
// end of WinHTTP text-fetch implementation
#endif

// (binary download + SHA256 verification removed)

void runRemoteVersionCheck() {
    // reset info and mark that we've attempted a check
    gRemoteVersionInfo = RemoteVersionInfo{};
    gRemoteVersionInfo.checked = true;
    gRemoteVersionInfo.versionInfoUrl = getVersionInfoUrl(); // where to fetch version info

    // fetch remote text manifest from the configured url
    std::string body;
    if (!fetchHttpsTextWinHttp(gRemoteVersionInfo.versionInfoUrl,
                               body,
                               gRemoteVersionInfo.errorMessage)) {
        return; // leave error message populated by fetch function
    }

    // parse manifest into version + optional download url
    AppVersion latestVersion{};
    std::string downloadUrl;
    if (!parseVersionFileText(body, latestVersion, downloadUrl)) {
        gRemoteVersionInfo.errorMessage = "version file format is invalid";
        return;
    }

    // populate results and determine whether current build is outdated
    gRemoteVersionInfo.succeeded = true;
    gRemoteVersionInfo.latestVersion = latestVersion;
    gRemoteVersionInfo.downloadUrl = downloadUrl;
    gRemoteVersionInfo.outdated =
        compareAppVersion(kCurrentAppVersion, gRemoteVersionInfo.latestVersion) < 0;
}

std::string formatFileSize(std::size_t bytes) {
    std::ostringstream oss;
    if (bytes < 1024)
        oss << bytes << " B";
    else if (bytes < 1024 * 1024)
        oss << std::fixed << std::setprecision(1) << (bytes / 1024.0) << " KB";
    else if (bytes < 1024ULL * 1024 * 1024)
        oss << std::fixed << std::setprecision(1) << (bytes / (1024.0 * 1024.0)) << " MB";
    else
        oss << std::fixed << std::setprecision(2) << (bytes / (1024.0 * 1024.0 * 1024.0)) << " GB";
    return oss.str();
}

// ---------------------------------------------------------------------------
//  message helpers
// ---------------------------------------------------------------------------
constexpr char kMessageMagic[] = {'M', 'S', 'G', '1'};

std::uint64_t currentTimeSeconds() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

ByteVector buildMessagePayload(const std::string& msg, std::uint64_t ts) {
    ByteVector p;
    // reserve expected size to avoid reallocations
    p.reserve(sizeof(kMessageMagic) + sizeof(ts) + msg.size());
    // prefix with magic marker to identify message payloads
    p.insert(p.end(), std::begin(kMessageMagic), std::end(kMessageMagic));
    // append 64-bit timestamp in big-endian order
    for (int s = 56; s >= 0; s -= 8)
        p.push_back(static_cast<std::uint8_t>((ts >> s) & 0xFFU));
    // append message bytes
    p.insert(p.end(), msg.begin(), msg.end());
    return p;
}

bool parseMessagePayload(const ByteVector& data, std::string& msg, std::uint64_t& ts) {
    const std::size_t hs = sizeof(kMessageMagic) + sizeof(std::uint64_t);
    if (data.size() < hs) return false;
    // validate magic marker at start
    if (!std::equal(std::begin(kMessageMagic), std::end(kMessageMagic), data.begin()))
        return false;
    ts = 0;
    for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i)
        ts = (ts << 8U) | static_cast<std::uint64_t>(data[sizeof(kMessageMagic) + i]);
    msg.assign(data.begin() + hs, data.end());
    return true;
}

std::string formatTimestamp(std::uint64_t ts) {
    std::time_t raw = static_cast<std::time_t>(ts);
    std::tm ti{};
#ifdef _WIN32
#if defined(_MSC_VER)
    // thread-safe localtime variant on msvc
    if (localtime_s(&ti, &raw) != 0) return "unknown";
#else
    // fallback to std::localtime result copy for other windows compilers
    if (std::tm* tmp = std::localtime(&raw)) ti = *tmp;
    else return "unknown";
#endif
#else
    // unix-like thread-safe localtime variant
    if (localtime_r(&raw, &ti) == nullptr) return "unknown";
#endif
    std::ostringstream oss;
    oss << std::put_time(&ti, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

std::vector<std::string> listMessageFiles(const std::string& dir) {
    std::vector<std::string> files;
#ifdef _WIN32
    // scan for files matching "file_*" using win32 find APIs
    std::string pat = joinPath(dir, "file_*");
    WIN32_FIND_DATAA fd{};
    HANDLE h = FindFirstFileA(pat.c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                files.emplace_back(fd.cFileName);
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
#else
    // unix-like: iterate directory entries and collect those starting with "file_"
    std::string dp = dir.empty() ? "." : dir;
    if (DIR* d = opendir(dp.c_str())) {
        while (dirent* e = readdir(d)) {
            std::string n(e->d_name);
            if (n.rfind("file_", 0) == 0) files.push_back(n);
        }
        closedir(d);
    }
#endif
    std::sort(files.begin(), files.end());
    return files;
}

std::string generateMessageFilePath(const std::string& baseDir) {
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    std::string cand;
    std::size_t attempt = 0;
    // create a candidate filename using current epoch ms and ensure uniqueness
    do {
        std::ostringstream oss;
        oss << "file_" << ms;
        if (attempt > 0) oss << '_' << attempt;
        cand = joinPath(baseDir, oss.str());
        ++attempt;
    } while (fileExists(cand));
    return cand;
}

bool isDigits(const std::string& t) {
    return !t.empty() && std::all_of(t.begin(), t.end(),
        [](unsigned char ch) { return std::isdigit(ch) != 0; });
}

// ---------------------------------------------------------------------------
//  console / UI helpers
// ---------------------------------------------------------------------------
bool enableAnsiColors() {
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD m = 0;
    if (!GetConsoleMode(h, &m)) return false;
    if (!(m & ENABLE_VIRTUAL_TERMINAL_PROCESSING))
        if (!SetConsoleMode(h, m | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
            return false;
    HANDLE eh = GetStdHandle(STD_ERROR_HANDLE);
    if (eh != INVALID_HANDLE_VALUE) {
        DWORD em = 0;
        if (GetConsoleMode(eh, &em))
            SetConsoleMode(eh, em | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
    // attempt to enable ansi vt processing and utf-8 output on windows
    gUnicodeSupported = (SetConsoleOutputCP(CP_UTF8) != 0);
    if (gUnicodeSupported) {
        SetConsoleCP(CP_UTF8);
        std::setlocale(LC_ALL, ".UTF-8");
    }
    initSymbols();
    return true;
#else
    // unix-like: set locale and detect utf support from env vars
    std::setlocale(LC_ALL, "en_US.UTF-8");
    const char* lang = std::getenv("LANG");
    const char* lcAll = std::getenv("LC_ALL");
    gUnicodeSupported = (lang && (std::strstr(lang, "UTF") || std::strstr(lang, "utf"))) ||
                        (lcAll && (std::strstr(lcAll, "UTF") || std::strstr(lcAll, "utf")));
    initSymbols();
    return true;
#endif
}

void clearConsole(bool ansi) {
#ifdef _WIN32
    if (ansi) {
        std::cout << "\033[2J\033[3J\033[H" << std::flush;
    } else {
        // native console API instead of system("cls")
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut != INVALID_HANDLE_VALUE) {
            CONSOLE_SCREEN_BUFFER_INFO csbi;
            if (GetConsoleScreenBufferInfo(hOut, &csbi)) {
                DWORD cells = static_cast<DWORD>(csbi.dwSize.X) *
                              static_cast<DWORD>(csbi.dwSize.Y);
                COORD origin = {0, 0};
                DWORD written = 0;
                FillConsoleOutputCharacterA(hOut, ' ', cells, origin, &written);
                FillConsoleOutputAttribute(hOut, csbi.wAttributes, cells, origin, &written);
                SetConsoleCursorPosition(hOut, origin);
            }
        }
    }
#else
    (void)ansi;
    std::cout << "\033[2J\033[3J\033[H" << std::flush;
#endif
}

void applyConsoleTitle() {
#ifdef _WIN32
    std::wstring title = utf8ToWide(kAppExeName);
    SetConsoleTitleW(title.c_str());
#endif
}

const std::array<std::string, 23> kBannerLines = {
    u8"                \xe2\xa3\xa4\xe2\xa3\xb6\xe2\xa3\xb6\xe2\xa3\xb6\xe2\xa3\xb6\xe2\xa3\xb6\xe2\xa3\xa6\xe2\xa3\x84\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80",
    u8"\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa2\xb0\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xb7\xe2\xa1\x84\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80",
    u8"\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa3\xa0\xe2\xa2\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa1\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80",
    u8"\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa3\xb0\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa1\x87\xe2\xa3\xbf\xe2\xa3\xb7\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xaf\xe2\xa1\x84\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80",
    u8"\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa1\xb0\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\x87\xe2\xa3\xbf\xe2\xa3\x80\xe2\xa0\xb8\xe2\xa1\x9f\xe2\xa2\xb9\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xb7\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80",
    u8"\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa2\x80\xe2\xa2\xa1\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa1\x87\xe2\xa0\x9d\xe2\xa0\x8b\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa2\xbf\xe2\xa2\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa1\x87\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80",
    u8"\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\xb8\xe2\xa2\xb8\xe2\xa0\xb8\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\x87\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x8a\xe2\xa3\xbd\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa0\x81\xe2\xa3\xb7\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80",
    u8"\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa2\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xb7\xe2\xa3\x84\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa2\xa0\xe2\xa3\xb4\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa0\x8b\xe2\xa3\xa0\xe2\xa1\x8f\xe2\xa1\x84\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80",
    u8"\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x90\xe2\xa0\xbe\xe2\xa3\xbf\xe2\xa3\x9f\xe2\xa1\xbb\xe2\xa0\x89\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x88\xe2\xa2\xbf\xe2\xa0\x8b\xe2\xa3\xbf\xe2\xa1\xbf\xe2\xa0\x9a\xe2\xa0\x8b\xe2\xa0\x81\xe2\xa1\x81\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80",
    u8"\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa2\x80\xe2\xa3\xb4\xe2\xa3\xb6\xe2\xa3\xbe\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa1\x84\xe2\xa0\x80\xe2\xa3\xb3\xe2\xa1\xb6\xe2\xa1\xa6\xe2\xa1\x80\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xb7\xe2\xa3\xb6\xe2\xa3\xa4\xe2\xa1\xbe\xe2\xa0\x81\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80",
    u8"\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa2\xb8\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa1\x86\xe2\xa0\x80\xe2\xa1\x87\xe2\xa1\xbf\xe2\xa0\x89\xe2\xa3\xba\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80",
    u8"\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa2\xb8\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xaf\xe2\xa0\xbd\xe2\xa2\xb2\xe2\xa0\x87\xe2\xa0\xa3\xe2\xa0\x90\xe2\xa0\x9a\xe2\xa2\xbb\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80",
    u8"\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa1\x90\xe2\xa3\xbe\xe2\xa1\x8f\xe2\xa3\xb7\xe2\xa0\x80\xe2\xa0\x80\xe2\xa3\xbc\xe2\xa3\xb7\xe2\xa1\xa7\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xa6\xe2\xa3\x84\xe2\xa1\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80",
    u8"\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa3\xbb\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xae\xe2\xa0\xb3\xe2\xa3\xbf\xe2\xa3\x87\xe2\xa2\x88\xe2\xa3\xbf\xe2\xa0\x9f\xe2\xa3\xac\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa1\xa6\xe2\xa2\x84\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80",
    u8"\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa2\x80\xe2\xa2\x84\xe2\xa3\xbe\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xb7\xe2\xa3\x9c\xe2\xa2\xbf\xe2\xa3\xbc\xe2\xa2\x8f\xe2\xa3\xbe\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa2\xbb\xe2\xa3\xbf\xe2\xa3\x9d\xe2\xa3\xbf\xe2\xa3\xa6\xe2\xa1\x91\xe2\xa2\x84\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80",
    u8"\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa3\xa0\xe2\xa3\xb6\xe2\xa3\xb7\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa0\x83\xe2\xa0\x98\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa1\xb7\xe2\xa3\xa5\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa0\x80\xe2\xa0\xb9\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xb7\xe2\xa1\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80",
    u8"\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa3\x87\xe2\xa3\xa4\xe2\xa3\xbe\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa1\xbf\xe2\xa0\xbb\xe2\xa1\x8f\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\xb8\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xae\xe2\xa3\xbe\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa1\x87\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x99\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa1\xbf\xe2\xa1\x87\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80",
    u8"\xe2\xa0\x80\xe2\xa0\x80\xe2\xa2\x80\xe2\xa1\xb4\xe2\xa3\xab\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa0\x8b\xe2\xa0\x80\xe2\xa0\x80\xe2\xa1\x87\xe2\xa0\x80\xe2\xa0\x80\xe2\xa2\xb0\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa1\x87\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa2\x98\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\x9f\xe2\xa2\xa6\xe2\xa1\xb8\xe2\xa0\x80\xe2\xa0\x80",
    u8"\xe2\xa0\x80\xe2\xa1\xb0\xe2\xa0\x8b\xe2\xa3\xb4\xe2\xa3\xbf\xe2\xa3\x9f\xe2\xa3\xbf\xe2\xa0\x83\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x88\xe2\xa0\x80\xe2\xa0\x80\xe2\xa3\xb8\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\x87\xe2\xa3\xbd\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\x87\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x81\xe2\xa0\xb8\xe2\xa3\xbf\xe2\xa2\xbb\xe2\xa3\xa6\xe2\xa0\x89\xe2\xa2\x86\xe2\xa0\x80",
    u8"\xe2\xa2\xa0\xe2\xa0\x87\xe2\xa1\x94\xe2\xa3\xbf\xe2\xa0\x8f\xe2\xa0\x8f\xe2\xa0\x99\xe2\xa0\x86\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa2\x80\xe2\xa3\x9c\xe2\xa3\x9b\xe2\xa1\xbb\xe2\xa2\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa5\xbf\xe2\xa1\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa1\x87\xe2\xa1\x87\xe2\xa0\xb9\xe2\xa3\xb7\xe2\xa1\x88\xe2\xa1\x84\xe2\xa0\x80",
    u8"\xe2\xa0\x80\xe2\xa1\xb8\xe2\xa3\xb4\xe2\xa1\x8f\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa2\x80\xe2\xa3\xbe\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbb\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa1\x84\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa1\x87\xe2\xa1\x87\xe2\xa0\x80\xe2\xa2\xbb\xe2\xa1\xbf\xe2\xa1\x87\xe2\xa0\x80",
    u8"\xe2\xa0\x80\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\x86\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa2\x80\xe2\xa3\xbc\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa1\x80\xe2\xa0\x80\xe2\xa3\xb0\xe2\xa0\xbf\xe2\xa0\xa4\xe2\xa0\x92\xe2\xa1\x9b\xe2\xa2\xb9\xe2\xa3\xbf\xe2\xa0\x84",
    u8"\xe2\xa0\x80\xe2\xa3\xbf\xe2\xa3\xb7\xe2\xa1\x86\xe2\xa0\x81\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa2\xa0\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa0\x9f\xe2\xa0\xbb\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa3\xbf\xe2\xa1\x9f\xe2\xa0\xbb\xe2\xa2\xb7\xe2\xa1\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa0\x80\xe2\xa3\xb8\xe2\xa3\xbf"
};

void animateTitle() {
    static bool animated = false;
    const std::string title = "t h e r a p i s t";
    const char* pad = "              ";

    if (animated) {
        std::cout << Color::accent << pad << title << Color::reset << std::endl;
        return;
    }
    animated = true;

    const char glyphs[] = "$!%&^;:'\"?>.<,@#~";
    const std::size_t glyphCount = sizeof(glyphs) - 1;
    const int resolveFrames = 3;
    const int frameDelay = 50;

    // simple lcg rng used only for title animation randomness
    unsigned seed = static_cast<unsigned>(
        std::chrono::steady_clock::now().time_since_epoch().count() & 0xFFFFFFFFU);
    auto rng = [&seed]() -> unsigned {
        seed = seed * 1103515245U + 12345U;
        return (seed >> 16U) & 0x7FFFU;
    };

    std::string display(title.size(), ' ');
    for (std::size_t i = 0; i < title.size(); ++i) {
        if (title[i] != ' ')
            display[i] = glyphs[rng() % glyphCount];
    }

    // reveal title one position at a time with a small resolve animation
    for (std::size_t pos = 0; pos < title.size(); ++pos) {
        if (title[pos] == ' ') continue;
        for (int frame = 0; frame < resolveFrames; ++frame) {
            // fill trailing characters with randomized glyphs for visual effect
            for (std::size_t j = pos; j < title.size(); ++j) {
                if (title[j] != ' ')
                    display[j] = glyphs[rng() % glyphCount];
            }
            std::cout << "\r" << Color::accent << pad << display << Color::reset << std::flush;
#ifdef _WIN32
            ::Sleep(static_cast<DWORD>(frameDelay));
#else
            std::this_thread::sleep_for(std::chrono::milliseconds(frameDelay));
#endif
        }
        // lock in the real character at this position
        display[pos] = title[pos];
    }
    std::cout << "\r" << Color::accent << pad << title << Color::reset << std::endl;
}

void printBanner() {
    std::cout << '\n';
    animateTitle();
    std::cout << Color::muted
              << "              made by ytax"
              << Color::reset << '\n';
    std::cout << std::flush;
}

void printDivider() {
    std::cout << "  " << Color::border;
    for (int i = 0; i < 42; ++i) std::cout << Sym::dash;
    std::cout << Color::reset << std::endl;
}

void printSection(const char* name) {
    std::string t(name);
    int pad = 38 - static_cast<int>(t.size());
    std::cout << "\n  " << Color::accent << Sym::dash << Sym::dash
              << " " << name << " " << Color::border;
    for (int i = 0; i < pad; ++i) std::cout << Sym::dash;
    std::cout << Color::reset << "\n" << std::endl;
}

void printOk(const std::string& msg) {
    std::cout << "    " << Color::ok << Sym::check << Color::reset
              << "  " << msg << std::endl;
}

void printFail(const std::string& msg) {
    std::cout << "    " << Color::errorBold << Sym::cross << "  " << msg
              << Color::reset << std::endl;
}

void printWarn(const std::string& msg) {
    std::cout << "    " << Color::warn << Sym::warn << "  " << msg
              << Color::reset << std::endl;
}

void printNote(const std::string& msg) {
    std::cout << "    " << Color::info << Sym::dot << Color::reset
              << "  " << Color::label << msg << Color::reset << std::endl;
}

void printPrompt(const std::string& lbl) {
    std::cout << "    " << Color::accent << Sym::arrow << Color::reset
              << "  " << Color::label << lbl << Color::reset << " ";
}

// loading spinner
#ifdef _WIN32
struct SpinnerCtx {
    std::string msg;
    volatile LONG done;
    volatile LONG succeeded;
};

static DWORD WINAPI spinnerProc(LPVOID param) {
    auto* ctx = static_cast<SpinnerCtx*>(param);
    const char frames[] = {'|', '/', '-', '\\'};
    int i = 0;
    while (!InterlockedCompareExchange(&ctx->done, 0, 0)) {
        std::cout << "\r  " << Color::muted << ctx->msg << " "
                  << frames[i % 4] << " " << Color::reset << std::flush;
        ++i;
        ::Sleep(120);
    }
    if (InterlockedCompareExchange(&ctx->succeeded, 0, 0)) {
        std::cout << "\r  " << Color::ok << ctx->msg << " done"
                  << Color::reset << "       " << std::endl;
    } else {
        // clear the spinner line on error
        std::string blank(ctx->msg.size() + 20, ' ');
        std::cout << "\r" << blank << "\r" << std::flush;
    }
    return 0;
}

template <typename Func>
auto withSpinner(const std::string& msg, Func&& fn) -> decltype(fn()) {
    SpinnerCtx ctx;
    ctx.msg = msg;
    ctx.done = 0;
    ctx.succeeded = 0;
    HANDLE t = CreateThread(nullptr, 0, spinnerProc, &ctx, 0, nullptr);
    try {
        auto result = fn();
        InterlockedExchange(&ctx.succeeded, 1);
        InterlockedExchange(&ctx.done, 1);
        if (t) { WaitForSingleObject(t, INFINITE); CloseHandle(t); }
        return result;
    } catch (...) {
        InterlockedExchange(&ctx.done, 1);
        if (t) { WaitForSingleObject(t, INFINITE); CloseHandle(t); }
        throw;
    }
}
#else
void spinnerThread(const std::string& msg, std::atomic<bool>& done,
                   std::atomic<bool>& succeeded) {
    const char frames[] = {'|', '/', '-', '\\'};
    int i = 0;
    while (!done.load(std::memory_order_relaxed)) {
        // simple spinner loop prints a rotating frame until work completes
        std::cout << "\r  " << Color::muted << msg << " "
                  << frames[i % 4] << " " << Color::reset << std::flush;
        ++i;
        std::this_thread::sleep_for(std::chrono::milliseconds(120));
    }
    if (succeeded.load(std::memory_order_relaxed)) {
        std::cout << "\r  " << Color::ok << msg << " done"
                  << Color::reset << "       " << std::endl;
    } else {
        std::string blank(msg.size() + 20, ' ');
        std::cout << "\r" << blank << "\r" << std::flush;
    }
}

template <typename Func>
auto withSpinner(const std::string& msg, Func&& fn) -> decltype(fn()) {
    std::atomic<bool> done{false};
    std::atomic<bool> succeeded{false};
    std::thread t(spinnerThread, msg, std::ref(done), std::ref(succeeded));
    try {
        // run the provided work while spinner animates in another thread
        auto result = fn();
        succeeded.store(true, std::memory_order_relaxed);
        done.store(true, std::memory_order_relaxed);
        t.join();
        return result;
    } catch (...) {
        done.store(true, std::memory_order_relaxed);
        t.join();
        throw;
    }
}
#endif

void typeOutAnimated(const std::string& text,
                     std::chrono::milliseconds charDelay,
                     std::chrono::milliseconds nlDelay)
{
    for (unsigned char uch : text) {
        char ch = static_cast<char>(uch);
        std::cout << ch;
        std::cout.flush();
        if (ch == '\r') continue;
        auto d = (ch == '\n') ? nlDelay : charDelay;
        if (d.count() > 0) {
#ifdef _WIN32
            ::Sleep(static_cast<DWORD>(d.count()));
#else
            std::this_thread::sleep_for(d);
#endif
        }
    }
}

// ---------------------------------------------------------------------------
//  self-test
// ---------------------------------------------------------------------------
bool runSelfTest(bool verbose) {
    std::size_t savedIter = gKdfIterations;
    std::size_t savedMem  = gKdfMemoryBytes;
    gKdfIterations  = 16;
    gKdfMemoryBytes = 65536;

    int passed = 0;
    int failed = 0;
    int total  = 0;

    auto restore = [&]() {
        gKdfIterations  = savedIter;
        gKdfMemoryBytes = savedMem;
    };

    auto runTest = [&](const char* name, const char* details, std::function<void()> fn) {
        ++total;
        try {
            fn();
            ++passed;
            if (verbose) {
                std::cout << "    " << Color::ok << Sym::check << Color::reset
                          << "  " << name << std::endl;
                std::cout << "       " << Color::muted << details
                          << Color::reset << std::endl;
            }
        } catch (const std::exception& ex) {
            ++failed;
            if (verbose) {
                std::cout << "    " << Color::errorBold << Sym::cross << Color::reset
                          << "  " << name << "  " << Color::error << ex.what()
                          << Color::reset << std::endl;
                std::cout << "       " << Color::muted << details
                          << Color::reset << std::endl;
            }
        }
    };

    auto category = [&](const char* name) {
        if (verbose) printSection(name);
    };

    const std::string pass = std::string(kAppExeName) + "-selftest";

    // -- s-box & primitives --

    category("s-box & primitives");

    runTest("sbox invertibility",
            "checked inv(fwd(x)) == x and fwd(inv(x)) == x for all bytes 0..255",
    [&]() {
        const auto& sb = sbox();
        for (int i = 0; i < 256; ++i) {
            std::uint8_t b = static_cast<std::uint8_t>(i);
            if (sb.inv[sb.fwd[b]] != b)
                throw std::runtime_error("inv(fwd(x)) != x");
            if (sb.fwd[sb.inv[b]] != b)
                throw std::runtime_error("fwd(inv(x)) != x");
        }
    });

    runTest("sbox completeness",
            "verified all 256 distinct values present in forward table",
    [&]() {
        const auto& sb = sbox();
        std::array<bool, 256> seen{};
        for (int i = 0; i < 256; ++i)
            seen[static_cast<std::size_t>(sb.fwd[static_cast<std::size_t>(i)])] = true;
        for (int i = 0; i < 256; ++i)
            if (!seen[static_cast<std::size_t>(i)])
                throw std::runtime_error("missing value " + std::to_string(i));
    });

    runTest("sbox fwd64 lookup table",
            "verified fwd64[lane][b] == fwd[b] << (lane*8) for all lanes and bytes",
    [&]() {
        const auto& sb = sbox();
        for (int lane = 0; lane < 8; ++lane) {
            unsigned shift = static_cast<unsigned>(lane * 8);
            for (int b = 0; b < 256; ++b) {
                std::uint64_t expected =
                    static_cast<std::uint64_t>(sb.fwd[static_cast<std::size_t>(b)]) << shift;
                if (sb.fwd64[static_cast<std::size_t>(lane)][static_cast<std::size_t>(b)] != expected)
                    throw std::runtime_error("mismatch at lane " + std::to_string(lane));
            }
        }
    });

    // -- block cipher --

    category("block cipher");

    runTest("determinism",
            "encrypted same 128-bit block twice with same key; outputs identical",
    [&]() {
        ByteVector salt = generateSalt(kSaltSize);
        auto ks = deriveHardenedSchedule(pass, salt);
        ScopedKS w(ks);
        std::uint64_t L1 = 0x0123456789ABCDEFULL, R1 = 0xFEDCBA9876543210ULL;
        std::uint64_t L2 = L1, R2 = R1;
        encryptBlock(L1, R1, ks);
        encryptBlock(L2, R2, ks);
        if (L1 != L2 || R1 != R2)
            throw std::runtime_error("same input gave different output");
    });

    runTest("non-identity",
            "verified encrypted block differs from plaintext block",
    [&]() {
        ByteVector salt = generateSalt(kSaltSize);
        auto ks = deriveHardenedSchedule(pass, salt);
        ScopedKS w(ks);
        std::uint64_t L = 0x0123456789ABCDEFULL, R = 0xFEDCBA9876543210ULL;
        std::uint64_t origL = L, origR = R;
        encryptBlock(L, R, ks);
        if (L == origL && R == origR)
            throw std::runtime_error("encrypted == plaintext");
    });

    runTest("avalanche (bit diffusion)",
            "flipped 1 input bit; verified >25% of 128 output bits changed",
    [&]() {
        ByteVector salt = generateSalt(kSaltSize);
        auto ks = deriveHardenedSchedule(pass, salt);
        ScopedKS w(ks);
        std::uint64_t L1 = 0xAAAAAAAAAAAAAAAAULL, R1 = 0x5555555555555555ULL;
        std::uint64_t L2 = L1 ^ 1ULL, R2 = R1;
        encryptBlock(L1, R1, ks);
        encryptBlock(L2, R2, ks);
        std::uint64_t dL = L1 ^ L2, dR = R1 ^ R2;
        int bits = 0;
        while (dL) { bits += static_cast<int>(dL & 1ULL); dL >>= 1; }
        while (dR) { bits += static_cast<int>(dR & 1ULL); dR >>= 1; }
        if (bits < 32)
            throw std::runtime_error("only " + std::to_string(bits) + "/128 bits changed");
    });

    // -- ctr mode --

    category("ctr mode");

    runTest("encrypt/decrypt identity",
            "applied CTR encrypt then decrypt; compared decrypted == original (200 bytes)",
    [&]() {
        ByteVector salt = generateSalt(kSaltSize);
        auto ks = deriveHardenedSchedule(pass, salt);
        ScopedKS w(ks);
        ByteVector original(200);
        for (std::size_t i = 0; i < original.size(); ++i)
            original[i] = static_cast<std::uint8_t>(i);
        ByteVector encrypted, decrypted;
        applyCipher(original, encrypted, ks, salt);
        applyCipher(encrypted, decrypted, ks, salt);
        if (decrypted != original)
            throw std::runtime_error("decrypt(encrypt(x)) != x");
    });

    runTest("salt independence",
            "encrypted same data with two different salts; verified ciphertexts differ",
    [&]() {
        ByteVector salt1 = generateSalt(kSaltSize);
        ByteVector salt2 = generateSalt(kSaltSize);
        auto ks = deriveHardenedSchedule(pass, salt1);
        ScopedKS w(ks);
        ByteVector data(64, 0x42);
        ByteVector enc1, enc2;
        applyCipher(data, enc1, ks, salt1);
        applyCipher(data, enc2, ks, salt2);
        if (enc1 == enc2)
            throw std::runtime_error("different salts produced same ciphertext");
    });

    // -- key derivation --

    category("key derivation");

    runTest("password sensitivity",
            "derived keys from two different passwords; verified round keys differ",
    [&]() {
        ByteVector salt = generateSalt(kSaltSize);
        auto ks1 = deriveHardenedSchedule("password-one", salt);
        ScopedKS w1(ks1);
        auto ks2 = deriveHardenedSchedule("password-two", salt);
        ScopedKS w2(ks2);
        if (ks1.rka[0] == ks2.rka[0] && ks1.rkb[0] == ks2.rkb[0])
            throw std::runtime_error("different passwords produced same keys");
    });

    runTest("salt sensitivity",
            "derived keys with same password but different salts; verified keys differ",
    [&]() {
        ByteVector s1 = generateSalt(kSaltSize);
        ByteVector s2 = generateSalt(kSaltSize);
        auto ks1 = deriveHardenedSchedule(pass, s1);
        ScopedKS w1(ks1);
        auto ks2 = deriveHardenedSchedule(pass, s2);
        ScopedKS w2(ks2);
        if (ks1.rka[0] == ks2.rka[0] && ks1.rkb[0] == ks2.rkb[0])
            throw std::runtime_error("different salts produced same keys");
    });

    // -- mac --

    category("mac");

    runTest("consistency",
            "computed MAC twice for same input and salts; verified MACs equal",
    [&]() {
        ByteVector data = {'t','e','s','t'};
        ByteVector s1 = generateSalt(kSaltSize);
        ByteVector s2 = generateSalt(kSaltSize);
        Mac256 a = computeHardenedMac(data, pass, s1, s2);
        Mac256 b = computeHardenedMac(data, pass, s1, s2);
        if (!constantTimeMacEq(a, b))
            throw std::runtime_error("same input produced different MAC");
    });

    runTest("sensitivity",
            "computed MAC for different inputs with same salts; verified MACs differ",
    [&]() {
        ByteVector d1 = {'a'}, d2 = {'b'};
        ByteVector s1 = generateSalt(kSaltSize);
        ByteVector s2 = generateSalt(kSaltSize);
        Mac256 a = computeHardenedMac(d1, pass, s1, s2);
        Mac256 b = computeHardenedMac(d2, pass, s1, s2);
        if (constantTimeMacEq(a, b))
            throw std::runtime_error("different input produced same MAC");
    });

    // -- payload round-trips --

    category("payload round-trips");

    runTest("empty payload (V6)",
            "encrypt(empty) -> decrypt; verified plaintext empty and version==6",
    [&]() {
        FileMetadata m{"", currentDateString()};
        ByteVector enc = encryptPayload({}, pass, m);
        DecryptResult dec = decryptPayload(enc, pass);
        if (!dec.plaintext.empty())
            throw std::runtime_error("output not empty");
        if (dec.version != kVersionV6)
            throw std::runtime_error("version mismatch");
    });

    runTest("1-byte payload",
            "encrypted/decrypted a single byte; verified equality",
    [&]() {
        ByteVector plain = {0x42};
        FileMetadata m{"one.bin", currentDateString()};
        ByteVector enc = encryptPayload(plain, pass, m);
        DecryptResult dec = decryptPayload(enc, pass);
        if (dec.plaintext != plain)
            throw std::runtime_error("single byte mismatch");
    });

    runTest("small payload + metadata",
            "encrypted 5 bytes with filename/date; verified all fields after decrypt",
    [&]() {
        ByteVector plain = {'h','e','l','l','o'};
        FileMetadata m{"test.txt", "01-01-2020"};
        ByteVector enc = encryptPayload(plain, pass, m);
        DecryptResult dec = decryptPayload(enc, pass);
        if (dec.plaintext != plain)
            throw std::runtime_error("data mismatch");
        if (dec.meta.originalName != "test.txt")
            throw std::runtime_error("name: " + dec.meta.originalName);
        if (dec.meta.date != "01-01-2020")
            throw std::runtime_error("date: " + dec.meta.date);
    });

    runTest("single-block payload (16 bytes)",
            "encrypted/decrypted exactly one block; verified equality",
    [&]() {
        ByteVector plain(kBlockSize, 0xAA);
        FileMetadata m{"block.bin", currentDateString()};
        ByteVector enc = encryptPayload(plain, pass, m);
        DecryptResult dec = decryptPayload(enc, pass);
        if (dec.plaintext != plain)
            throw std::runtime_error("mismatch at block boundary");
    });

    runTest("cross-block payload (17 bytes)",
            "encrypted/decrypted 17 bytes spanning blocks; verified equality",
    [&]() {
        ByteVector plain(kBlockSize + 1, 0xBB);
        FileMetadata m{"cross.bin", currentDateString()};
        ByteVector enc = encryptPayload(plain, pass, m);
        DecryptResult dec = decryptPayload(enc, pass);
        if (dec.plaintext != plain)
            throw std::runtime_error("mismatch at cross-block boundary");
    });

    runTest("large payload (4096 bytes)",
            "encrypted/decrypted 4096 bytes; verified equality",
    [&]() {
        ByteVector plain(4096);
        for (std::size_t i = 0; i < plain.size(); ++i)
            plain[i] = static_cast<std::uint8_t>(i & 0xFFU);
        FileMetadata m{"big.bin", currentDateString()};
        ByteVector enc = encryptPayload(plain, pass, m);
        DecryptResult dec = decryptPayload(enc, pass);
        if (dec.plaintext != plain)
            throw std::runtime_error("large payload mismatch");
    });

    runTest("metadata with special chars",
            "used filename with unicode chars; verified preservation after decrypt",
    [&]() {
        ByteVector plain = {'d','a','t','a'};
        FileMetadata m{"t\xc3\xa9st\xe2\x80\x94" "file.txt", currentDateString()};
        ByteVector enc = encryptPayload(plain, pass, m);
        DecryptResult dec = decryptPayload(enc, pass);
        if (dec.plaintext != plain)
            throw std::runtime_error("data mismatch");
        if (dec.meta.originalName != m.originalName)
            throw std::runtime_error("name mismatch: " + dec.meta.originalName);
    });

    runTest("V6 header structure",
            "verified magic='TPC6', version=6, saltLen=32, macLen=32 in output",
    [&]() {
        ByteVector plain = {'h','d','r'};
        FileMetadata m{"h.bin", currentDateString()};
        ByteVector enc = encryptPayload(plain, pass, m);
        if (enc.size() < 7) throw std::runtime_error("output too short");
        if (enc[0] != 'T' || enc[1] != 'P' || enc[2] != 'C' || enc[3] != '6')
            throw std::runtime_error("bad magic bytes");
        if (enc[4] != 6) throw std::runtime_error("bad version byte");
        if (enc[5] != kSaltSize) throw std::runtime_error("bad saltLen");
        if (enc[6] != kMacSize) throw std::runtime_error("bad macLen");
    });

    runTest("augmented V6 build/parse",
            "built augmented payload; parsed and verified plaintext + metadata match",
    [&]() {
        ByteVector plain = {'t','e','s','t'};
        FileMetadata m{"aug.txt", "15-03-2025"};
        ByteVector aug = buildAugmentedV6(plain, m);
        FileMetadata parsed;
        ByteVector recovered = parseAugmentedV6(aug, parsed);
        if (recovered != plain)
            throw std::runtime_error("plaintext mismatch");
        if (parsed.originalName != "aug.txt")
            throw std::runtime_error("name mismatch");
        if (parsed.date != "15-03-2025")
            throw std::runtime_error("date mismatch");
    });

    runTest("double encrypt produces different output",
            "encrypted same plaintext twice; verified outputs differ (random salts)",
    [&]() {
        ByteVector plain = {'d','u','p'};
        FileMetadata m{"dup.bin", currentDateString()};
        ByteVector enc1 = encryptPayload(plain, pass, m);
        ByteVector enc2 = encryptPayload(plain, pass, m);
        if (enc1 == enc2)
            throw std::runtime_error("two encryptions are identical");
    });

    // -- authentication & tamper --

    category("authentication & tamper");

    runTest("wrong passphrase rejection",
            "attempted decrypt with wrong passphrase; verified failure",
    [&]() {
        ByteVector plain = {'x'};
        FileMetadata m{"x.bin", currentDateString()};
        ByteVector enc = encryptPayload(plain, pass, m);
        bool rejected = false;
        try { decryptPayload(enc, "wrong-pass"); }
        catch (...) { rejected = true; }
        if (!rejected)
            throw std::runtime_error("wrong passphrase accepted");
    });

    runTest("tampered ciphertext",
            "flipped last ciphertext byte; verified decryption fails",
    [&]() {
        ByteVector plain = {'s','e','c','r','e','t'};
        FileMetadata m{"t.bin", currentDateString()};
        ByteVector enc = encryptPayload(plain, pass, m);
        if (!enc.empty()) enc.back() ^= 0xFF;
        bool rejected = false;
        try { decryptPayload(enc, pass); }
        catch (...) { rejected = true; }
        if (!rejected)
            throw std::runtime_error("tampered ciphertext accepted");
    });

    runTest("tampered mac",
            "modified first MAC byte; verified MAC verification fails",
    [&]() {
        ByteVector plain = {'m','a','c'};
        FileMetadata m{"m.bin", currentDateString()};
        ByteVector enc = encryptPayload(plain, pass, m);
        std::size_t macOff = 4 + 3 + kSaltSize * 2;
        if (enc.size() > macOff) enc[macOff] ^= 0x01;
        bool rejected = false;
        try { decryptPayload(enc, pass); }
        catch (...) { rejected = true; }
        if (!rejected)
            throw std::runtime_error("tampered MAC accepted");
    });

    runTest("truncated input rejection",
            "fed 3-byte truncated input; verified exception thrown",
    [&]() {
        ByteVector tiny = {0x01, 0x02, 0x03};
        bool rejected = false;
        try { decryptPayload(tiny, pass); }
        catch (...) { rejected = true; }
        if (!rejected)
            throw std::runtime_error("truncated input accepted");
    });

    runTest("wrong magic rejection",
            "fed data with invalid magic bytes; verified exception thrown",
    [&]() {
        ByteVector bad = {'X','X','X','X', 6, 32, 32};
        bad.resize(200, 0);
        bool rejected = false;
        try { decryptPayload(bad, pass); }
        catch (...) { rejected = true; }
        if (!rejected)
            throw std::runtime_error("wrong magic accepted");
    });

    // -- counter --

    category("counter");

    runTest("increment correctness",
            "incremented counter from known value; verified low word +1 and carry",
    [&]() {
        std::array<std::uint8_t, kBlockSize> ctr{};
        store64LE(ctr.data(), 0x00000000000000FFULL);
        store64LE(ctr.data() + 8, 0ULL);
        incrementCounter(ctr);
        std::uint64_t lo = load64LE(ctr.data());
        std::uint64_t hi = load64LE(ctr.data() + 8);
        if (lo != 0x0000000000000100ULL || hi != 0ULL)
            throw std::runtime_error("simple increment failed");
        store64LE(ctr.data(), 0xFFFFFFFFFFFFFFFFULL);
        store64LE(ctr.data() + 8, 0ULL);
        incrementCounter(ctr);
        lo = load64LE(ctr.data());
        hi = load64LE(ctr.data() + 8);
        if (lo != 0ULL || hi != 1ULL)
            throw std::runtime_error("carry failed");
    });

    // -- file i/o --

    category("file i/o");

    runTest("file round-trip",
            "wrote -> encrypted -> decrypted -> read; verified file contents match",
    [&]() {
        std::string tmpIn  = "selftest_input.tmp";
        std::string tmpEnc = "selftest_enc.tmp";
        std::string tmpDec = "selftest_dec.tmp";

        ByteVector payload = {'T','e','s','t','!'};
        writeBinaryFile(tmpIn, payload);

        FileMetadata m{extractFilename(tmpIn), currentDateString()};
        ByteVector raw = readBinaryFile(tmpIn);
        ByteVector enc = encryptPayload(raw, pass, m);
        writeBinaryFile(tmpEnc, enc);
        setEncryptedFileTimestamps(tmpEnc);

        ByteVector encRead = readBinaryFile(tmpEnc);
        DecryptResult dec = decryptPayload(encRead, pass);
        writeBinaryFile(tmpDec, dec.plaintext);

        ByteVector check = readBinaryFile(tmpDec);
        std::remove(tmpIn.c_str());
        std::remove(tmpEnc.c_str());
        std::remove(tmpDec.c_str());

        if (check != payload)
            throw std::runtime_error("file data mismatch");
    });

    // -- message layer --

    category("message layer");

    runTest("message payload build/parse",
            "built message payload; parsed and verified message + timestamp equality",
    [&]() {
        std::string msg = "hello from the self-test";
        std::uint64_t ts = currentTimeSeconds();
        ByteVector payload = buildMessagePayload(msg, ts);

        std::string parsedMsg;
        std::uint64_t parsedTs = 0;
        if (!parseMessagePayload(payload, parsedMsg, parsedTs))
            throw std::runtime_error("parse returned false");
        if (parsedMsg != msg)
            throw std::runtime_error("message mismatch");
        if (parsedTs != ts)
            throw std::runtime_error("timestamp mismatch");
    });

    runTest("encrypted message round-trip",
            "encrypted message; decrypted and verified message equality",
    [&]() {
        std::string msg = "encrypted test message";
        std::uint64_t ts = currentTimeSeconds();
        ByteVector payload = buildMessagePayload(msg, ts);
        FileMetadata m{"message", currentDateString()};
        ByteVector enc = encryptPayload(payload, pass, m);
        DecryptResult dec = decryptPayload(enc, pass);

        std::string parsedMsg;
        std::uint64_t parsedTs = 0;
        if (!parseMessagePayload(dec.plaintext, parsedMsg, parsedTs))
            throw std::runtime_error("parse failed after decrypt");
        if (parsedMsg != msg)
            throw std::runtime_error("message mismatch after decrypt");
    });

    // -- version metadata --

    category("version metadata");

    runTest("version file parse",
            "parsed semantic version + release URL from plain text update metadata",
    [&]() {
        AppVersion latest{};
        std::string downloadUrl;
        std::string manifest = std::string(kAppVersionText) + "\n" + kDefaultReleaseUrl + "\n";
        if (!parseVersionFileText(manifest, latest, downloadUrl)) {
            throw std::runtime_error("version file parse failed");
        }
        if (formatAppVersion(latest) != kAppVersionText)
            throw std::runtime_error("version mismatch");
        if (downloadUrl.find("github.com/ytaxx/TherapistEncrypter/releases") == std::string::npos)
            throw std::runtime_error("download URL mismatch");
    });

    // cleanup
    std::remove("selftest_input.tmp");
    std::remove("selftest_enc.tmp");
    std::remove("selftest_dec.tmp");

    restore();

    // summary
    if (verbose) {
        std::cout << std::endl;
        printDivider();
        std::cout << std::endl;
        printNote("cipher:   feistel V6, " + std::to_string(kRounds) + " rounds, "
              + std::to_string(kBlockSize) + "-byte block, double-pass CTR");
        printNote("kdf:      " + std::to_string(savedIter) + " iterations, "
                  + formatFileSize(savedMem) + " memory");
        printNote("mac:      256-bit cascaded (4x FNV-like)");
        printNote("salt:     " + std::to_string(kSaltSize) + " bytes (x2)");
        printNote("format:   V6 with embedded filename + date");
        std::cout << std::endl;
        if (failed == 0)
            std::cout << "    " << Color::okBold << Sym::check << "  " << passed << " passed"
                      << Color::reset << Color::muted << " / 0 failed / " << total << " total"
                      << Color::reset << std::endl;
        else
            std::cout << "    " << Color::errorBold << Sym::cross << "  "
                      << Color::ok << passed << " passed" << Color::reset
                      << " / " << Color::error << failed << " failed" << Color::reset
                      << " / " << total << " total" << std::endl;
    }

    return failed == 0;
}

// ---------------------------------------------------------------------------
//  KDF override parsing
// ---------------------------------------------------------------------------
bool parseSizeWithSuffix(const std::string& s, std::size_t& out) {
    if (s.empty()) return false;
    char last = s.back();
    std::string num = s;
    std::uint64_t mult = 1ULL;
    if (last == 'K' || last == 'k') { mult = 1024ULL; num = s.substr(0, s.size() - 1); }
    else if (last == 'M' || last == 'm') { mult = 1024ULL * 1024ULL; num = s.substr(0, s.size() - 1); }
    else if (last == 'G' || last == 'g') { mult = 1024ULL * 1024ULL * 1024ULL; num = s.substr(0, s.size() - 1); }
    try {
        out = static_cast<std::size_t>(std::stoull(num) * mult);
        return true;
    } catch (...) { return false; }
}


void showOutdatedVersionWarning(bool ansi) {
#ifdef _WIN32
    // only proceed if we successfully queried a remote version
    if (!gRemoteVersionInfo.checked || !gRemoteVersionInfo.succeeded) return;
    // if not outdated, do not block the user - the main menu will print a green status
    if (!gRemoteVersionInfo.outdated) return;
#else
    if (!isProgramOutdated()) return;
#endif
#ifdef _WIN32
    std::string latest = formatAppVersion(gRemoteVersionInfo.latestVersion);
    std::string current = formatAppVersion(kCurrentAppVersion);
    std::string popupText = std::string("This program is outdated.\n\n") +
        "You're using " + current + "\n" +
        "Latest available: " + latest + "\n\n" +
        "You can download the latest version\n" +
        "\nThis message will also appear in the console with the download link.";
    // try to disable console input / echo while the popup is visible so
    // keystrokes typed by the user while the dialog is open are not buffered
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    DWORD prevMode = 0;
    bool modeSaved = false;
    if (hIn != INVALID_HANDLE_VALUE && GetConsoleMode(hIn, &prevMode)) {
        modeSaved = true;
        DWORD newMode = prevMode & ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT);
        SetConsoleMode(hIn, newMode);
    }

    // show top-most popup and request foreground to improve focus behavior
    MessageBoxW(nullptr,
                utf8ToWide(popupText).c_str(),
                utf8ToWide(std::string(kAppExeName) + " update warning").c_str(),
                MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND | MB_TOPMOST);

    // flush any buffered input and restore previous console mode
    if (hIn != INVALID_HANDLE_VALUE) {
        FlushConsoleInputBuffer(hIn);
        if (modeSaved) SetConsoleMode(hIn, prevMode);
    }
#endif
    clearConsole(ansi);
    printBanner();
    printDivider();
    printSection("update warning");
    // keep console output minimal: advise user to download latest and provide
    // the URL here (the popup intentionally omits the direct link)
    printWarn("this program is outdated, you're using " + current + ", you can download the latest version");
    if (!gRemoteVersionInfo.downloadUrl.empty())
        printNote("from here: " + gRemoteVersionInfo.downloadUrl);
    std::cout << std::endl;
    printDivider();
    std::cout << std::endl;
    printPrompt("press enter to continue");
    std::string dummy;
    std::getline(std::cin, dummy);
}
void loadKdfOverrides() {
    constexpr std::size_t kMaxIterations = 100000000; // 100 M
    constexpr std::size_t kMaxMemory = std::size_t{2} * 1024 * 1024 * 1024; // 2 GiB
    if (const char* e = std::getenv("THERAPIST_KDF_ITERATIONS")) {
        try {
            std::size_t v = static_cast<std::size_t>(std::stoull(e));
            if (v > 0) gKdfIterations = std::min(v, kMaxIterations);
        } catch (...) {}
    }
    if (const char* e = std::getenv("THERAPIST_KDF_MEMORY_BYTES")) {
        std::size_t v = 0;
        if (parseSizeWithSuffix(std::string(e), v) && v > 0)
            gKdfMemoryBytes = std::min(v, kMaxMemory);
    }
}

// ---------------------------------------------------------------------------
//  password strength evaluation
// ---------------------------------------------------------------------------
struct PasswordStrength {
    int score;
    std::string rating;
    std::vector<std::string> warnings;
};

PasswordStrength evaluatePassword(const std::string& pass) {
    PasswordStrength result;
    result.score = 0;
    if (pass.size() >= 16)      result.score += 30;
    else if (pass.size() >= 12) result.score += 25;
    else if (pass.size() >= 8)  result.score += 15;
    else if (pass.size() >= 6)  result.score += 8;
    else                        result.score += 3;

    bool hasUp = false, hasLo = false, hasDig = false, hasSp = false;
    for (unsigned char ch : pass) {
        if (std::isupper(ch))      hasUp = true;
        else if (std::islower(ch)) hasLo = true;
        else if (std::isdigit(ch)) hasDig = true;
        else                       hasSp = true;
    }
    int variety = (hasUp?1:0) + (hasLo?1:0) + (hasDig?1:0) + (hasSp?1:0);
    result.score += variety * 10;

    std::string sorted = pass;
    std::sort(sorted.begin(), sorted.end());
    auto last = std::unique(sorted.begin(), sorted.end());
    std::size_t unique = static_cast<std::size_t>(std::distance(sorted.begin(), last));
    if (unique >= 10)     result.score += 20;
    else if (unique >= 6) result.score += 10;
    else                  result.score += 3;

    if (unique == 1) {
        result.score = std::max(0, result.score - 30);
        result.warnings.push_back("all characters are the same");
    }

    // normalize (lowercase + common leet substitutions) (WORD LIST IS AI GENERATED)
    auto normalizeLeet = [](const std::string& s) -> std::string {
        std::string out;
        out.reserve(s.size());
        for (unsigned char ch : s) {
            switch (ch) {
                case '@': out.push_back('a'); break;
                case '3': out.push_back('e'); break;
                case '1': case '!': out.push_back('i'); break;
                case '0': out.push_back('o'); break;
                case '5': case '$': out.push_back('s'); break;
                default: out.push_back(static_cast<char>(std::tolower(ch))); break;
            }
        }
        return out;
    };

    std::string norm = normalizeLeet(pass);

    static const char* commonWords[] = {
        "password", "123456", "12345678", "123456789", "1234567890",
        "qwerty", "qwerty123", "qwertyuiop", "asdfgh", "asdfghjkl",
        "letmein", "welcome", "admin", "root", "toor",
        "password123", "1234567", "123123", "123321",
        "123456a", "123456abc", "password1", "password12", "password!",
        "login", "princess", "dragon", "master", "shadow",
        "sunshine", "trustno1", "baseball", "football", "basketball",
        "soccer", "hockey", "tennis", "golf", "racing",
        "iloveyou", "lovely", "loveme", "loveyou", "babygirl",
        "babyboy", "princess1", "princess123", "queen", "king",
        "monkey", "monkey123", "chocolate", "cookie", "banana",
        "apple", "cherry", "dragon1", "dragon123", "master1",
        "master123", "shadow1", "shadow123", "sunshine1", "sunshine123",
        // keyboard patterns
        "qwerty", "qwertz", "azerty", "qazwsx", "wsxedc", "edcrfv",
        "rfvtgb", "tgbzhn", "yhnujm", "ujmikol", "plmokn", "ijnbhu",
        "zaq12wsx", "1qaz2wsx", "1q2w3e4r", "1q2w3e", "q1w2e3r4",
        "asdzxc", "zxcvbn", "zxcvbnm", "poiuyt", "lkjhgf", "mnbvcx",
        "qweasd", "wasd", "wasdqwer", "qwerasdf", "zxcvasdf",
        "1234qwer", "qwer1234", "asdf1234", "1234asdf", "1q2w3e4r5t",
        // context-specific
        "therapist", "encrypt", "encrypted", "decrypt", "decrypted",
        "cipher", "crypto", "cryptography", "security", "secure",
        "unsafe", "pass123", "passw0rd", "p@ssword", "p@ssw0rd",
        "secret", "secret123", "hidden", "private", "vault", "safe",
        "lock", "unlock", "key", "aes", "rsa", "sha256", "hash", "salt",
        // common dictionary words
        "hello", "world", "test", "testing", "demo", "example",
        "sample", "user", "username", "name", "first", "last",
        "firstlast", "lastname", "firstname", "initial", "temp",
        "temporary", "default", "standard", "normal", "common",
        "general", "public", "private", "shared", "personal",
        // sports teams & terms
        "yankees", "redsox", "lakers", "warriors", "cowboys",
        "steelers", "packers", "patriots", "chelsea", "arsenal",
        "manutd", "realmadrid", "barcelona", "juventus", "bayern",
        "manchester", "liverpool", "tottenham", "dodgers", "cubs",
        // common names
        "michael", "jennifer", "james", "john", "robert", "david",
        "mary", "patricia", "linda", "barbara", "elizabeth", "susan",
        "jessica", "sarah", "karen", "nancy", "lisa", "betty",
        "daniel", "chris", "christopher", "matthew", "anthony", "mark",
        "donald", "steven", "paul", "andrew", "joshua", "kevin",
        "brian", "george", "edward", "ronald", "timothy", "jason",
        "jeffrey", "ryan", "jacob", "gary", "nicholas", "eric",
        "jonathan", "stephen", "larry", "justin", "scott", "brandon",
        "benjamin", "samuel", "frank", "gregory", "raymond", "alexander",
        "patrick", "jack", "dennis", "jerry", "tyler", "aaron",
        // pet names
        "buster", "buddy", "rocky", "lucky", "lady", "shadow",
        "sammy", "bear", "tiger", "coco", "bailey", "max",
        "maxwell", "charlie", "bella", "luna", "lucy", "daisy",
        "molly", "maggy", "sadie", "chloe", "lily",
        // dates & numbers
        "2024", "2025", "2026", "2023", "2022", "2021", "2020",
        "2000", "1999", "1998", "1997", "1996", "1995", "1990",
        "1980", "1234", "4321", "6969", "1111", "0000", "7777",
        "6666", "8888", "9999", "1010", "1212", "1221", "2112",
        // profanity
        "fuckyou", "fuckoff", "shithead", "asshole", "bitch",
        "bastard", "damnit", "crap", "piss", "screwyou",
        // l33t bases
        "hacker", "hack", "crack", "cracker", "phreak", "phreaker",
        "warez", "pirate", "torrent", "download", "upload",
        "administrator", "system", "sysadmin", "webmaster", "host",
        "server", "database", "network", "internet", "online",
        "offline", "desktop", "laptop", "mobile", "phone",
        "iphone", "android", "windows", "linux", "ubuntu",
        "debian", "fedora", "chrome", "firefox", "safari",
        "google", "facebook", "twitter", "instagram", "snapchat",
        "reddit", "youtube", "amazon", "netflix", "spotify",
        "paypal", "bank", "money", "cash", "dollar", "euro",
        "bitcoin", "crypto", "wallet", "account", "member",
        "subscribe", "free", "access", "entry", "allowed",
        // keyboard walks extended
        "qwe", "wer", "ert", "rty", "tyu", "yui", "uio", "iop",
        "asd", "sdf", "dfg", "fgh", "ghj", "hjk", "jkl", "kl",
        "zxc", "xcv", "cvb", "vbn", "bnm", "nm", "qaz", "wsx",
        "edc", "rfv", "tgb", "yhn", "ujm", "ikl", "ol", "p",
        // doubles/triples
        "abc", "abcd", "abcde", "abcdef", "abcdefg", "hijklmnop",
        "xyz", "xxx", "ooo", "aaa", "bbb", "ccc", "ddd", "eee",
        "fff", "ggg", "hhh", "iii", "jjj", "kkk", "lll", "mmm",
        "nnn", "ppp", "qqq", "rrr", "sss", "ttt", "uuu", "vvv",
        "www", "yyy", "zzz"
    };
    const std::size_t commonWordsCount = sizeof(commonWords) / sizeof(commonWords[0]);
    static std::unordered_set<std::string> commonWordSet;
    static bool commonWordSetInited = false;
    if (!commonWordSetInited) {
        commonWordSet.reserve(commonWordsCount * 2);
        for (std::size_t i = 0; i < commonWordsCount; ++i)
            commonWordSet.insert(std::string(commonWords[i]));
        commonWordSetInited = true;
    }

    // exact match of normalized password
    if (commonWordSet.find(norm) != commonWordSet.end()) {
        result.score = std::max(0, result.score - 20);
        result.warnings.push_back(std::string("contains common word: ") + norm);
    } else {
        // substring check (catch embedded common words)
        for (std::size_t i = 0; i < commonWordsCount; ++i) {
            if (norm.find(commonWords[i]) != std::string::npos) {
                result.score = std::max(0, result.score - 20);
                result.warnings.push_back(std::string("contains common word: ") + commonWords[i]);
                break;
            }
        }
    }

    if (pass.size() > 3) {
        bool sequential = true;
        for (std::size_t i = 1; i < pass.size() && sequential; ++i) {
            if (static_cast<unsigned char>(pass[i]) !=
                static_cast<unsigned char>(pass[i - 1]) + 1)
                sequential = false;
        }
        if (sequential) {
            result.score = std::max(0, result.score - 15);
            result.warnings.push_back("characters are sequential");
        }
    }

    if (pass.size() < 8)  result.warnings.push_back("shorter than 8 characters");
    if (!hasUp)            result.warnings.push_back("no uppercase letters");
    if (!hasLo)            result.warnings.push_back("no lowercase letters");
    if (!hasDig)           result.warnings.push_back("no digits");
    if (!hasSp)            result.warnings.push_back("no special characters");

    result.score = std::min(100, std::max(0, result.score));
    if (result.score >= 80)      result.rating = "very strong";
    else if (result.score >= 60) result.rating = "strong";
    else if (result.score >= 40) result.rating = "fair";
    else if (result.score >= 20) result.rating = "weak";
    else                         result.rating = "very weak";

    return result;
}

bool checkPasswordAcceptable(std::string& passphrase) {
    // allow the user to retry entering a passphrase if they decline weak-password confirmations
    while (true) {
        if (passphrase.empty()) {
            printFail("passphrase cannot be empty");
            return false;
        }
        if (static_cast<int>(passphrase.size()) < gSettings.minPasswordLength) {
            printFail("password must be at least " +
                      std::to_string(gSettings.minPasswordLength) + " characters");
            return false;
        }

        bool hasUp = false, hasLo = false, hasDig = false, hasSp = false;
        for (unsigned char ch : passphrase) {
            if (std::isupper(ch))      hasUp = true;
            else if (std::islower(ch)) hasLo = true;
            else if (std::isdigit(ch)) hasDig = true;
            else                       hasSp = true;
        }
        if (gSettings.requireUppercase && !hasUp) {
            printFail("password must contain uppercase letters");
            return false;
        }
        if (gSettings.requireLowercase && !hasLo) {
            printFail("password must contain lowercase letters");
            return false;
        }
        if (gSettings.requireDigit && !hasDig) {
            printFail("password must contain digits");
            return false;
        }
        if (gSettings.requireSpecial && !hasSp) {
            printFail("password must contain special characters");
            return false;
        }

        auto strength = evaluatePassword(passphrase);

        const char* color = Color::error;
        if (strength.score >= 80)      color = Color::okBold;
        else if (strength.score >= 60) color = Color::ok;
        else if (strength.score >= 40) color = Color::warn;
        else if (strength.score >= 20) color = Color::warnBold;

        // show evaluated password strength to the user
        std::cout << "    " << color << "password strength: " << strength.rating
              << " (" << strength.score << "/100)" << Color::reset << std::endl;

        if (gSettings.confirmWeakPasswords && strength.score < 40) {
            // print any heuristic warnings found during evaluation
            for (const auto& w : strength.warnings)
                printWarn(w);

            printPrompt("weak password! are you sure? (y/n):");
            std::string yn;
            if (!std::getline(std::cin, yn)) return false;
            yn = trimCopy(yn);
            if (yn == "y" || yn == "Y") {
                printPrompt("really proceed with this weak password? (y/n):");
                if (!std::getline(std::cin, yn)) return false;
                yn = trimCopy(yn);
                if (yn == "y" || yn == "Y") return true;
            }

            // user declined � offer to enter a new password instead of returning to menu
            printPrompt("enter a new passphrase (leave empty to cancel):");
            std::string newp;
            if (!std::getline(std::cin, newp)) return false;
            newp = trimCopy(newp);
            if (newp.empty()) return false; // cancel -> propagate false to caller
            passphrase = newp; // loop and re-evaluate
            continue;
        }

        return true;
    }
}

void syncSettingsToGlobals() {
    gKdfIterations  = gSettings.kdfIterations;
    gKdfMemoryBytes = gSettings.kdfMemoryBytes;
}

void setChaffMinSetting(std::size_t value, bool& adjustedMax) {
    adjustedMax = false;
    gSettings.chaffMin = value;
    if (gSettings.chaffMin > gSettings.chaffMax) {
        gSettings.chaffMax = gSettings.chaffMin;
        adjustedMax = true;
    }
}

void setChaffMaxSetting(std::size_t value, bool& adjustedMin) {
    adjustedMin = false;
    gSettings.chaffMax = value;
    if (gSettings.chaffMax < gSettings.chaffMin) {
        gSettings.chaffMin = gSettings.chaffMax;
        adjustedMin = true;
    }
}

} // namespace therapist

// ===========================================================================
//  main
// ===========================================================================
using namespace therapist;

int main(int argc, char* argv[]) {
    const bool ansi = enableAnsiColors();
    applyConsoleTitle();
    loadKdfOverrides();
    gSettings.kdfIterations = gKdfIterations;
    gSettings.kdfMemoryBytes = gKdfMemoryBytes;

    // parse CLI arguments
    bool requestSelfTest = false;
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) {
        std::string a(argv[i]);
        if (a.rfind("--kdf-iterations=", 0) == 0) {
            constexpr std::size_t kMaxIter = 100000000;
            try { std::size_t v = std::stoull(a.substr(17)); if (v > 0) gKdfIterations = std::min(v, kMaxIter); } catch (...) {}
            continue;
        }
        if (a.rfind("--kdf-memory=", 0) == 0) {
            constexpr std::size_t kMaxMem = std::size_t{2} * 1024 * 1024 * 1024;
            std::size_t v = 0;
            if (parseSizeWithSuffix(a.substr(13), v) && v > 0) gKdfMemoryBytes = std::min(v, kMaxMem);
            continue;
        }
        if (a == "--self-test") { requestSelfTest = true; continue; }
        args.push_back(a);
    }

    // startup self-test (quick, silent)
    if (!requestSelfTest) {
        bool ok = runSelfTest(false);
        if (!ok) {
            std::cerr << "    " << Color::errorBold << Sym::cross
                      << "  startup self-test failed -- the program may not work correctly"
                      << Color::reset << std::endl;
        }
    }

    // explicit self-test mode
    if (requestSelfTest) {
        clearConsole(ansi);
        printBanner();
        printDivider();
        std::cout << std::endl;
        printNote("running self-tests...");
        std::cout << std::endl;
        bool ok = runSelfTest(true);
        std::cout << std::endl;
        printDivider();
        std::cout << std::endl;
        std::cout << (ok
            ? (std::string("    ") + Color::okBold + Sym::check + "  all tests passed" + Color::reset)
            : (std::string("    ") + Color::errorBold + Sym::cross + "  some tests failed" + Color::reset))
            << std::endl;
        return ok ? 0 : 2;
    }

    // non-interactive CLI mode
    if (args.size() == 2) {
        // encrypt: therapist <file> <passphrase>
        const std::string inPath = args[0];
        const std::string passphrase = args[1];
        const std::string outPath = buildEncryptedPath(inPath);

        printNote("encrypting " + extractFilename(inPath) + "...");
        ByteVector data = readBinaryFile(inPath);
        FileMetadata meta{extractFilename(inPath), currentDateString()};
        ByteVector enc = withSpinner("deriving key", [&]() {
            return encryptPayload(data, passphrase, meta);
        });
        writeBinaryFile(outPath, enc);
        setEncryptedFileTimestamps(outPath);
        printOk("encrypted -> " + outPath);
        return 0;
    }
    if (args.size() == 3 && args[0] == "decrypt") {
        // decrypt: therapist decrypt <file> <passphrase>
        const std::string inPath = args[1];
        const std::string passphrase = args[2];

        printNote("decrypting " + extractFilename(inPath) + "...");
        ByteVector data = readBinaryFile(inPath);
        DecryptResult result = withSpinner("deriving key", [&]() {
            return decryptPayload(data, passphrase);
        });
        const std::string outPath = buildDecryptedPath(inPath, result.meta.originalName);
        writeBinaryFile(outPath, result.plaintext);
        if (!result.meta.originalName.empty())
            printNote("original: " + result.meta.originalName + "  (" + result.meta.date + ")");
        printOk("decrypted -> " + outPath);
        return 0;
    }

    // ---------------------------------------------------------------------------
    //  interactive mode
    // ---------------------------------------------------------------------------
    const std::string exeDir = executableDirectory(argc, argv);

    auto waitForMenu = [&]() {
        std::cout << std::endl;
        printDivider();
        printPrompt("press enter to return");
        std::string dummy;
        std::getline(std::cin, dummy);
        clearConsole(ansi);
    };

    // initialize current app version from env or compiled default string
    {
        const char* envv = std::getenv("THERAPIST_CURRENT_VERSION");
        std::string cur = envv && envv[0] ? trimCopy(std::string(envv)) : std::string(kCurrentVersionText);
        AppVersion parsed{0,0,0, std::string()};
        if (parseAppVersionText(cur, parsed)) {
            kCurrentAppVersion = parsed;
        }
    }

    runRemoteVersionCheck();
    showOutdatedVersionWarning(ansi);

    while (true) {
        try {
            clearConsole(ansi);
            printBanner();
            printDivider();
            std::cout << std::endl;
            std::cout << "    " << Color::accent << "[1]" << Color::reset << "  encrypt a file" << std::endl;
            std::cout << "    " << Color::accent << "[2]" << Color::reset << "  decrypt a file" << std::endl;
            std::cout << "    " << Color::accent << "[3]" << Color::reset << "  write an encrypted message" << std::endl;
            std::cout << "    " << Color::accent << "[4]" << Color::reset << "  read an encrypted message" << std::endl;
            std::cout << "    " << Color::accent << "[5]" << Color::reset << "  run self-test" << std::endl;
            std::cout << "    " << Color::accent << "[6]" << Color::reset << "  settings" << std::endl;
            std::cout << "    " << Color::accent << "[0]" << Color::reset << "  exit" << std::endl;
            std::cout << std::endl;
            printDivider();
            std::cout << std::endl;
            if (gRemoteVersionInfo.checked && gRemoteVersionInfo.succeeded) {
                if (gRemoteVersionInfo.outdated) {
                    printWarn("program is outdated, you're using " + formatAppVersion(kCurrentAppVersion) + " please download the latest version");
                } else {
                    printOk("program is up to date, you're using " + formatAppVersion(kCurrentAppVersion));
                }
                std::cout << std::endl;
            }
            printPrompt("choose:");
            std::string choice;
            if (!std::getline(std::cin, choice)) break;
            choice = trimCopy(choice);
            if (choice.empty()) continue;
            char c = choice[0];

            // ---- exit ----
            if (c == '0' || c == 'q' || c == 'Q') break;

            // ---- encrypt file ----
            if (c == '1') {
                clearConsole(ansi);
                printBanner();
                printDivider();
                printSection("encrypt a file");

                printPrompt("file path:");
                std::string filePath;
                if (!std::getline(std::cin, filePath)) continue;
                filePath = trimCopy(filePath);
                if (filePath.empty()) { printFail("no file specified"); waitForMenu(); continue; }

                // strip surrounding quotes if present
                if (filePath.size() >= 2 &&
                    ((filePath.front() == '"' && filePath.back() == '"') ||
                     (filePath.front() == '\'' && filePath.back() == '\'')))
                    filePath = filePath.substr(1, filePath.size() - 2);

                if (!fileExists(filePath)) {
                    printFail("file not found: " + filePath);
                    waitForMenu(); continue;
                }

                ByteVector data = readBinaryFile(filePath);
                if (gSettings.showDetails)
                    printNote("file size: " + formatFileSize(data.size()));

                printPrompt("passphrase:");
                std::string passphrase;
                if (!std::getline(std::cin, passphrase)) continue;
                if (!checkPasswordAcceptable(passphrase)) {
                    waitForMenu(); continue;
                }

                // optional custom output name
                printPrompt("output name (enter to skip):");
                std::string customName;
                std::getline(std::cin, customName);
                customName = trimCopy(customName);

                std::string outPath = customName.empty()
                    ? buildEncryptedPath(filePath)
                    : customName;

                FileMetadata meta{extractFilename(filePath), currentDateString()};

                std::cout << std::endl;
                ByteVector enc = withSpinner("deriving encryption key", [&]() {
                    return encryptPayload(data, passphrase, meta);
                });
                writeBinaryFile(outPath, enc);
                if (gSettings.spoofTimestamps)
                    setEncryptedFileTimestamps(outPath);

                printOk("encrypted -> " + outPath);
                if (gSettings.showDetails)
                    printNote("original name stored: " + meta.originalName + "  (" + meta.date + ")");
                if (gSettings.deleteSourceAfterEncrypt) {
                    if (std::remove(filePath.c_str()) == 0)
                        printOk("source file deleted: " + filePath);
                    else
                        printWarn("could not delete source file");
                }
                waitForMenu();
                continue;
            }

            // ---- decrypt file ----
            if (c == '2') {
                clearConsole(ansi);
                printBanner();
                printDivider();
                printSection("decrypt a file");

                printPrompt("encrypted file path:");
                std::string filePath;
                if (!std::getline(std::cin, filePath)) continue;
                filePath = trimCopy(filePath);
                if (filePath.empty()) { printFail("no file specified"); waitForMenu(); continue; }

                if (filePath.size() >= 2 &&
                    ((filePath.front() == '"' && filePath.back() == '"') ||
                     (filePath.front() == '\'' && filePath.back() == '\'')))
                    filePath = filePath.substr(1, filePath.size() - 2);

                if (!fileExists(filePath)) {
                    printFail("file not found: " + filePath);
                    waitForMenu(); continue;
                }

                printPrompt("passphrase:");
                std::string passphrase;
                if (!std::getline(std::cin, passphrase)) continue;
                if (passphrase.empty()) {
                    printFail("passphrase cannot be empty");
                    waitForMenu(); continue;
                }

                ByteVector data = readBinaryFile(filePath);
                if (gSettings.showDetails)
                    printNote("file size: " + formatFileSize(data.size()));

                std::cout << std::endl;
                DecryptResult result = withSpinner("deriving decryption key", [&]() {
                    return decryptPayload(data, passphrase);
                });

                if (!result.meta.originalName.empty()) {
                    printNote("original file: " + result.meta.originalName
                              + "  (" + result.meta.date + ")");
                }

                std::string outPath = buildDecryptedPath(filePath, result.meta.originalName);

                // ask before overwriting
                if (fileExists(outPath)) {
                    printWarn("file already exists: " + outPath);
                    printPrompt("overwrite? (y/n):");
                    std::string yn;
                    std::getline(std::cin, yn);
                    if (trimCopy(yn) != "y" && trimCopy(yn) != "Y") {
                        outPath = filePath + ".decrypted";
                        printNote("saving as: " + outPath);
                    }
                }

                writeBinaryFile(outPath, result.plaintext);
                printOk("decrypted -> " + outPath);
                waitForMenu();
                continue;
            }

            // ---- write message ----
            if (c == '3') {
                clearConsole(ansi);
                printBanner();
                printDivider();
                printSection("write an encrypted message");

                printPrompt("what would you like to tell me?:");
                std::string message;
                if (!std::getline(std::cin, message)) continue;
                if (message.empty()) {
                    printFail("you have to tell me something to hide your secret");
                    waitForMenu(); continue;
                }

                printPrompt("passphrase:");
                std::string passphrase;
                if (!std::getline(std::cin, passphrase)) continue;
                if (!checkPasswordAcceptable(passphrase)) {
                    waitForMenu(); continue;
                }

                std::uint64_t ts = currentTimeSeconds();
                ByteVector payload = buildMessagePayload(message, ts);
                FileMetadata meta{"message", currentDateString()};

                std::cout << std::endl;
                ByteVector enc = withSpinner("deriving key", [&]() {
                    return encryptPayload(payload, passphrase, meta);
                });

                std::string outPath = generateMessageFilePath(exeDir);
                writeBinaryFile(outPath, enc);
                if (gSettings.spoofTimestamps)
                    setEncryptedFileTimestamps(outPath);
                printOk("your secret has been saved to: " + outPath);
                waitForMenu();
                continue;
            }

            // ---- read message ----
            if (c == '4') {
                clearConsole(ansi);
                printBanner();
                printDivider();
                printSection("read an encrypted message");

                const auto available = listMessageFiles(exeDir);
                std::string msgFile;

                if (!available.empty()) {
                    std::cout << "    " << Color::accent << "available sessions:" << Color::reset << std::endl;
                    for (std::size_t i = 0; i < available.size(); ++i)
                        std::cout << "      " << Color::accent << "[" << (i + 1) << "]"
                                  << Color::reset << "  " << available[i] << std::endl;
                    std::cout << std::endl;
                    printDivider();
                    std::cout << std::endl;
                    printPrompt("choose (1-" + std::to_string(available.size()) + ") or filename:");
                    std::string sel;
                    if (!std::getline(std::cin, sel)) continue;
                    sel = trimCopy(sel);
                    if (isDigits(sel)) {
                        int idx = std::stoi(sel);
                        if (idx >= 1 && static_cast<std::size_t>(idx) <= available.size())
                            msgFile = available[static_cast<std::size_t>(idx) - 1];
                    }
                    if (msgFile.empty() && !sel.empty()) msgFile = sel;
                }

                if (msgFile.empty()) {
                    printPrompt("filename:");
                    if (!std::getline(std::cin, msgFile)) continue;
                    msgFile = trimCopy(msgFile);
                }

                if (msgFile.empty()) {
                    printFail("no file specified");
                    waitForMenu(); continue;
                }

                std::string resolved = resolveRelativeToExe(exeDir, msgFile);
                if (!fileExists(resolved)) {
                    printFail("file not found: " + resolved);
                    waitForMenu(); continue;
                }

                printPrompt("passphrase:");
                std::string passphrase;
                if (!std::getline(std::cin, passphrase)) continue;
                if (passphrase.empty()) {
                    printFail("passphrase cannot be empty");
                    waitForMenu(); continue;
                }

                ByteVector data = readBinaryFile(resolved);

                std::cout << std::endl;
                DecryptResult result = withSpinner("deriving key", [&]() {
                    return decryptPayload(data, passphrase);
                });

                std::string messageText;
                std::uint64_t timestamp = 0;
                if (parseMessagePayload(result.plaintext, messageText, timestamp)) {
                    std::cout << std::endl;
                    std::cout << "    " << Color::okBold << Sym::check << Color::reset
                              << "  this is what you told me"
                              << Color::muted << " (" << formatTimestamp(timestamp) << ")"
                              << Color::reset << std::endl;
                    std::cout << std::endl << "    ";
                    typeOutAnimated(messageText,
                                   std::chrono::milliseconds(70),
                                   std::chrono::milliseconds(220));
                    std::cout << std::endl;
                } else {
                    printWarn("unable to decode message format -- showing raw bytes");
                    if (!result.plaintext.empty())
                        std::cout.write(
                            reinterpret_cast<const char*>(result.plaintext.data()),
                            static_cast<std::streamsize>(result.plaintext.size()));
                    std::cout << std::endl;
                }
                waitForMenu();
                continue;
            }

            // ---- self-test ----
            if (c == '5') {
                clearConsole(ansi);
                printBanner();
                printDivider();
                std::cout << std::endl;
                printNote("running self-tests...");
                std::cout << std::endl;
                bool ok = runSelfTest(true);
                std::cout << std::endl;
                printDivider();
                std::cout << std::endl;
                std::cout << (ok
                    ? (std::string("    ") + Color::okBold + Sym::check + "  all tests passed" + Color::reset)
                    : (std::string("    ") + Color::errorBold + Sym::cross + "  some tests failed" + Color::reset))
                    << std::endl;
                waitForMenu();
                continue;
            }

            // ---- settings ----
            if (c == '6') {
                while (true) {
                    clearConsole(ansi);
                    printBanner();
                    printDivider();
                    printSection("settings");

                    auto onOff = [](bool v) -> const char* { return v ? "ON" : "OFF"; };

                    std::cout << "    " << Color::accent << " [1]" << Color::reset
                              << "  KDF iterations       : " << Color::info << gSettings.kdfIterations << Color::reset << std::endl;
                    std::cout << "    " << Color::accent << " [2]" << Color::reset
                              << "  KDF memory           : " << Color::info << formatFileSize(gSettings.kdfMemoryBytes) << Color::reset << std::endl;
                    std::cout << "    " << Color::accent << " [3]" << Color::reset
                              << "  chaff padding min    : " << Color::info << gSettings.chaffMin << " bytes" << Color::reset << std::endl;
                    std::cout << "    " << Color::accent << " [4]" << Color::reset
                              << "  chaff padding max    : " << Color::info << gSettings.chaffMax << " bytes" << Color::reset << std::endl;
                    std::cout << "    " << Color::accent << " [5]" << Color::reset
                              << "  spoof timestamps     : " << Color::info << onOff(gSettings.spoofTimestamps) << Color::reset << std::endl;
                    std::cout << "    " << Color::accent << " [6]" << Color::reset
                              << "  delete source        : " << Color::info << onOff(gSettings.deleteSourceAfterEncrypt) << Color::reset << std::endl;
                    std::cout << "    " << Color::accent << " [7]" << Color::reset
                              << "  min password length  : " << Color::info << gSettings.minPasswordLength << Color::reset << std::endl;
                    std::cout << "    " << Color::accent << " [8]" << Color::reset
                              << "  require uppercase    : " << Color::info << onOff(gSettings.requireUppercase) << Color::reset << std::endl;
                    std::cout << "    " << Color::accent << " [9]" << Color::reset
                              << "  require lowercase    : " << Color::info << onOff(gSettings.requireLowercase) << Color::reset << std::endl;
                    std::cout << "    " << Color::accent << "[10]" << Color::reset
                              << "  require digits       : " << Color::info << onOff(gSettings.requireDigit) << Color::reset << std::endl;
                    std::cout << "    " << Color::accent << "[11]" << Color::reset
                              << "  require special chars: " << Color::info << onOff(gSettings.requireSpecial) << Color::reset << std::endl;
                    std::cout << "    " << Color::accent << "[12]" << Color::reset
                              << "  confirm weak password: " << Color::info << onOff(gSettings.confirmWeakPasswords) << Color::reset << std::endl;
                    std::cout << "    " << Color::accent << "[13]" << Color::reset
                              << "  show details         : " << Color::info << onOff(gSettings.showDetails) << Color::reset << std::endl;
                    std::cout << "    " << Color::accent << "[14]" << Color::reset
                              << "  reset to defaults" << std::endl;
                    std::cout << "    " << Color::accent << " [0]" << Color::reset
                              << "  back to main menu" << std::endl;
                    std::cout << std::endl;
                    printDivider();
                    std::cout << std::endl;

                    printPrompt("setting #:");
                    std::string sel;
                    if (!std::getline(std::cin, sel)) break;
                    sel = trimCopy(sel);
                    if (sel.empty()) continue;
                    if (sel == "0") break;

                    auto readValue = [&](const std::string& label) -> std::string {
                        printPrompt(label);
                        std::string v;
                        std::getline(std::cin, v);
                        return trimCopy(v);
                    };

                    auto toggleBool = [](bool& v) { v = !v; };

                    if (sel == "1") {
                        std::string v = readValue("iterations (e.g. 131072):");
                        if (!v.empty()) {
                            try {
                                std::size_t n = std::stoull(v);
                                if (n >= 1024) {
                                    gSettings.kdfIterations = n;
                                    syncSettingsToGlobals();
                                    printOk("KDF iterations set to " + std::to_string(n));
                                } else printFail("minimum 1024 iterations");
                            } catch (...) { printFail("invalid number"); }
                        }
                    }
                    else if (sel == "2") {
                        std::string v = readValue("memory (e.g. 1M, 512K, 2M):");
                        if (!v.empty()) {
                            std::size_t n = 0;
                            if (parseSizeWithSuffix(v, n) && n >= 65536) {
                                gSettings.kdfMemoryBytes = n;
                                syncSettingsToGlobals();
                                printOk("KDF memory set to " + formatFileSize(n));
                            } else printFail("minimum 64 KB");
                        }
                    }
                    else if (sel == "3") {
                        std::string v = readValue("min chaff bytes (1-512):");
                        if (!v.empty()) {
                            try {
                                std::size_t n = std::stoull(v);
                                if (n >= 1 && n <= 512) {
                                    bool adjustedMax = false;
                                    setChaffMinSetting(n, adjustedMax);
                                    printOk("chaff min set to " + std::to_string(n));
                                    if (adjustedMax)
                                        printWarn("chaff max was raised to match the new minimum");
                                } else printFail("range: 1-512");
                            } catch (...) { printFail("invalid number"); }
                        }
                    }
                    else if (sel == "4") {
                        std::string v = readValue("max chaff bytes (1-1024):");
                        if (!v.empty()) {
                            try {
                                std::size_t n = std::stoull(v);
                                if (n >= 1 && n <= 1024) {
                                    bool adjustedMin = false;
                                    setChaffMaxSetting(n, adjustedMin);
                                    printOk("chaff max set to " + std::to_string(n));
                                    if (adjustedMin)
                                        printWarn("chaff min was lowered to match the new maximum");
                                } else printFail("range: 1-1024");
                            } catch (...) { printFail("invalid number"); }
                        }
                    }
                    else if (sel == "5") {
                        toggleBool(gSettings.spoofTimestamps);
                        printOk(std::string("timestamp spoofing ") + onOff(gSettings.spoofTimestamps));
                    }
                    else if (sel == "6") {
                        toggleBool(gSettings.deleteSourceAfterEncrypt);
                        printOk(std::string("delete source ") + onOff(gSettings.deleteSourceAfterEncrypt));
                    }
                    else if (sel == "7") {
                        std::string v = readValue("min password length (0-128):");
                        if (!v.empty()) {
                            try {
                                int n = std::stoi(v);
                                if (n >= 0 && n <= 128) {
                                    gSettings.minPasswordLength = n;
                                    printOk("min password length set to " + std::to_string(n));
                                } else printFail("range: 0-128");
                            } catch (...) { printFail("invalid number"); }
                        }
                    }
                    else if (sel == "8") {
                        toggleBool(gSettings.requireUppercase);
                        printOk(std::string("require uppercase ") + onOff(gSettings.requireUppercase));
                    }
                    else if (sel == "9") {
                        toggleBool(gSettings.requireLowercase);
                        printOk(std::string("require lowercase ") + onOff(gSettings.requireLowercase));
                    }
                    else if (sel == "10") {
                        toggleBool(gSettings.requireDigit);
                        printOk(std::string("require digits ") + onOff(gSettings.requireDigit));
                    }
                    else if (sel == "11") {
                        toggleBool(gSettings.requireSpecial);
                        printOk(std::string("require special chars ") + onOff(gSettings.requireSpecial));
                    }
                    else if (sel == "12") {
                        toggleBool(gSettings.confirmWeakPasswords);
                        printOk(std::string("confirm weak passwords ") + onOff(gSettings.confirmWeakPasswords));
                    }
                    else if (sel == "13") {
                        toggleBool(gSettings.showDetails);
                        printOk(std::string("show details ") + onOff(gSettings.showDetails));
                    }
                    else if (sel == "14") {
                        gSettings = EncryptionSettings{};
                        syncSettingsToGlobals();
                        printOk("all settings reset to defaults");
                    }
                    else {
                        printWarn("invalid option");
                    }

#ifdef _WIN32
                    ::Sleep(600);
#else
                    std::this_thread::sleep_for(std::chrono::milliseconds(600));
#endif
                }
                continue;
            }

            printWarn("invalid option");
            waitForMenu();
        }
        catch (const std::exception& ex) {
            printFail(std::string("error: ") + ex.what());
            waitForMenu();
        }
    }

    return 0;
}
