// therapist encrypter - single-file C++17 command-line encryption tool
// no external dependencies required

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
#else
#include <dirent.h>
#include <sys/mman.h>
#include <utime.h>
#endif

namespace therapist {

// ---------------------------------------------------------------------------
//  types
// ---------------------------------------------------------------------------
using ByteVector = std::vector<std::uint8_t>;

// ---------------------------------------------------------------------------
//  constants
// ---------------------------------------------------------------------------
// v5 (backward-compatible decrypt only)
constexpr std::array<std::uint8_t, 4> kMagicV5 = {'T', 'P', 'C', '5'};
constexpr std::uint8_t kVersionV5 = 5;

// v6 (current default -- adds embedded filename + date)
constexpr std::array<std::uint8_t, 4> kMagicV6 = {'T', 'P', 'C', '6'};
constexpr std::uint8_t kVersionV6 = 6;

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

// block cipher whitening constants (derived from pi and e)
constexpr std::uint64_t kWhitenA =
    0x3141592653589793ULL ^ 0x2718281828459045ULL;
constexpr std::uint64_t kWhitenB =
    0x6A09E667F3BCC908ULL ^ 0xBB67AE8584CAA73BULL;

// ---------------------------------------------------------------------------
//  colors
// ---------------------------------------------------------------------------
namespace Color {
    constexpr const char* reset   = "\033[0m";
    constexpr const char* accent  = "\033[38;5;214m";
    constexpr const char* muted   = "\033[38;5;244m";
    constexpr const char* warn    = "\033[38;5;208m";
    constexpr const char* error   = "\033[38;5;196m";
    constexpr const char* ok      = "\033[38;5;82m";
}

// ---------------------------------------------------------------------------
//  s-box (256-byte permutation, deterministic PRNG)
// ---------------------------------------------------------------------------
struct SBoxPair {
    std::array<std::uint8_t, 256> fwd;
    std::array<std::uint8_t, 256> inv;
    std::array<std::array<std::uint64_t, 256>, 8> fwd64{};
};

inline SBoxPair buildSBoxPair() {
    SBoxPair p;
    for (int i = 0; i < 256; ++i)
        p.fwd[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(i);
    std::uint32_t rng = 0x7A3B9E1DU;
    for (int i = 255; i > 0; --i) {
        rng = rng * 1103515245U + 12345U;
        int j = static_cast<int>(((rng >> 16) & 0x7FFFU) %
                                 static_cast<unsigned>(i + 1));
        std::swap(p.fwd[static_cast<std::size_t>(i)],
                  p.fwd[static_cast<std::size_t>(j)]);
    }
    for (int i = 0; i < 256; ++i)
        p.inv[p.fwd[static_cast<std::size_t>(i)]] =
            static_cast<std::uint8_t>(i);
    for (int lane = 0; lane < 8; ++lane) {
        const unsigned shift = static_cast<unsigned>(lane * 8U);
        for (int b = 0; b < 256; ++b)
            p.fwd64[static_cast<std::size_t>(lane)][static_cast<std::size_t>(b)] =
                static_cast<std::uint64_t>(p.fwd[static_cast<std::size_t>(b)]) << shift;
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
inline std::uint64_t rotl64(std::uint64_t v, unsigned s) {
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

inline std::uint64_t load64LE(const std::uint8_t* d) {
    std::uint64_t v;
    std::memcpy(&v, d, 8);
#if PLATFORM_LE
    return v;
#else
    return bswap64(v);
#endif
}

inline void store64LE(std::uint8_t* d, std::uint64_t v) {
#if PLATFORM_LE
    std::memcpy(d, &v, 8);
#else
    std::uint64_t t = bswap64(v);
    std::memcpy(d, &t, 8);
#endif
}

inline void incrementCounter(std::array<std::uint8_t, kBlockSize>& ctr) {
    std::uint64_t lo = load64LE(ctr.data());
    std::uint64_t hi = load64LE(ctr.data() + 8);
    ++lo;
    if (lo == 0ULL) ++hi;
    store64LE(ctr.data(), lo);
    store64LE(ctr.data() + 8, hi);
}

inline std::uint64_t applySBoxToWord(std::uint64_t w, const SBoxPair& sb) {
    std::uint64_t r = 0;
    for (unsigned i = 0; i < 8U; ++i) {
        std::uint8_t b = static_cast<std::uint8_t>((w >> (i * 8U)) & 0xFFU);
        r |= sb.fwd64[i][static_cast<std::size_t>(b)];
    }
    return r;
}

// ---------------------------------------------------------------------------
//  CSPRNG (OS entropy -- no std::random_device)
// ---------------------------------------------------------------------------
inline void fillCryptoRandom(std::uint8_t* buf, std::size_t len) {
    if (len == 0) return;
#ifdef _WIN32
    using RtlGenRandomPtr = BOOLEAN(WINAPI*)(PVOID, ULONG);
    static RtlGenRandomPtr fn = []() -> RtlGenRandomPtr {
        HMODULE mod = GetModuleHandleW(L"advapi32.dll");
        if (!mod) mod = LoadLibraryW(L"advapi32.dll");
        if (!mod) return nullptr;
        return reinterpret_cast<RtlGenRandomPtr>(
            GetProcAddress(mod, "SystemFunction036"));
    }();
    if (fn) {
        std::size_t off = 0;
        while (off < len) {
            ULONG chunk = static_cast<ULONG>(
                std::min<std::size_t>(len - off, 0xFFFFFFFFUL));
            if (!fn(buf + off, chunk))
                throw std::runtime_error("RtlGenRandom failed");
            off += chunk;
        }
        return;
    }
#else
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
    ByteVector salt(size);
    fillCryptoRandom(salt.data(), size);
    return salt;
}

// ---------------------------------------------------------------------------
//  secure memory helpers
// ---------------------------------------------------------------------------
inline void secureZero(void* p, std::size_t n) {
    if (!p || n == 0) return;
    volatile std::uint8_t* vp = reinterpret_cast<volatile std::uint8_t*>(p);
    for (std::size_t i = 0; i < n; ++i) vp[i] = 0;
}

inline void secureWipe(ByteVector& v) {
    if (!v.empty()) { secureZero(v.data(), v.size()); v.clear(); v.shrink_to_fit(); }
}

inline void secureWipe(std::string& s) {
    if (!s.empty()) { secureZero(&s[0], s.size()); s.clear(); s.shrink_to_fit(); }
}

inline bool lockMemory(void* p, std::size_t sz) {
#ifdef _WIN32
    return VirtualLock(p, static_cast<SIZE_T>(sz)) != 0;
#else
    return mlock(p, sz) == 0;
#endif
}

inline void unlockMemory(void* p, std::size_t sz) {
#ifdef _WIN32
    VirtualUnlock(p, static_cast<SIZE_T>(sz));
#else
    munlock(p, sz);
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
// MinGW: manual alignment via overallocation
inline void* alignedAlloc(std::size_t align, std::size_t sz) {
    if (align < sizeof(void*)) align = sizeof(void*);
    std::size_t total = sz + align + sizeof(void*);
    void* raw = std::malloc(total);
    if (!raw) return nullptr;
    void** aligned = reinterpret_cast<void**>(
        (reinterpret_cast<std::uintptr_t>(raw) + sizeof(void*) + align - 1) & ~(align - 1));
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

// RAII aligned buffer with optional memory lock and guaranteed zero-on-destruct
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
            secureZero(ptr, size);
            if (locked) unlockMemory(ptr, size);
            alignedFree(ptr);
        }
    }

    ScopedBuffer(const ScopedBuffer&) = delete;
    ScopedBuffer& operator=(const ScopedBuffer&) = delete;
};

// ---------------------------------------------------------------------------
//  key schedule
// ---------------------------------------------------------------------------
struct HardenedKeySchedule {
    std::array<std::uint64_t, 32> rka{};
    std::array<std::uint64_t, 32> rkb{};
    std::array<std::uint64_t, 32> rkc{};
    std::array<std::uint64_t, 4>  macSeeds{};
};

// RAII wiper for HardenedKeySchedule
struct ScopedKS {
    HardenedKeySchedule& ks;
    explicit ScopedKS(HardenedKeySchedule& k) : ks(k) {}
    ~ScopedKS() { secureZero(&ks, sizeof(ks)); }
    ScopedKS(const ScopedKS&) = delete;
    ScopedKS& operator=(const ScopedKS&) = delete;
};

// memory-hard key derivation
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
        stir(static_cast<std::uint8_t>(pass[i]), i + 4U);
    for (std::size_t i = 0; i < salt.size(); ++i)
        stir(salt[i], i + pass.size() + 4U);

    for (int p = 0; p < 3; ++p)
        for (int j = 0; j < 8; ++j) {
            st[j] ^= rotl64(st[(j + 1) & 7], 17U) + 0xC2B2AE3D27D4EB4FULL;
            st[j] = rotl64(st[j], static_cast<unsigned>((j * 7 + 5) % 64));
        }

    // phase 2: expand into scratch buffer
    std::size_t memBytes = (gKdfMemoryBytes / 8U) * 8U;
    const std::size_t words = memBytes / 8U;
    if (words <= 8U) throw std::invalid_argument("KDF memory too small");

    const char* lockEnv = std::getenv("THERAPIST_KDF_MLOCK");
    bool tryLock = lockEnv && lockEnv[0] != '\0';

    ScopedBuffer scratch(64, memBytes, tryLock);
    std::uint64_t* mem = static_cast<std::uint64_t*>(scratch.ptr);

    {
        std::size_t p = 0;
        for (std::size_t i = 0; i < words; ++i) {
            st[p & 7U] = rotl64(st[p & 7U], 17U) ^ st[(p + 3U) & 7U];
            st[p & 7U] += 0xC2B2AE3D27D4EB4FULL;
            mem[i] = st[p & 7U];
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
//  v5 block cipher
// ---------------------------------------------------------------------------
inline std::uint64_t enhancedRoundFunction(std::uint64_t half,
                                           std::uint64_t keyA,
                                           std::uint64_t keyB,
                                           std::uint64_t keyC)
{
    const auto& sb = sbox();
    half ^= keyA;
    half = applySBoxToWord(half, sb);
    half = rotl64(half, 19U);
    half += keyB;
    half ^= rotl64(half, 41U);
    half *= 0xD6E8FEB86659CDD9ULL;
    half ^= (half >> 33U);
    half = applySBoxToWord(half ^ keyC, sb);
    half = rotl64(half, 13U) ^ rotl64(half, 29U);
    half += keyA ^ keyC;
    half ^= (half >> 37U);
    return half;
}

inline void encryptBlockV5(std::uint64_t& L, std::uint64_t& R,
                           const HardenedKeySchedule& ks)
{
    L ^= ks.rka[0] ^ kWhitenA;
    R ^= ks.rkb[0] ^ kWhitenB;
    for (std::size_t r = 0; r < kRounds; ++r) {
        std::uint64_t f = enhancedRoundFunction(R, ks.rka[r], ks.rkb[r], ks.rkc[r]);
        std::uint64_t nL = R;
        R = L ^ f;
        L = nL;
    }
    L ^= ks.rka[kRounds - 1] ^ kWhitenB;
    R ^= ks.rkb[kRounds - 1] ^ kWhitenA;
}

// ---------------------------------------------------------------------------
//  CTR mode cipher (symmetric -- encrypt = decrypt)
// ---------------------------------------------------------------------------
inline std::array<std::uint8_t, kBlockSize> initCtrFromSalt(const ByteVector& salt) {
    std::array<std::uint8_t, kBlockSize> ctr{};
    std::uint64_t sL = 0x6A09E667F3BCC909ULL;
    std::uint64_t sR = 0xBB67AE8584CAA73BULL;
    for (std::size_t i = 0; i < salt.size(); ++i) {
        sL ^= static_cast<std::uint64_t>(salt[i]) << ((i % 8U) * 8U);
        sL = rotl64(sL, 9U);
        sR ^= static_cast<std::uint64_t>(salt[i]) << (((i + 3U) % 8U) * 8U);
        sR = rotl64(sR, 13U);
    }
    store64LE(ctr.data(), sL);
    store64LE(ctr.data() + 8, sR);
    return ctr;
}

void applyCipher(const ByteVector& in, ByteVector& out,
                 const HardenedKeySchedule& ks,
                 const ByteVector& salt)
{
    out.resize(in.size());
    auto ctr = initCtrFromSalt(salt);
    std::array<std::uint8_t, kBlockSize> ksBuf{};
    std::size_t off = 0;
    while (off < in.size()) {
        std::uint64_t l = load64LE(ctr.data());
        std::uint64_t r = load64LE(ctr.data() + 8);
        encryptBlockV5(l, r, ks);
        store64LE(ksBuf.data(), l);
        store64LE(ksBuf.data() + 8, r);
        std::size_t chunk = std::min<std::size_t>(kBlockSize, in.size() - off);
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
//  256-bit cascaded MAC
// ---------------------------------------------------------------------------
struct Mac256 { std::uint64_t h[4]; };

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

    inline void macFeedByte(Mac256& mac, std::uint8_t byte) {
        for (int i = 0; i < 4; ++i) {
            mac.h[i] ^= byte;
            mac.h[i] *= kMacPrimes[i];
            mac.h[i] ^= (mac.h[i] >> 33U);
        }
        mac.h[0] ^= rotl64(mac.h[3], 7U);
        mac.h[1] ^= rotl64(mac.h[0], 11U);
        mac.h[2] ^= rotl64(mac.h[1], 17U);
        mac.h[3] ^= rotl64(mac.h[2], 23U);
    }

    inline void macFeedBuffer(Mac256& mac, const std::uint8_t* buf, std::size_t len) {
        for (std::size_t i = 0; i < len; ++i)
            macFeedByte(mac, buf[i]);
    }

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
        for (unsigned char ch : pass) macFeedByte(mac, static_cast<std::uint8_t>(ch));
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
                mac.h[i] ^= rotl64(mac.h[(i + 1) & 3], 19U);
                mac.h[i] *= kMacPrimes[i];
                mac.h[i] ^= (mac.h[i] >> 29U);
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

// build augmented payload: chaff + metadata + plaintext (V6)
ByteVector buildAugmentedV6(const ByteVector& plain, const FileMetadata& meta) {
    std::uint8_t rndByte[1];
    fillCryptoRandom(rndByte, 1);
    std::size_t chaffLen = kChaffMin +
        (static_cast<std::size_t>(rndByte[0]) % (kChaffMax - kChaffMin + 1));

    // truncate name if needed
    std::string name = meta.originalName;
    if (name.size() > 0xFFFF) name.resize(0xFFFF);
    std::string date = meta.date;
    if (date.size() < kDateLen) date.resize(kDateLen, '0');
    if (date.size() > kDateLen) date.resize(kDateLen);

    ByteVector aug;
    aug.reserve(2 + chaffLen + 2 + name.size() + kDateLen + plain.size());

    // chaff header (2-byte LE length) + random chaff
    aug.push_back(static_cast<std::uint8_t>(chaffLen & 0xFFU));
    aug.push_back(static_cast<std::uint8_t>((chaffLen >> 8U) & 0xFFU));
    aug.resize(2 + chaffLen);
    fillCryptoRandom(aug.data() + 2, chaffLen);

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

// build augmented payload: chaff + plaintext (V5 legacy, no metadata)
ByteVector buildAugmentedV5(const ByteVector& plain) {
    std::uint8_t rndByte[1];
    fillCryptoRandom(rndByte, 1);
    std::size_t chaffLen = kChaffMin +
        (static_cast<std::size_t>(rndByte[0]) % (kChaffMax - kChaffMin + 1));

    ByteVector aug;
    aug.reserve(2 + chaffLen + plain.size());
    aug.push_back(static_cast<std::uint8_t>(chaffLen & 0xFFU));
    aug.push_back(static_cast<std::uint8_t>((chaffLen >> 8U) & 0xFFU));
    aug.resize(2 + chaffLen);
    fillCryptoRandom(aug.data() + 2, chaffLen);
    aug.insert(aug.end(), plain.begin(), plain.end());
    return aug;
}

// parse V6 augmented payload: extract metadata + plaintext
ByteVector parseAugmentedV6(const ByteVector& aug, FileMetadata& meta) {
    if (aug.size() < 2)
        throw std::runtime_error("authentication failed: wrong passphrase or corrupted data");

    // read chaff
    std::size_t chaffLen = static_cast<std::size_t>(aug[0]) |
                           (static_cast<std::size_t>(aug[1]) << 8U);
    if (chaffLen < kChaffMin || chaffLen > kChaffMax || 2 + chaffLen > aug.size())
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

// parse V5 augmented payload: just strip chaff
ByteVector parseAugmentedV5(const ByteVector& aug) {
    if (aug.size() < 2)
        throw std::runtime_error("authentication failed: wrong passphrase or corrupted data");

    std::size_t chaffLen = static_cast<std::size_t>(aug[0]) |
                           (static_cast<std::size_t>(aug[1]) << 8U);
    if (chaffLen < kChaffMin || chaffLen > kChaffMax || 2 + chaffLen > aug.size())
        throw std::runtime_error("authentication failed: wrong passphrase or corrupted data");

    return ByteVector(aug.begin() + 2 + static_cast<std::ptrdiff_t>(chaffLen),
                      aug.end());
}

// ---------------------------------------------------------------------------
//  encrypt / decrypt payloads
// ---------------------------------------------------------------------------
struct DecryptResult {
    ByteVector plaintext;
    FileMetadata meta; // populated for V6; empty for V5
    std::uint8_t version = 0;
};

// always encrypts as V6 (with embedded filename + date)
ByteVector encryptPayload(const ByteVector& plain,
                          const std::string& passphrase,
                          const FileMetadata& meta)
{
    ByteVector salt1 = generateSalt(kSaltSize);
    ByteVector salt2 = generateSalt(kSaltSize);

    ByteVector augmented = buildAugmentedV6(plain, meta);

    // first encryption pass
    auto ks1 = deriveHardenedSchedule(passphrase, salt1);
    ScopedKS w1(ks1);
    ByteVector pass1;
    applyCipher(augmented, pass1, ks1, salt1);

    // second encryption pass
    auto ks2 = deriveHardenedSchedule(passphrase, salt2);
    ScopedKS w2(ks2);
    ByteVector pass2;
    applyCipher(pass1, pass2, ks2, salt2);

    // MAC over original plaintext
    Mac256 mac = computeHardenedMac(plain, passphrase, salt1, salt2);

    // assemble output
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

// auto-detect V5 or V6; returns plaintext + metadata
DecryptResult decryptPayload(const ByteVector& input,
                             const std::string& passphrase)
{
    const std::size_t baseHdr = 4 + 3; // magic(4) + version(1) + saltLen(1) + macLen(1)
    if (input.size() < baseHdr)
        throw std::invalid_argument("encrypted data is too short");

    // detect version
    bool isV5 = std::equal(kMagicV5.begin(), kMagicV5.end(), input.begin());
    bool isV6 = std::equal(kMagicV6.begin(), kMagicV6.end(), input.begin());
    if (!isV5 && !isV6)
        throw std::runtime_error("encrypted data header mismatch");

    std::uint8_t version = input[4];
    if ((isV5 && version != kVersionV5) || (isV6 && version != kVersionV6))
        throw std::runtime_error("unsupported encrypted data version");

    std::uint8_t saltLen = input[5];
    std::uint8_t macLen  = input[6];
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
    if (isV6)
        result.plaintext = parseAugmentedV6(augmented, result.meta);
    else
        result.plaintext = parseAugmentedV5(augmented);

    // verify MAC
    Mac256 computed = computeHardenedMac(result.plaintext, passphrase, salt1, salt2);
    if (!constantTimeMacEq(computed, storedMac))
        throw std::runtime_error("authentication failed: wrong passphrase or corrupted data");

    secureWipe(pass1);
    secureWipe(augmented);
    return result;
}

// ---------------------------------------------------------------------------
//  file I/O
// ---------------------------------------------------------------------------
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
    // prefer original name from metadata
    if (!originalName.empty()) {
        // resolve into same directory as input
        auto pos = inputPath.find_last_of("\\/");
        if (pos != std::string::npos)
            return inputPath.substr(0, pos + 1) + originalName;
        return originalName;
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
    p.reserve(sizeof(kMessageMagic) + sizeof(ts) + msg.size());
    p.insert(p.end(), std::begin(kMessageMagic), std::end(kMessageMagic));
    for (int s = 56; s >= 0; s -= 8)
        p.push_back(static_cast<std::uint8_t>((ts >> s) & 0xFFU));
    p.insert(p.end(), msg.begin(), msg.end());
    return p;
}

bool parseMessagePayload(const ByteVector& data, std::string& msg, std::uint64_t& ts) {
    const std::size_t hs = sizeof(kMessageMagic) + sizeof(std::uint64_t);
    if (data.size() < hs) return false;
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
    if (localtime_s(&ti, &raw) != 0) return "unknown";
#else
    if (std::tm* tmp = std::localtime(&raw)) ti = *tmp;
    else return "unknown";
#endif
#else
    if (localtime_r(&raw, &ti) == nullptr) return "unknown";
#endif
    std::ostringstream oss;
    oss << std::put_time(&ti, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

std::vector<std::string> listMessageFiles(const std::string& dir) {
    std::vector<std::string> files;
#ifdef _WIN32
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
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    std::setlocale(LC_ALL, ".UTF-8");
    return true;
#else
    std::setlocale(LC_ALL, "en_US.UTF-8");
    return true;
#endif
}

void clearConsole(bool ansi) {
#ifdef _WIN32
    if (ansi) std::cout << "\033[2J\033[3J\033[H" << std::flush;
    else std::system("cls");
#else
    (void)ansi;
    std::cout << "\033[2J\033[3J\033[H" << std::flush;
#endif
}

void applyConsoleTitle() {
#ifdef _WIN32
    SetConsoleTitleW(L"therapist");
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

    for (std::size_t pos = 0; pos < title.size(); ++pos) {
        if (title[pos] == ' ') continue;
        for (int frame = 0; frame < resolveFrames; ++frame) {
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
    std::cout << Color::muted << "  ----------------------------------------"
              << Color::reset << std::endl;
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
    // save and override KDF params for speed
    std::size_t savedIter = gKdfIterations;
    std::size_t savedMem  = gKdfMemoryBytes;
    gKdfIterations  = 16;
    gKdfMemoryBytes = 65536; // 64 KB

    int passed = 0;
    int failed = 0;
    int total  = 0;

    auto restore = [&]() {
        gKdfIterations  = savedIter;
        gKdfMemoryBytes = savedMem;
    };

    auto runTest = [&](const char* name, const char* details, std::function<void()> fn) {
        ++total;
        if (verbose)
            std::cout << "  " << Color::muted << "[" << total << "] "
                      << Color::reset << name << "..." << std::flush;
        try {
            fn();
            ++passed;
            if (verbose) {
                std::cout << " " << Color::ok << "ok" << Color::reset << std::endl;
                std::cout << "    " << Color::muted << details << Color::reset << std::endl;
            }
        } catch (const std::exception& ex) {
            ++failed;
            if (verbose) {
                std::cout << " " << Color::error << "FAIL: " << ex.what()
                          << Color::reset << std::endl;
                std::cout << "    " << Color::muted << details << Color::reset << std::endl;
            }
        }
    };

    const std::string pass = "therapist-selftest";

    // --- crypto primitives ---

    runTest("sbox invertibility", "checked inv(fwd(x)) == x and fwd(inv(x)) == x for all bytes 0..255", [&]() {
        const auto& sb = sbox();
        for (int i = 0; i < 256; ++i) {
            std::uint8_t b = static_cast<std::uint8_t>(i);
            if (sb.inv[sb.fwd[b]] != b)
                throw std::runtime_error("inv(fwd(x)) != x");
            if (sb.fwd[sb.inv[b]] != b)
                throw std::runtime_error("fwd(inv(x)) != x");
        }
    });

    runTest("block cipher determinism", "encrypted same 128-bit block twice with same key; compared outputs are equal", [&]() {
        ByteVector salt = generateSalt(kSaltSize);
        auto ks = deriveHardenedSchedule(pass, salt);
        ScopedKS w(ks);
        std::uint64_t L1 = 0x0123456789ABCDEFULL, R1 = 0xFEDCBA9876543210ULL;
        std::uint64_t L2 = L1, R2 = R1;
        encryptBlockV5(L1, R1, ks);
        encryptBlockV5(L2, R2, ks);
        if (L1 != L2 || R1 != R2)
            throw std::runtime_error("same input gave different output");
    });

    runTest("ctr encrypt/decrypt identity", "applied CTR encrypt then decrypt; compared decrypted == original (200 bytes)", [&]() {
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

    runTest("mac consistency", "computed MAC twice for same input and salts; compared MACs equal", [&]() {
        ByteVector data = {'t','e','s','t'};
        ByteVector s1 = generateSalt(kSaltSize);
        ByteVector s2 = generateSalt(kSaltSize);
        Mac256 a = computeHardenedMac(data, pass, s1, s2);
        Mac256 b = computeHardenedMac(data, pass, s1, s2);
        if (!constantTimeMacEq(a, b))
            throw std::runtime_error("same input produced different MAC");
    });

    runTest("mac sensitivity", "computed MAC for different inputs with same salts; compared MACs differ", [&]() {
        ByteVector d1 = {'a'}, d2 = {'b'};
        ByteVector s1 = generateSalt(kSaltSize);
        ByteVector s2 = generateSalt(kSaltSize);
        Mac256 a = computeHardenedMac(d1, pass, s1, s2);
        Mac256 b = computeHardenedMac(d2, pass, s1, s2);
        if (constantTimeMacEq(a, b))
            throw std::runtime_error("different input produced same MAC");
    });

    // --- payload round-trips ---

    runTest("empty payload round-trip (V6)", "encrypt(empty) -> decrypt; checked plaintext empty and version==6", [&]() {
        FileMetadata m{"", currentDateString()};
        ByteVector enc = encryptPayload({}, pass, m);
        DecryptResult dec = decryptPayload(enc, pass);
        if (!dec.plaintext.empty())
            throw std::runtime_error("output not empty");
        if (dec.version != kVersionV6)
            throw std::runtime_error("version mismatch");
    });

    runTest("small payload + metadata verify", "after decrypt compared plaintext and metadata.originalName and metadata.date", [&]() {
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

    runTest("single-block payload (16 bytes)", "encrypted/decrypted exactly one block (16 bytes); compared equality", [&]() {
        ByteVector plain(kBlockSize, 0xAA);
        FileMetadata m{"block.bin", currentDateString()};
        ByteVector enc = encryptPayload(plain, pass, m);
        DecryptResult dec = decryptPayload(enc, pass);
        if (dec.plaintext != plain)
            throw std::runtime_error("mismatch at block boundary");
    });

    runTest("cross-block payload (17 bytes)", "encrypted/decrypted 17 bytes spanning blocks; compared equality", [&]() {
        ByteVector plain(kBlockSize + 1, 0xBB);
        FileMetadata m{"cross.bin", currentDateString()};
        ByteVector enc = encryptPayload(plain, pass, m);
        DecryptResult dec = decryptPayload(enc, pass);
        if (dec.plaintext != plain)
            throw std::runtime_error("mismatch at cross-block boundary");
    });

    runTest("large payload (4096 bytes)", "encrypted/decrypted large buffer (4096 bytes); compared equality", [&]() {
        ByteVector plain(4096);
        for (std::size_t i = 0; i < plain.size(); ++i)
            plain[i] = static_cast<std::uint8_t>(i & 0xFFU);
        FileMetadata m{"big.bin", currentDateString()};
        ByteVector enc = encryptPayload(plain, pass, m);
        if (verbose)
            std::cout << " [" << formatFileSize(enc.size()) << "]" << std::flush;
        DecryptResult dec = decryptPayload(enc, pass);
        if (dec.plaintext != plain)
            throw std::runtime_error("large payload mismatch");
    });

    // --- authentication tests ---

    runTest("wrong passphrase rejection", "attempted decrypt with wrong passphrase; expected failure (exception)", [&]() {
        ByteVector plain = {'x'};
        FileMetadata m{"x.bin", currentDateString()};
        ByteVector enc = encryptPayload(plain, pass, m);
        bool rejected = false;
        try { decryptPayload(enc, "wrong-pass"); }
        catch (...) { rejected = true; }
        if (!rejected)
            throw std::runtime_error("wrong passphrase accepted");
    });

    runTest("tampered ciphertext detection", "tampered last ciphertext byte; expected decryption to fail", [&]() {
        ByteVector plain = {'s','e','c','r','e','t'};
        FileMetadata m{"t.bin", currentDateString()};
        ByteVector enc = encryptPayload(plain, pass, m);
        // tamper with the last byte of ciphertext
        if (!enc.empty()) enc.back() ^= 0xFF;
        bool rejected = false;
        try { decryptPayload(enc, pass); }
        catch (...) { rejected = true; }
        if (!rejected)
            throw std::runtime_error("tampered ciphertext accepted");
    });

    runTest("tampered mac detection", "modified first MAC byte; expected MAC verification to fail", [&]() {
        ByteVector plain = {'m','a','c'};
        FileMetadata m{"m.bin", currentDateString()};
        ByteVector enc = encryptPayload(plain, pass, m);
        // MAC starts at offset 4+3+32+32 = 71
        std::size_t macOff = 4 + 3 + kSaltSize * 2;
        if (enc.size() > macOff) enc[macOff] ^= 0x01;
        bool rejected = false;
        try { decryptPayload(enc, pass); }
        catch (...) { rejected = true; }
        if (!rejected)
            throw std::runtime_error("tampered MAC accepted");
    });

    // --- file I/O ---

    runTest("file I/O round-trip", "wrote file, encrypted, decrypted, and compared resulting file contents match", [&]() {
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

    // --- message helpers ---

    runTest("message payload build/parse", "built message payload and parsed it; compared message and timestamp equality", [&]() {
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

    runTest("encrypted message round-trip", "encrypted message, decrypted and parsed; compared message equality after decrypt", [&]() {
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

    // cleanup any leftover test files
    std::remove("selftest_input.tmp");
    std::remove("selftest_enc.tmp");
    std::remove("selftest_dec.tmp");

    restore();

    // summary
    if (verbose) {
        std::cout << std::endl;
        std::cout << "  " << Color::muted << "cipher:     "
                  << Color::reset << "feistel V5/V6, " << kRounds << " rounds, "
                  << kBlockSize << "-byte block, double-pass CTR" << std::endl;
        std::cout << "  " << Color::muted << "kdf:        "
                  << Color::reset << savedIter << " iterations, "
                  << formatFileSize(savedMem) << " memory" << std::endl;
        std::cout << "  " << Color::muted << "mac:        "
                  << Color::reset << "256-bit cascaded (4x FNV-like)" << std::endl;
        std::cout << "  " << Color::muted << "salt:       "
                  << Color::reset << kSaltSize << " bytes (x2)" << std::endl;
        std::cout << "  " << Color::muted << "format:     "
                  << Color::reset << "V6 with embedded filename + date" << std::endl;
        std::cout << std::endl;
        std::cout << "  " << Color::muted << "results:    "
                  << Color::ok << passed << " passed"
                  << Color::reset << " / ";
        if (failed > 0)
            std::cout << Color::error << failed << " failed" << Color::reset;
        else
            std::cout << Color::muted << "0 failed" << Color::reset;
        std::cout << " / " << total << " total" << std::endl;
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

void loadKdfOverrides() {
    if (const char* e = std::getenv("THERAPIST_KDF_ITERATIONS")) {
        try { std::size_t v = static_cast<std::size_t>(std::stoull(e)); if (v > 0) gKdfIterations = v; } catch (...) {}
    }
    if (const char* e = std::getenv("THERAPIST_KDF_MEMORY_BYTES")) {
        std::size_t v = 0;
        if (parseSizeWithSuffix(std::string(e), v) && v > 0) gKdfMemoryBytes = v;
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

    // parse CLI arguments
    bool requestSelfTest = false;
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) {
        std::string a(argv[i]);
        if (a.rfind("--kdf-iterations=", 0) == 0) {
            try { std::size_t v = std::stoull(a.substr(17)); if (v > 0) gKdfIterations = v; } catch (...) {}
            continue;
        }
        if (a.rfind("--kdf-memory=", 0) == 0) {
            std::size_t v = 0;
            if (parseSizeWithSuffix(a.substr(13), v) && v > 0) gKdfMemoryBytes = v;
            continue;
        }
        if (a == "--self-test") { requestSelfTest = true; continue; }
        args.push_back(a);
    }

    // startup self-test (quick, silent)
    if (!requestSelfTest) {
        bool ok = runSelfTest(false);
        if (!ok) {
            std::cerr << Color::error
                      << "  [!] startup self-test failed -- the program may not work correctly"
                      << Color::reset << std::endl;
        }
    }

    // explicit self-test mode
    if (requestSelfTest) {
        clearConsole(ansi);
        printBanner();
        printDivider();
        std::cout << "  running self-tests...\n" << std::endl;
        bool ok = runSelfTest(true);
        printDivider();
        std::cout << (ok ? "  all tests passed" : "  some tests failed") << std::endl;
        return ok ? 0 : 2;
    }

    // non-interactive CLI mode
    if (args.size() == 2) {
        // encrypt: therapist <file> <passphrase>
        const std::string inPath = args[0];
        const std::string passphrase = args[1];
        const std::string outPath = buildEncryptedPath(inPath);

        std::cout << "  encrypting " << extractFilename(inPath) << "..." << std::endl;
        ByteVector data = readBinaryFile(inPath);
        FileMetadata meta{extractFilename(inPath), currentDateString()};
        ByteVector enc = withSpinner("deriving key", [&]() {
            return encryptPayload(data, passphrase, meta);
        });
        writeBinaryFile(outPath, enc);
        setEncryptedFileTimestamps(outPath);
        std::cout << Color::ok << "  encrypted -> " << outPath << Color::reset << std::endl;
        return 0;
    }
    if (args.size() == 3 && args[0] == "decrypt") {
        // decrypt: therapist decrypt <file> <passphrase>
        const std::string inPath = args[1];
        const std::string passphrase = args[2];

        std::cout << "  decrypting " << extractFilename(inPath) << "..." << std::endl;
        ByteVector data = readBinaryFile(inPath);
        DecryptResult result = withSpinner("deriving key", [&]() {
            return decryptPayload(data, passphrase);
        });
        const std::string outPath = buildDecryptedPath(inPath, result.meta.originalName);
        writeBinaryFile(outPath, result.plaintext);
        if (!result.meta.originalName.empty())
            std::cout << Color::muted << "  original: " << result.meta.originalName
                      << "  (" << result.meta.date << ")" << Color::reset << std::endl;
        std::cout << Color::ok << "  decrypted -> " << outPath << Color::reset << std::endl;
        return 0;
    }

    // ---------------------------------------------------------------------------
    //  interactive mode
    // ---------------------------------------------------------------------------
    const std::string exeDir = executableDirectory(argc, argv);

    auto waitForMenu = [&]() {
        printDivider();
        std::cout << Color::muted << "  press enter to return to the menu" << Color::reset;
        std::string dummy;
        std::getline(std::cin, dummy);
        clearConsole(ansi);
    };

    while (true) {
        try {
            clearConsole(ansi);
            printBanner();
            printDivider();
            std::cout << Color::accent << "  [1] " << Color::reset << "encrypt a file" << std::endl;
            std::cout << Color::accent << "  [2] " << Color::reset << "decrypt a file" << std::endl;
            std::cout << Color::accent << "  [3] " << Color::reset << "write a secret message" << std::endl;
            std::cout << Color::accent << "  [4] " << Color::reset << "read a secret message" << std::endl;
            std::cout << Color::accent << "  [5] " << Color::reset << "run self-test" << std::endl;
            std::cout << Color::accent << "  [0] " << Color::reset << "exit" << std::endl;
            printDivider();
            std::cout << Color::muted << "  choose: " << Color::reset;
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
                std::cout << Color::muted << "  file path: " << Color::reset;
                std::string filePath;
                if (!std::getline(std::cin, filePath)) continue;
                filePath = trimCopy(filePath);
                if (filePath.empty()) { std::cout << "  no file specified" << std::endl; waitForMenu(); continue; }

                // strip surrounding quotes if present
                if (filePath.size() >= 2 &&
                    ((filePath.front() == '"' && filePath.back() == '"') ||
                     (filePath.front() == '\'' && filePath.back() == '\'')))
                    filePath = filePath.substr(1, filePath.size() - 2);

                if (!fileExists(filePath)) {
                    std::cout << Color::error << "  file not found: " << filePath << Color::reset << std::endl;
                    waitForMenu(); continue;
                }

                ByteVector data = readBinaryFile(filePath);
                std::cout << Color::muted << "  file size: " << formatFileSize(data.size()) << Color::reset << std::endl;

                std::cout << Color::muted << "  passphrase: " << Color::reset;
                std::string passphrase;
                if (!std::getline(std::cin, passphrase)) continue;
                if (passphrase.empty()) {
                    std::cout << Color::error << "  passphrase cannot be empty" << Color::reset << std::endl;
                    waitForMenu(); continue;
                }
                if (passphrase.size() < 8) {
                    std::cout << Color::warn << "  warning: short passphrase (< 8 chars) is less secure" << Color::reset << std::endl;
                }

                // optional custom output name
                std::cout << Color::muted << "  output name (enter to skip): " << Color::reset;
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
                setEncryptedFileTimestamps(outPath);

                std::cout << Color::ok << "  encrypted -> " << outPath << Color::reset << std::endl;
                std::cout << Color::muted << "  original name stored: " << meta.originalName
                          << "  (" << meta.date << ")" << Color::reset << std::endl;
                waitForMenu();
                continue;
            }

            // ---- decrypt file ----
            if (c == '2') {
                clearConsole(ansi);
                printBanner();
                printDivider();
                std::cout << Color::muted << "  encrypted file path: " << Color::reset;
                std::string filePath;
                if (!std::getline(std::cin, filePath)) continue;
                filePath = trimCopy(filePath);
                if (filePath.empty()) { std::cout << "  no file specified" << std::endl; waitForMenu(); continue; }

                if (filePath.size() >= 2 &&
                    ((filePath.front() == '"' && filePath.back() == '"') ||
                     (filePath.front() == '\'' && filePath.back() == '\'')))
                    filePath = filePath.substr(1, filePath.size() - 2);

                if (!fileExists(filePath)) {
                    std::cout << Color::error << "  file not found: " << filePath << Color::reset << std::endl;
                    waitForMenu(); continue;
                }

                std::cout << Color::muted << "  passphrase: " << Color::reset;
                std::string passphrase;
                if (!std::getline(std::cin, passphrase)) continue;
                if (passphrase.empty()) {
                    std::cout << Color::error << "  passphrase cannot be empty" << Color::reset << std::endl;
                    waitForMenu(); continue;
                }
                if (passphrase.size() < 8) {
                    std::cout << Color::warn << "  warning: short passphrase (< 8 chars) is less secure" << Color::reset << std::endl;
                }

                ByteVector data = readBinaryFile(filePath);
                std::cout << Color::muted << "  file size: " << formatFileSize(data.size()) << Color::reset << std::endl;

                std::cout << std::endl;
                DecryptResult result = withSpinner("deriving decryption key", [&]() {
                    return decryptPayload(data, passphrase);
                });

                if (!result.meta.originalName.empty()) {
                    std::cout << Color::muted << "  original file: " << result.meta.originalName
                              << "  (" << result.meta.date << ")" << Color::reset << std::endl;
                }

                std::string outPath = buildDecryptedPath(filePath, result.meta.originalName);

                // ask before overwriting
                if (fileExists(outPath)) {
                    std::cout << Color::warn << "  file already exists: " << outPath << Color::reset << std::endl;
                    std::cout << Color::muted << "  overwrite? (y/n): " << Color::reset;
                    std::string yn;
                    std::getline(std::cin, yn);
                    if (trimCopy(yn) != "y" && trimCopy(yn) != "Y") {
                        outPath = filePath + ".decrypted";
                        std::cout << Color::muted << "  saving as: " << outPath << Color::reset << std::endl;
                    }
                }

                writeBinaryFile(outPath, result.plaintext);
                std::cout << Color::ok << "  decrypted -> " << outPath << Color::reset << std::endl;
                waitForMenu();
                continue;
            }

            // ---- write message ----
            if (c == '3') {
                clearConsole(ansi);
                printBanner();
                printDivider();
                std::cout << Color::muted << "  what would you like to tell me?: " << Color::reset;
                std::string message;
                if (!std::getline(std::cin, message)) continue;
                if (message.empty()) {
                    std::cout << Color::error << "  you have to tell me something to hide your secret"
                              << Color::reset << std::endl;
                    waitForMenu(); continue;
                }

                std::cout << Color::muted << "  passphrase: " << Color::reset;
                std::string passphrase;
                if (!std::getline(std::cin, passphrase)) continue;
                if (passphrase.empty()) {
                    std::cout << Color::error << "  passphrase cannot be empty" << Color::reset << std::endl;
                    waitForMenu(); continue;
                }
                if (passphrase.size() < 8) {
                    std::cout << Color::warn << "  warning: short passphrase (< 8 chars) is less secure" << Color::reset << std::endl;
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
                setEncryptedFileTimestamps(outPath);
                std::cout << Color::ok << "  your secret has been saved to: " << outPath
                          << Color::reset << std::endl;
                waitForMenu();
                continue;
            }

            // ---- read message ----
            if (c == '4') {
                clearConsole(ansi);
                printBanner();
                printDivider();

                const auto available = listMessageFiles(exeDir);
                std::string msgFile;

                if (!available.empty()) {
                    std::cout << Color::accent << "  available sessions:" << Color::reset << std::endl;
                    for (std::size_t i = 0; i < available.size(); ++i)
                        std::cout << Color::accent << "    [" << (i + 1) << "] "
                                  << Color::reset << available[i] << std::endl;
                    printDivider();
                    std::cout << Color::muted << "  choose (1-" << available.size()
                              << ") or type a filename: " << Color::reset;
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
                    std::cout << Color::muted << "  filename: " << Color::reset;
                    if (!std::getline(std::cin, msgFile)) continue;
                    msgFile = trimCopy(msgFile);
                }

                if (msgFile.empty()) {
                    std::cout << Color::error << "  no file specified" << Color::reset << std::endl;
                    waitForMenu(); continue;
                }

                std::string resolved = resolveRelativeToExe(exeDir, msgFile);
                if (!fileExists(resolved)) {
                    std::cout << Color::error << "  file not found: " << resolved << Color::reset << std::endl;
                    waitForMenu(); continue;
                }

                std::cout << Color::muted << "  passphrase: " << Color::reset;
                std::string passphrase;
                if (!std::getline(std::cin, passphrase)) continue;
                if (passphrase.empty()) {
                    std::cout << Color::error << "  passphrase cannot be empty" << Color::reset << std::endl;
                    waitForMenu(); continue;
                }
                if (passphrase.size() < 8) {
                    std::cout << Color::warn << "  warning: short passphrase (< 8 chars) is less secure" << Color::reset << std::endl;
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
                    std::cout << Color::ok << "  this is what you told me"
                              << Color::reset << Color::muted
                              << " (" << formatTimestamp(timestamp) << ")"
                              << Color::reset << std::endl;
                    std::cout << std::endl << "  ";
                    typeOutAnimated(messageText,
                                   std::chrono::milliseconds(70),
                                   std::chrono::milliseconds(220));
                    std::cout << std::endl;
                } else {
                    std::cout << Color::warn
                              << "  unable to decode message format -- showing raw bytes"
                              << Color::reset << std::endl;
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
                std::cout << "  running self-tests...\n" << std::endl;
                bool ok = runSelfTest(true);
                printDivider();
                std::cout << (ok
                    ? (std::string(Color::ok) + "  all tests passed" + Color::reset)
                    : (std::string(Color::error) + "  some tests failed" + Color::reset))
                    << std::endl;
                waitForMenu();
                continue;
            }

            std::cout << Color::warn << "  invalid option" << Color::reset << std::endl;
            waitForMenu();
        }
        catch (const std::exception& ex) {
            std::cerr << Color::error << "  error: " << ex.what()
                      << Color::reset << std::endl;
            waitForMenu();
        }
    }

    return 0;
}
