#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <fstream>
#include <functional>
#include <memory>
#include <future>
#include <iostream>
#include <iterator>
#include <numeric>
#include <sstream>
#include <stdexcept>
#include <string>
#include <random>
#include <thread>
#include <vector>
#include <ctime>
#include <iomanip>
#include <clocale>
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
#ifndef NTSTATUS
using NTSTATUS = LONG;
#endif
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef BCRYPT_SUCCESS
#define BCRYPT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
#else
#include <dirent.h>
#include <sys/mman.h>
#endif


#define detectDebugger                  _0xA7E3
#define hardenAgainstDebuggers          _0xB1F9
#define renderStaticBanner              _0xC2D4
#define printBanner                     _0xD3E5
#define printDivider                    _0xE4F6
#define clearConsole                    _0xF507
#define writeBinaryFile                 _0x0618
#define readBinaryFile                  _0x1729
#define buildOutputPath                 _0x283A
#define executableDirectory             _0x394B
#define resolveRelativeToExe            _0x4A5C
#define programName                     _0x5B6D
#define enableAnsiColors                _0x6C7E
#define applyProgramNameToConsoleWindow _0x7D8F
#define generateSalt                    _0x8EA0
#define rotl64                          _0x6C8F
#define load64LE                        _0x7DA0
#define store64LE                       _0x8EB1
#define incrementCounter                _0x5B7E
#define customTransform                 _0x1739
#define dispatchSensitiveTransform      _0x284A
#define executeEncryptLane              _0x395B
#define executeDecryptLane              _0x4A6C
#define maskIntentDecision              _0x5B7D
#define debuggerProbeSignature          _0x6C8E
#define fabricateDebuggerDecoy          _0x7D9F
#define listMessageFiles                _0x8EA1
#define generateMessageFilePath         _0x9FB2
#define buildMessagePayload             _0xA0C3
#define parseMessagePayload             _0xB1D4
#define formatTimestamp                  _0xC2E5
#define typeOutAnimated                 _0xD3F6
#define sleepForDelay                   _0xE407
#define currentTimeSeconds              _0xF518
#define fileExists                      _0x0629
#define joinPath                        _0x173A
#define isAbsolutePath                  _0x284B
#define trimCopy                        _0x395C
#define isDigits                        _0x4A6D
/* v4 legacy names */
#define deriveKeyScheduleV4             _0x9FB1
#define roundFunctionV4                 _0xA0C2
#define encryptBlockFeistelV4           _0xB1D3
#define decryptBlockFeistelV4           _0xC2E4
#define applyTherapistCipherV4          _0xD3F5
#define computeMacV4                    _0xE406
#define encryptPayloadV4                _0xF517
#define decryptPayloadV4                _0x0628
/* v5 hardened names */
#define buildSBoxPair                   _0x9FC2
#define applySBoxToWord                 _0xA2B3
#define deriveHardenedSchedule          _0xA0D3
#define enhancedRoundFunction           _0xB1E4
#define encryptBlockV5                  _0xC2F5
#define decryptBlockV5                  _0xD306
#define applyEnhancedCipher             _0xE417
#define computeHardenedMac              _0xF528
#define encryptPayloadV5                _0x0639
#define decryptPayloadV5                _0x174A
#define addChaffPadding                 _0x285B
#define removeChaffPadding              _0x396C
#define constantTimeMacEq               _0x4A7D
#define stretchInitialState             _0x5B8E
#define encryptPayloadAuto              _0x6D9F
#define decryptPayloadAuto              _0x7EA0

#define OPAQUE_TRUE(x)   (((static_cast<unsigned>(x) * static_cast<unsigned>(x)) | 1U) != 0U)
#define OPAQUE_FALSE(x)  ((static_cast<unsigned>(x) & (~static_cast<unsigned>(x))) != 0U)
#define OPAQUE_ZERO      (static_cast<std::size_t>(0x5A3BU ^ 0x5A3BU))
#define OPAQUE_ONE       (static_cast<std::size_t>((0xC7D2U >> 15U) & 1U))

namespace therapist
{
    using ByteVector = std::vector<std::uint8_t>;
    constexpr char kDefaultProgramName[] = "\xe2\x80\x8e ";
    // Forward declarations used by streaming fallback helpers
    ByteVector readBinaryFile(const std::string &path);
    void writeBinaryFile(const std::string &path, const ByteVector &data);
    ByteVector encryptPayloadAuto(const ByteVector &plain, const std::string &passphrase);
    ByteVector decryptPayloadAuto(const ByteVector &input, const std::string &passphrase);
    std::uint64_t currentTimeSeconds();

    /* ─── anti-tamper sentinel — if these constants are modified the cipher
       silently produces wrong output (no helpful error for an attacker)   ──- */
    constexpr std::uint64_t _kSentinelA =
        0x3141592653589793ULL ^ 0x2718281828459045ULL;
    constexpr std::uint64_t _kSentinelB =
        0x6A09E667F3BCC908ULL ^ 0xBB67AE8584CAA73BULL;

    /* ═══════════════════════════════════════════════════════════════════════
     *  S-BOX 256-byte permutation for nonlinear substitution
     *  generated at startup via Fisher-Yates shuffle with deterministic PRNG.
     * ═══════════════════════════════════════════════════════════════════ */

    struct SBoxPair
    {
        std::array<std::uint8_t, 256> fwd;
        std::array<std::uint8_t, 256> inv;
        std::array<std::array<std::uint64_t, 256>, 8> fwd64{}; // precomputed 64-bit lane tables
    };

    inline SBoxPair buildSBoxPair()
    {
        SBoxPair p;
        for (int i = 0; i < 256; ++i)
            p.fwd[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(i);
        std::uint32_t rng = 0x7A3B9E1DU;
        for (int i = 255; i > 0; --i)
        {
            rng = rng * 1103515245U + 12345U;
            int j = static_cast<int>(((rng >> 16) & 0x7FFFU) %
                                     static_cast<unsigned>(i + 1));
            std::swap(p.fwd[static_cast<std::size_t>(i)],
                      p.fwd[static_cast<std::size_t>(j)]);
        }

        
        for (int i = 0; i < 256; ++i)
            p.inv[p.fwd[static_cast<std::size_t>(i)]] =
                static_cast<std::uint8_t>(i);

        // precompute 64-bit lane tables for faster substitution of 64-bit words
        for (int lane = 0; lane < 8; ++lane)
        {
            const unsigned shift = static_cast<unsigned>(lane * 8U);
            for (int b = 0; b < 256; ++b)
                p.fwd64[static_cast<std::size_t>(lane)][static_cast<std::size_t>(b)] =
                    static_cast<std::uint64_t>(p.fwd[static_cast<std::size_t>(b)]) << shift;
        }
        return p;
    }

    inline const SBoxPair &sbox()
    {
        static const SBoxPair instance = buildSBoxPair();
        return instance;
    }

    /* ═══════════════════════════════════════════════════════════════════════
     *  COLORS
     * ═══════════════════════════════════════════════════════════════════ */
    namespace Color
    {
        constexpr const char *reset   = "\033[0m";
        constexpr const char *accent  = "\033[38;5;214m";
        constexpr const char *muted   = "\033[38;5;244m";
        constexpr const char *warning = "\033[38;5;208m";
        constexpr const char *error   = "\033[38;5;196m";
        constexpr const char *success = "\033[38;5;82m";
    }

    /* ═══════════════════════════════════════════════════════════════════════
     *  CIPHER PARAMETERS
     * ═══════════════════════════════════════════════════════════════════ */
    /* v4 legacy */
    constexpr std::array<std::uint8_t, 4> kMagicV4        = {'T', 'P', 'C', '3'};
    constexpr std::uint8_t                kVersionV4      = 4;
    constexpr std::size_t                 kSaltSizeV4     = 16;
    constexpr std::size_t                 kMacSizeV4      = 8;
    constexpr std::size_t                 kRoundsV4       = 12;

    /* v5 hardened */
    constexpr std::array<std::uint8_t, 4> kMagicV5        = {'T', 'P', 'C', '5'};
    constexpr std::uint8_t                kVersionV5      = 5;
    constexpr std::size_t                 kSaltSizeV5     = 32;
    constexpr std::size_t                 kMacSizeV5      = 32;   /* 4 x u64 */
    constexpr std::size_t                 kRoundsV5       = 32;
    constexpr std::size_t                 kKdfIterations  = 131072;
    constexpr std::size_t                 kKdfMemoryBytes = 1048576; /* 1 MiB */
    constexpr std::size_t                 kChaffMinBytes  = 16;
    constexpr std::size_t                 kChaffMaxBytes  = 48;
    constexpr std::size_t                 kBlockSize      = 16;
    constexpr std::size_t                 kStreamChunkSize = 65536; /* 64 KiB streaming chunk */

    // Runtime-tunable KDF parameters (can be overridden via env/CLI)
    static std::size_t gKdfIterations = kKdfIterations;
    static std::size_t gKdfMemoryBytes = kKdfMemoryBytes;

    // Parse size strings like "1M", "64K", or decimal bytes. Returns false on parse error.
    inline bool parseSizeWithSuffix(const std::string &s, std::size_t &out)
    {
        if (s.empty()) return false;
        char last = s.back();
        std::string num = s;
        std::uint64_t mult = 1ULL;
        if (last == 'K' || last == 'k') { mult = 1024ULL; num = s.substr(0, s.size() - 1); }
        else if (last == 'M' || last == 'm') { mult = 1024ULL * 1024ULL; num = s.substr(0, s.size() - 1); }
        else if (last == 'G' || last == 'g') { mult = 1024ULL * 1024ULL * 1024ULL; num = s.substr(0, s.size() - 1); }
        try
        {
            std::size_t v = static_cast<std::size_t>(std::stoull(num));
            out = static_cast<std::size_t>(v * mult);
            return true;
            }
            catch (const std::exception &ex)
            {
                std::cerr << "self-test exception: " << ex.what() << std::endl;
                return false;
            }
            catch (...)
            {
                std::cerr << "self-test unknown exception" << std::endl;
                return false;
            }
    }

    /* ═══════════════════════════════════════════════════════════════════════
     *  ANTI-DEBUG
     * ═══════════════════════════════════════════════════════════════════ */
#ifdef _WIN32
    namespace
    {
        using NtQueryInformationProcessPtr =
            NTSTATUS(WINAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        using NtSetInformationThreadPtr =
            NTSTATUS(WINAPI *)(HANDLE, ULONG, PVOID, ULONG);
        using CheckRemoteDebuggerPresentPtr =
            BOOL(WINAPI *)(HANDLE, PBOOL);

        NtQueryInformationProcessPtr resolveNtQueryInformationProcess()
        {
            static NtQueryInformationProcessPtr fn = []() -> NtQueryInformationProcessPtr
            {
                HMODULE mod = GetModuleHandleW(L"ntdll.dll");
                if (!mod) mod = LoadLibraryW(L"ntdll.dll");
                if (!mod) return nullptr;
                return reinterpret_cast<NtQueryInformationProcessPtr>(
                    GetProcAddress(mod, "NtQueryInformationProcess"));
            }();
            return fn;
        }

        NtSetInformationThreadPtr resolveNtSetInformationThread()
        {
            static NtSetInformationThreadPtr fn = []() -> NtSetInformationThreadPtr
            {
                HMODULE mod = GetModuleHandleW(L"ntdll.dll");
                if (!mod) mod = LoadLibraryW(L"ntdll.dll");
                if (!mod) return nullptr;
                return reinterpret_cast<NtSetInformationThreadPtr>(
                    GetProcAddress(mod, "NtSetInformationThread"));
            }();
            return fn;
        }

        CheckRemoteDebuggerPresentPtr resolveCheckRemoteDebuggerPresent()
        {
            static CheckRemoteDebuggerPresentPtr fn = []() -> CheckRemoteDebuggerPresentPtr
            {
                HMODULE mod = GetModuleHandleW(L"kernel32.dll");
                if (!mod) mod = LoadLibraryW(L"kernel32.dll");
                if (!mod) return nullptr;
                return reinterpret_cast<CheckRemoteDebuggerPresentPtr>(
                    GetProcAddress(mod, "CheckRemoteDebuggerPresent"));
            }();
            return fn;
        }

        constexpr ULONG kProcessDebugPort         = 7U;
        constexpr ULONG kProcessDebugObjectHandle  = 30U;
        constexpr ULONG kProcessDebugFlags         = 31U;
        constexpr ULONG kThreadHideFromDebugger    = 0x11U;
    }
#endif

    bool detectDebugger()
    {
#ifdef _WIN32
        if (IsDebuggerPresent()) return true;

        if (auto checkRemote = resolveCheckRemoteDebuggerPresent())
        {
            BOOL rem = FALSE;
            if (checkRemote(GetCurrentProcess(), &rem) && rem) return true;
        }

        if (auto ntQ = resolveNtQueryInformationProcess())
        {
            HANDLE dbgObj = nullptr;
            NTSTATUS st = ntQ(GetCurrentProcess(), kProcessDebugObjectHandle,
                              &dbgObj, static_cast<ULONG>(sizeof(dbgObj)), nullptr);
            if (BCRYPT_SUCCESS(st) && dbgObj) return true;

            ULONG dbgFlags = 0;
            st = ntQ(GetCurrentProcess(), kProcessDebugFlags,
                     &dbgFlags, static_cast<ULONG>(sizeof(dbgFlags)), nullptr);
            if (BCRYPT_SUCCESS(st) && dbgFlags == 0) return true;

            HANDLE dbgPort = nullptr;
            st = ntQ(GetCurrentProcess(), kProcessDebugPort,
                     &dbgPort, static_cast<ULONG>(sizeof(dbgPort)), nullptr);
            if (BCRYPT_SUCCESS(st) && dbgPort) return true;
        }
#endif
        return false;
    }

    void hardenAgainstDebuggers()
    {
#ifdef _WIN32
        const char *ov = std::getenv("THERAPIST_DISABLE_SELF_PROTECTION");
        if (ov && ov[0] != '\0') return;

        if (auto ntSet = resolveNtSetInformationThread())
            ntSet(GetCurrentThread(), kThreadHideFromDebugger, nullptr, 0);

        if (detectDebugger())
        {
            ::Sleep(1200 + (static_cast<int>(::GetTickCount() & 0x1FF)));
            throw std::runtime_error("security protection triggered");
        }
#endif
    }

#ifdef _WIN32
    namespace
    {
        using ShellExecuteWPtr =
            HINSTANCE(WINAPI *)(HWND, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, INT);
        using CommandLineToArgvWPtr = LPWSTR *(WINAPI *)(LPCWSTR, int *);

        HMODULE resolveShell32()
        {
            static HMODULE mod = []() -> HMODULE
            {
                HMODULE m = GetModuleHandleW(L"shell32.dll");
                if (!m) m = LoadLibraryW(L"shell32.dll");
                return m;
            }();
            return mod;
        }

        ShellExecuteWPtr resolveShellExecuteW()
        {
            static ShellExecuteWPtr fn = []() -> ShellExecuteWPtr
            {
                HMODULE mod = resolveShell32();
                if (!mod) return nullptr;
                return reinterpret_cast<ShellExecuteWPtr>(
                    GetProcAddress(mod, "ShellExecuteW"));
            }();
            return fn;
        }

        CommandLineToArgvWPtr resolveCommandLineToArgvW()
        {
            static CommandLineToArgvWPtr fn = []() -> CommandLineToArgvWPtr
            {
                HMODULE mod = resolveShell32();
                if (!mod) return nullptr;
                return reinterpret_cast<CommandLineToArgvWPtr>(
                    GetProcAddress(mod, "CommandLineToArgvW"));
            }();
            return fn;
        }
    }

    std::wstring quoteWindowsArg(const std::wstring &arg)
    {
        const bool needsQuotes =
            arg.empty() || arg.find_first_of(L" \t\n\v\"") != std::wstring::npos;
        if (!needsQuotes) return arg;

        std::wstring out;
        out.reserve(arg.size() + 8);
        out.push_back(L'"');
        std::size_t backslashes = 0;
        for (wchar_t ch : arg)
        {
            if (ch == L'\\')
            {
                ++backslashes;
                continue;
            }
            if (ch == L'"')
            {
                out.append(backslashes * 2 + 1, L'\\');
                out.push_back(L'"');
                backslashes = 0;
                continue;
            }
            out.append(backslashes, L'\\');
            backslashes = 0;
            out.push_back(ch);
        }
        out.append(backslashes * 2, L'\\');
        out.push_back(L'"');
        return out;
    }

    std::wstring buildRelaunchArguments()
    {
        const auto parse = resolveCommandLineToArgvW();
        if (!parse) return L"";

        int argcW = 0;
        LPWSTR *argvW = parse(GetCommandLineW(), &argcW);
        if (!argvW) return L"";

        std::wstring args;
        for (int i = 1; i < argcW; ++i)
        {
            if (i > 1) args.push_back(L' ');
            args += quoteWindowsArg(argvW[i]);
        }

        LocalFree(argvW);
        return args;
    }

    bool isRunningAsAdministrator()
    {
        BOOL isAdmin = FALSE;
        PSID adminGroup = nullptr;
        SID_IDENTIFIER_AUTHORITY auth = SECURITY_NT_AUTHORITY;

        if (!AllocateAndInitializeSid(&auth,
                                      2,
                                      SECURITY_BUILTIN_DOMAIN_RID,
                                      DOMAIN_ALIAS_RID_ADMINS,
                                      0,
                                      0,
                                      0,
                                      0,
                                      0,
                                      0,
                                      &adminGroup))
        {
            return false;
        }

        const BOOL ok = CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
        return ok == TRUE && isAdmin == TRUE;
    }

    bool relaunchAsAdministrator()
    {
        wchar_t exePath[MAX_PATH] = {};
        const DWORD len = GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        if (len == 0 || len >= MAX_PATH) return false;

        const auto shellExecute = resolveShellExecuteW();
        if (!shellExecute) return false;

        const std::wstring args = buildRelaunchArguments();
        HINSTANCE result = shellExecute(nullptr,
                                        L"runas",
                                        exePath,
                                        args.empty() ? nullptr : args.c_str(),
                                        nullptr,
                                        SW_SHOWNORMAL);
        return reinterpret_cast<INT_PTR>(result) > 32;
    }

    enum class AdminLaunchResult
    {
        Continue,
        Relaunched,
        Failed
    };

    AdminLaunchResult ensureAdministratorLaunch()
    {
        if (isRunningAsAdministrator()) return AdminLaunchResult::Continue;

        std::cout << Color::warning
                  << "administrator privileges are required; requesting elevation..."
                  << Color::reset << std::endl;

        if (relaunchAsAdministrator()) return AdminLaunchResult::Relaunched;
        return AdminLaunchResult::Failed;
    }
#endif

    /* ═══════════════════════════════════════════════════════════════════════
     *  CONSOLE SETUP
     * ═══════════════════════════════════════════════════════════════════ */
    bool enableAnsiColors()
    {
#ifdef _WIN32
        HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
        if (h == INVALID_HANDLE_VALUE) return false;
        DWORD m = 0;
        if (!GetConsoleMode(h, &m)) return false;
        if (!(m & ENABLE_VIRTUAL_TERMINAL_PROCESSING))
            if (!SetConsoleMode(h, m | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
                return false;
        HANDLE eh = GetStdHandle(STD_ERROR_HANDLE);
        if (eh != INVALID_HANDLE_VALUE)
        {
            DWORD em = 0;
            if (GetConsoleMode(eh, &em))
                SetConsoleMode(eh, em | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
        bool ok = true;
        if (!SetConsoleOutputCP(CP_UTF8)) ok = false;
        if (!SetConsoleCP(CP_UTF8))       ok = false;
        std::setlocale(LC_ALL, ".UTF-8");
        return ok;
#else
        std::setlocale(LC_ALL, "en_US.UTF-8");
        return true;
#endif
    }

    const std::string &programName()
    {
        static const std::string cached = []()
        {
            const char *env = std::getenv("THERAPIST_PROGRAM_NAME");
            if (env)
            {
                std::string c(env);
                c.erase(std::remove_if(c.begin(), c.end(),
                                       [](unsigned char ch)
                                       { return std::iscntrl(ch) != 0; }),
                        c.end());
                if (!c.empty()) return c;
            }
            return std::string(kDefaultProgramName);
        }();
        return cached;
    }

    void applyProgramNameToConsoleWindow()
    {
#ifdef _WIN32
        const auto &n = programName();
        if (n.empty()) return;
        int req = MultiByteToWideChar(CP_UTF8, 0, n.c_str(), -1, nullptr, 0);
        if (req <= 0) return;
        std::wstring w(static_cast<std::size_t>(req), L'\0');
        if (MultiByteToWideChar(CP_UTF8, 0, n.c_str(), -1, &w[0], req) <= 0)
            return;
        if (!w.empty() && w.back() == L'\0') w.pop_back();
        if (!w.empty()) SetConsoleTitleW(w.c_str());
#endif
    }

    /* ═══════════════════════════════════════════════════════════════════════
     *  BANNER
     * ═══════════════════════════════════════════════════════════════════ */
    const std::array<std::string, 23> kBannerBase = {
        u8"                ⣤⣶⣶⣶⣶⣶⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
        u8"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
        u8"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⢿⣿⣿⡿⣿⣿⣿⣿⣿⣿⣿⣿⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
        u8"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿⣿⡇⣿⣷⣿⣿⣿⣿⣿⣿⣯⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀             therapist         ",
        u8"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡰⣿⣿⣿⣇⣿⣀⠸⡟⢹⣿⣿⣿⣿⣿⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
        u8"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⢡⣿⣿⣿⡇⠝⠋⠀⠀⠀⢿⢿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
        u8"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⢸⠸⣿⣿⣇⠀⠀⠀⠀⠀⠀⠊⣽⣿⣿⣿⠁⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
        u8"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⣷⣄⠀⠀⠀⢠⣴⣿⣿⣿⠋⣠⡏⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀      ",
        u8"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠾⣿⣟⡻⠉⠀⠀⠀⠈⢿⠋⣿⡿⠚⠋⠁⡁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀          therapist         ",
        u8"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣶⣾⣿⣿⡄⠀⣳⡶⡦⡀⣿⣿⣷⣶⣤⡾⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
        u8"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⡆⠀⡇⡿⠉⣺⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
        u8"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣯⠽⢲⠇⠣⠐⠚⢻⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
        u8"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⡐⣾⡏⣷⠀⠀⣼⣷⡧⣿⣿⣦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
        u8"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣻⣿⣿⣿⣿⣿⣮⠳⣿⣇⢈⣿⠟⣬⣿⣿⣿⣿⣿⡦⢄⠀⠀⠀⠀⠀⠀⠀                               therapist          ",
        u8"⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⢄⣾⣿⣿⣿⣿⣿⣿⣿⣷⣜⢿⣼⢏⣾⣿⣿⣿⢻⣿⣝⣿⣦⡑⢄⠀⠀⠀⠀⠀",
        u8"⠀⠀⠀⠀⠀⠀⠀⣠⣶⣷⣿⣿⠃⠘⣿⣿⣿⣿⣿⣿⣿⡷⣥⣿⣿⣿⣿⣿⠀⠹⣿⣿⣿⣷⡀⠀⠀⠀⠀⠀",
        u8"⠀⠀⠀⠀⣇⣤⣾⣿⣿⡿⠻⡏⠀⠀⠸⣿⣿⣿⣿⣿⣿⣮⣾⣿⣿⣿⣿⡇⠀⠀⠙⣿⣿⡿⡇⠀⠀⠀⠀⠀               therapist          ",
        u8"⠀⠀⢀⡴⣫⣿⣿⣿⠋⠀⠀⡇⠀⠀⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⢘⣿⣿⣟⢦⡸⠀⠀⠀",
        u8"⠀⡰⠋⣴⣿⣟⣿⠃⠀⠀⠀⠈⠀⠀⣸⣿⣿⣿⣿⣿⣿⣇⣽⣿⣿⣿⣿⣇⠀⠀⠀⠁⠸⣿⢻⣦⠉⢆⠀⠀ ",
        u8"⢠⠇⡔⣿⠏⠏⠙⠆⠀⠀⠀⠀⢀⣜⣛⡻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⡀⠀⠀⠀⠀⡇⡇⠹⣷⡈⡄⠀",
        u8"⠀⡸⣴⡏⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣻⣿⣿⣿⣿⣿⣿⡄⠀⠀⠀⡇⡇⠀⢻⡿⡇⠀                                  therapist          ",
        u8"⠀⣿⣿⣆⠀⠀⠀⠀⠀⠀⢀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀⣰⠿⠤⠒⡛⢹⣿⠄",
        u8"⠀⣿⣷⡆⠁⠀⠀⠀⠀⢠⣿⣿⠟⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠻⢷⡀⠀⠀⠀⠀⠀⣸⣿          made by ytax         "};

    void renderStaticBanner()
    {
        const auto &name = programName();
        static const std::string placeholder(kDefaultProgramName);
        for (const auto &line : kBannerBase)
        {
            if (name == placeholder)
            {
                std::cout << line << '\n';
                continue;
            }
            if (line.find(placeholder) == std::string::npos)
            {
                std::cout << line << '\n';
                continue;
            }
            std::string updated = line;
            std::size_t pos = 0;
            while ((pos = updated.find(placeholder, pos)) != std::string::npos)
            {
                updated.replace(pos, placeholder.size(), name);
                pos += name.size();
            }
            std::cout << updated << '\n';
        }
        std::cout << std::flush;
    }

    void printBanner(bool) { renderStaticBanner(); }

    void printDivider()
    {
        std::cout << Color::muted << "" << Color::reset << std::endl;
    }

    void clearConsole(bool ansiEnabled)
    {
#ifdef _WIN32
        if (ansiEnabled)
            std::cout << "\033[2J\033[3J\033[H" << std::flush;
        else
            std::system("cls");
#else
        (void)ansiEnabled;
        std::cout << "\033[2J\033[3J\033[H" << std::flush;
#endif
    }

    /* ═══════════════════════════════════════════════════════════════════════
     *  PRIMITIVE HELPERS
     * ═══════════════════════════════════════════════════════════════════ */

    std::uint64_t rotl64(std::uint64_t v, unsigned s)
    {
        s &= 63U;
        return s ? (v << s) | (v >> (64U - s)) : v;
    }

    /* Platform helpers: efficient byte-swap and little-endian load/store */
#if defined(_MSC_VER)
#include <intrin.h>
#pragma intrinsic(_byteswap_uint64)
    static inline std::uint64_t bswap64(std::uint64_t x) { return _byteswap_uint64(x); }
#elif defined(__GNUC__) || defined(__clang__)
    static inline std::uint64_t bswap64(std::uint64_t x) { return __builtin_bswap64(x); }
#else
    static inline std::uint64_t bswap64(std::uint64_t x)
    {
        return ((x & 0xFF00000000000000ULL) >> 56) |
               ((x & 0x00FF000000000000ULL) >> 40) |
               ((x & 0x0000FF0000000000ULL) >> 24) |
               ((x & 0x000000FF00000000ULL) >> 8) |
               ((x & 0x00000000FF000000ULL) << 8) |
               ((x & 0x0000000000FF0000ULL) << 24) |
               ((x & 0x000000000000FF00ULL) << 40) |
               ((x & 0x00000000000000FFULL) << 56);
    }
#endif

/* Detect common little-endian platforms; default to little-endian on MSVC/x86 */
#if defined(_MSC_VER) || defined(__i386__) || defined(__x86_64__) || \
    (defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#define PLATFORM_LITTLE_ENDIAN 1
#else
#define PLATFORM_LITTLE_ENDIAN 0
#endif

    inline std::uint64_t load64LE(const std::uint8_t *d)
    {
        std::uint64_t v;
        std::memcpy(&v, d, 8);
#if PLATFORM_LITTLE_ENDIAN
        return v;
#else
        return bswap64(v);
#endif
    }

    inline void store64LE(std::uint8_t *d, std::uint64_t v)
    {
#if PLATFORM_LITTLE_ENDIAN
        std::memcpy(d, &v, 8);
#else
        std::uint64_t t = bswap64(v);
        std::memcpy(d, &t, 8);
#endif
    }

    void incrementCounter(std::array<std::uint8_t, kBlockSize> &ctr)
    {
        // treat counter as two little-endian u64 words to increment with carry
        std::uint64_t low = load64LE(ctr.data());
        std::uint64_t high = load64LE(ctr.data() + 8);
        ++low;
        if (low == 0ULL) ++high;
        store64LE(ctr.data(), low);
        store64LE(ctr.data() + 8, high);
    }

    inline std::uint64_t applySBoxToWord(std::uint64_t w,
                                         const SBoxPair &sbp)
    {
        // use precomputed 64-bit lane tables for faster substitution
        std::uint64_t r = 0;
        for (unsigned i = 0; i < 8U; ++i)
        {
            std::uint8_t b = static_cast<std::uint8_t>((w >> (i * 8U)) & 0xFFU);
            r |= sbp.fwd64[i][static_cast<std::size_t>(b)];
        }
        return r;
    }

    /* ─── CSPRNG uses OS entropy, not std::random_device (broken on MinGW) ── */
    void fillCryptoRandom(std::uint8_t *buf, std::size_t len)
    {
        if (len == 0) return;
#ifdef _WIN32
        /* RtlGenRandom (SystemFunction036) always available on Win XP+ */
        using RtlGenRandomPtr = BOOLEAN(WINAPI *)(PVOID, ULONG);
        static RtlGenRandomPtr fn = []() -> RtlGenRandomPtr {
            HMODULE mod = GetModuleHandleW(L"advapi32.dll");
            if (!mod) mod = LoadLibraryW(L"advapi32.dll");
            if (!mod) return nullptr;
            return reinterpret_cast<RtlGenRandomPtr>(
                GetProcAddress(mod, "SystemFunction036"));
        }();
        if (fn)
        {
            std::size_t off = 0;
            while (off < len)
            {
                ULONG chunk = static_cast<ULONG>(
                    std::min<std::size_t>(len - off, 0xFFFFFFFFUL));
                if (!fn(buf + off, chunk))
                    throw std::runtime_error("RtlGenRandom failed");
                off += chunk;
            }
            return;
        }
#else
        /* /dev/urandom fallback for non-Windows */
        std::ifstream urand("/dev/urandom", std::ios::binary);
        if (urand)
        {
            urand.read(reinterpret_cast<char *>(buf),
                       static_cast<std::streamsize>(len));
            if (static_cast<std::size_t>(urand.gcount()) == len) return;
        }
#endif
        throw std::runtime_error("no cryptographic random source available");
    }

    ByteVector generateSalt(std::size_t size)
    {
        ByteVector salt(size);
        fillCryptoRandom(salt.data(), size);
        return salt;
    }

    /* ═══════════════════════════════════════════════════════════════════════
     *  V4 LEGACY CIPHER (kept for backward-compatible decryption)
     * ═══════════════════════════════════════════════════════════════════ */

    struct TherapistKeyScheduleV4
    {
        std::array<std::uint64_t, 12> roundKeysA{};
        std::array<std::uint64_t, 12> roundKeysB{};
    };

    TherapistKeyScheduleV4 deriveKeyScheduleV4(const std::string &passphrase,
                                               const ByteVector &salt)
    {
        TherapistKeyScheduleV4 schedule{};
        std::uint64_t sA = 0x243F6A8885A308D3ULL;
        std::uint64_t sB = 0x13198A2E03707344ULL;
        auto stir = [&](std::uint8_t byte)
        {
            sA ^= static_cast<std::uint64_t>(byte) * 0x9E3779B185EBCA87ULL;
            sA = rotl64(sA, 11U) + 0xC2B2AE3D27D4EB4FULL;
            sB += sA ^ 0xD6E8FEB86659CDD9ULL;
            sB = rotl64(sB, 7U) ^ (sA >> 3U);
        };
        stir(static_cast<std::uint8_t>(passphrase.size() & 0xFFU));
        stir(static_cast<std::uint8_t>((passphrase.size() >> 8U) & 0xFFU));
        stir(static_cast<std::uint8_t>(salt.size() & 0xFFU));
        stir(static_cast<std::uint8_t>((salt.size() >> 8U) & 0xFFU));
        for (unsigned char ch : passphrase) stir(ch);
        for (std::uint8_t b : salt) stir(b);
        for (std::size_t r = 0; r < kRoundsV4; ++r)
        {
            sA ^= rotl64(sB, 23U) + 0x9E3779B97F4A7C15ULL * (r + 1U);
            sA = rotl64(sA, static_cast<unsigned>((r * 5U + 17U) % 64U));
            schedule.roundKeysA[r] = sA;
            sB ^= sA + 0xC6BC279692B5CC83ULL +
                  static_cast<std::uint64_t>(r) * 0x2545F4914F6CDD1DULL;
            sB = rotl64(sB, static_cast<unsigned>((r * 11U + 29U) % 64U));
            schedule.roundKeysB[r] = sB;
        }
        return schedule;
    }

    std::uint64_t roundFunctionV4(std::uint64_t half,
                                  std::uint64_t keyA,
                                  std::uint64_t keyB)
    {
        half ^= keyA;
        half = rotl64(half, 19U);
        half += keyB;
        half ^= rotl64(half, 41U);
        half *= 0xD6E8FEB86659CDD9ULL;
        half ^= (half >> 33U);
        half = rotl64(half, 13U) ^ rotl64(half, 29U);
        return half;
    }

    void encryptBlockFeistelV4(std::uint64_t &L, std::uint64_t &R,
                               const TherapistKeyScheduleV4 &ks)
    {
        for (std::size_t r = 0; r < kRoundsV4; ++r)
        {
            std::uint64_t f = roundFunctionV4(R, ks.roundKeysA[r], ks.roundKeysB[r]);
            std::uint64_t nL = R;
            std::uint64_t nR = L ^ f;
            L = nL;
            R = nR;
        }
    }

    void applyTherapistCipherV4(const ByteVector &in, ByteVector &out,
                                const TherapistKeyScheduleV4 &ks,
                                const ByteVector &salt)
    {
        out.resize(in.size());
        std::array<std::uint8_t, kBlockSize> ctr{};
        std::uint64_t seedL = 0x6A09E667F3BCC909ULL;
        std::uint64_t seedR = 0xBB67AE8584CAA73BULL;
        for (std::size_t i = 0; i < salt.size(); ++i)
        {
            seedL ^= static_cast<std::uint64_t>(salt[i]) << ((i % 8U) * 8U);
            seedL = rotl64(seedL, 9U);
            seedR ^= static_cast<std::uint64_t>(salt[i]) << (((i + 3U) % 8U) * 8U);
            seedR = rotl64(seedR, 13U);
        }
        store64LE(ctr.data(), seedL);
        store64LE(ctr.data() + 8, seedR);
        std::array<std::uint8_t, kBlockSize> ks_buf{};
        std::size_t off = 0;
        while (off < in.size())
        {
            std::uint64_t l = load64LE(ctr.data());
            std::uint64_t r = load64LE(ctr.data() + 8);
            encryptBlockFeistelV4(l, r, ks);
            store64LE(ks_buf.data(), l);
            store64LE(ks_buf.data() + 8, r);
            std::size_t chunk = std::min<std::size_t>(kBlockSize, in.size() - off);
            // XOR in 64-bit chunks where possible for speed (safe on x86/ARM with memcpy)
            const std::size_t full_words = chunk / 8;
            for (std::size_t j = 0; j < full_words; ++j)
            {
                std::uint64_t win = 0, ksw = 0;
                std::memcpy(&win, in.data() + off + j * 8, 8);
                std::memcpy(&ksw, ks_buf.data() + j * 8, 8);
                win ^= ksw;
                std::memcpy(out.data() + off + j * 8, &win, 8);
            }
            for (std::size_t i = full_words * 8; i < chunk; ++i)
                out[off + i] = static_cast<std::uint8_t>(in[off + i] ^ ks_buf[i]);
            incrementCounter(ctr);
            off += chunk;
        }
    }

    std::uint64_t computeMacV4(const ByteVector &plain,
                               const std::string &passphrase,
                               const ByteVector &salt)
    {
        std::uint64_t hash = 0xCBF29CE484222325ULL;
        auto mix = [&](std::uint8_t byte)
        {
            hash ^= byte;
            hash *= 0x100000001B3ULL;
            hash ^= (hash >> 33);
        };
        mix(static_cast<std::uint8_t>(passphrase.size() & 0xFFU));
        mix(static_cast<std::uint8_t>((passphrase.size() >> 8U) & 0xFFU));
        for (unsigned char ch : passphrase) mix(static_cast<std::uint8_t>(ch));
        for (std::uint8_t b : salt) mix(b);
        mix(static_cast<std::uint8_t>(plain.size() & 0xFFU));
        mix(static_cast<std::uint8_t>((plain.size() >> 8U) & 0xFFU));
        for (std::uint8_t b : plain) mix(b);
        return hash;
    }

    ByteVector decryptPayloadV4(const ByteVector &input,
                                const std::string &passphrase)
    {
        const std::size_t baseHdr = kMagicV4.size() + 3;
        if (input.size() < baseHdr)
            throw std::invalid_argument("encrypted data is too short");
        if (!std::equal(kMagicV4.begin(), kMagicV4.end(), input.begin()))
            throw std::runtime_error("encrypted data header mismatch");
        if (input[kMagicV4.size()] != kVersionV4)
            throw std::runtime_error("unsupported encrypted data version");
        std::uint8_t saltLen = input[kMagicV4.size() + 1];
        std::uint8_t macLen  = input[kMagicV4.size() + 2];
        if (saltLen == 0 || macLen == 0)
            throw std::runtime_error("corrupted encrypted data header");
        std::size_t totalHdr = baseHdr + saltLen + macLen;
        if (input.size() < totalHdr)
            throw std::runtime_error("encrypted data truncated");
        ByteVector salt(input.begin() + baseHdr,
                        input.begin() + baseHdr + saltLen);
        std::uint64_t storedMac = 0;
        if (macLen > sizeof(storedMac))
            throw std::runtime_error("unsupported mac size in encrypted data");
        for (std::size_t i = 0; i < macLen; ++i)
            storedMac = (storedMac << 8U) |
                        static_cast<std::uint64_t>(input[baseHdr + saltLen + i]);
        ByteVector cipher(input.begin() + totalHdr, input.end());
        auto ks = deriveKeyScheduleV4(passphrase, salt);
        ByteVector plain;
        applyTherapistCipherV4(cipher, plain, ks, salt);
        if (computeMacV4(plain, passphrase, salt) != storedMac)
            throw std::runtime_error(
                "authentication failed wrong passphrase or corrupted data");
        return plain;
    }

    /* ═══════════════════════════════════════════════════════════════════════
     *  V5 HARDENED CIPHER
     * ═══════════════════════════════════════════════════════════════════ */

    struct HardenedKeySchedule
    {
        std::array<std::uint64_t, 32> rka{};
        std::array<std::uint64_t, 32> rkb{};
        std::array<std::uint64_t, 32> rkc{};  /* s-box mixing keys */
        std::array<std::uint64_t, 4>  macSeeds{};
    };

    // Portable helpers: aligned allocation, optional memory lock, and prefetch.
#if defined(_WIN32)
    // Prefer MSVC native aligned allocator when available; otherwise fall back
    // to a small portable manual allocator for other Windows toolchains.
    #if defined(_MSC_VER)
    inline void *aligned_alloc_portable(std::size_t alignment, std::size_t size)
    {
        if (alignment < sizeof(void *)) alignment = sizeof(void *);
        return _aligned_malloc(size, alignment);
    }

    inline void aligned_free_portable(void *p)
    {
        if (!p) return;
        _aligned_free(p);
    }
    #else
    inline void *aligned_alloc_portable(std::size_t alignment, std::size_t size)
    {
        if (alignment < sizeof(void *)) alignment = sizeof(void *);
        std::size_t total = size + alignment + sizeof(void *);
        void *raw = std::malloc(total);
        if (!raw) return nullptr;
        std::uintptr_t rawp = reinterpret_cast<std::uintptr_t>(raw) + sizeof(void *);
        std::uintptr_t aligned = (rawp + (alignment - 1)) & ~(alignment - 1);
        void **store = reinterpret_cast<void **>(aligned - sizeof(void *));
        *store = raw;
        return reinterpret_cast<void *>(aligned);
    }

    inline void aligned_free_portable(void *p)
    {
        if (!p) return;
        void **store = reinterpret_cast<void **>(reinterpret_cast<std::uintptr_t>(p) - sizeof(void *));
        void *raw = *store;
        std::free(raw);
    }
    #endif
#else
    inline void *aligned_alloc_portable(std::size_t alignment, std::size_t size)
    {
        if (alignment < sizeof(void *)) alignment = sizeof(void *);
        void *p = nullptr;
        if (posix_memalign(&p, alignment, size) != 0) return nullptr;
        return p;
    }

    inline void aligned_free_portable(void *p)
    {
        free(p);
    }
#endif

    // Secure zeroing helper - uses volatile write to avoid optimizer elision.
    inline void secure_zero(void *p, std::size_t n)
    {
        if (!p || n == 0) return;
        volatile std::uint8_t *vp = reinterpret_cast<volatile std::uint8_t *>(p);
        for (std::size_t i = 0; i < n; ++i) vp[i] = 0;
    }

    inline void secure_wipe(ByteVector &v)
    {
        if (v.empty()) return;
        secure_zero(v.data(), v.size());
        v.clear();
        v.shrink_to_fit();
    }

    inline void secure_wipe(std::string &s)
    {
        if (s.empty()) return;
        secure_zero(&s[0], s.size());
        s.clear();
        s.shrink_to_fit();
    }

    // Forward-declare helpers used by RAII buffer (defined below).
    inline bool lock_memory(void *p, std::size_t size);
    inline void unlock_memory(void *p, std::size_t size);
    inline void prefetch_range(const void *p, std::size_t size, std::size_t step);

    // RAII wrapper for aligned scratch buffers that optionally locks memory
    // and ensures zeroing and freeing on destruction.
    struct ScopedAlignedBuffer
    {
        void *ptr{nullptr};
        std::size_t size{0};
        bool locked{false};

        ScopedAlignedBuffer(std::size_t alignment, std::size_t bytes, bool tryLock = false)
            : ptr(nullptr), size(bytes), locked(false)
        {
            ptr = aligned_alloc_portable(alignment, size);
            if (!ptr) throw std::bad_alloc();
            if (tryLock) locked = lock_memory(ptr, size);
            prefetch_range(ptr, size, 64);
        }

        ~ScopedAlignedBuffer()
        {
            if (ptr)
            {
                secure_zero(ptr, size);
                if (locked) unlock_memory(ptr, size);
                aligned_free_portable(ptr);
                ptr = nullptr;
            }
        }

        void *data() const { return ptr; }
    };

    inline bool lock_memory(void *p, std::size_t size)
    {
#if defined(_WIN32)
        return VirtualLock(p, static_cast<SIZE_T>(size)) != 0;
#else
        return mlock(p, size) == 0;
#endif
    }

    inline void unlock_memory(void *p, std::size_t size)
    {
#if defined(_WIN32)
        VirtualUnlock(p, static_cast<SIZE_T>(size));
#else
        munlock(p, size);
#endif
    }

#if defined(__GNUC__) || defined(__clang__)
    inline void prefetch_range(const void *p, std::size_t size, std::size_t step = 64)
    {
        const char *c = static_cast<const char *>(p);
        for (std::size_t off = 0; off < size; off += step)
            __builtin_prefetch(c + off, 0, 3);
    }
#else
    inline void prefetch_range(const void *, std::size_t, std::size_t = 64) {}
#endif

    // KDF: aligned scratch allocation, optional memory lock and prefetch
    // are handled above; iterations/memory are configurable via CLI/env.
    /* memory-hard key stretching: 131 072 iterations over 1 MiB scratch */
    HardenedKeySchedule deriveHardenedSchedule(const std::string &pass,
                                               const ByteVector &salt)
    {
        /* phase 1 — initial state from password + salt */
        std::array<std::uint64_t, 8> st = {{
            0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL,
            0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
            0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
            0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL
        }};

        auto stir = [&](std::uint8_t byte, std::size_t idx)
        {
            st[idx & 7] ^= static_cast<std::uint64_t>(byte) *
                           0x9E3779B185EBCA87ULL;
            st[idx & 7] = rotl64(st[idx & 7], 11U) + st[(idx + 1U) & 7U];
            st[(idx + 3U) & 7U] ^= st[idx & 7];
        };

        /* encode lengths first to resist length-extension */
        stir(static_cast<std::uint8_t>(pass.size() & 0xFFU), 0);
        stir(static_cast<std::uint8_t>((pass.size() >> 8U) & 0xFFU), 1);
        stir(static_cast<std::uint8_t>(salt.size() & 0xFFU), 2);
        stir(static_cast<std::uint8_t>((salt.size() >> 8U) & 0xFFU), 3);

        for (std::size_t i = 0; i < pass.size(); ++i)
            stir(static_cast<std::uint8_t>(pass[i]), i + 4U);
        for (std::size_t i = 0; i < salt.size(); ++i)
            stir(salt[i], i + pass.size() + 4U);

        /* three extra mixing passes over the initial state */
        for (int pass_i = 0; pass_i < 3; ++pass_i)
            for (int j = 0; j < 8; ++j)
            {
                st[j] ^= rotl64(st[(j + 1) & 7], 17U) +
                          0xC2B2AE3D27D4EB4FULL;
                st[j] = rotl64(st[j], static_cast<unsigned>((j * 7 + 5) % 64));
            }

          /* phase 2 — expand state into scratch buffer (64-bit words)
              memory size is configurable at runtime via `gKdfMemoryBytes` */
          std::size_t memBytes = gKdfMemoryBytes;
          // ensure multiple of 8 bytes (u64 words)
          memBytes = (memBytes / 8U) * 8U;
          constexpr std::size_t alignBytes = 64;

          const char *lockEnv = std::getenv("THERAPIST_KDF_MLOCK");
          bool tryLock = lockEnv && lockEnv[0] != '\0';

          // allocate cache-line aligned scratch via RAII wrapper
          const std::size_t words = memBytes / 8U;
          if (words <= 8U) throw std::invalid_argument("KDF memory too small");

          ScopedAlignedBuffer scratch(alignBytes, memBytes, tryLock);
          std::uint64_t *mem64 = static_cast<std::uint64_t *>(scratch.data());

        {
            std::size_t p = 0;
            for (std::size_t i = 0; i < words; ++i)
            {
                st[p & 7U] = rotl64(st[p & 7U], 17U) ^ st[(p + 3U) & 7U];
                st[p & 7U] += 0xC2B2AE3D27D4EB4FULL;
                mem64[i] = st[p & 7U];
                ++p;
            }
        }

        /* phase 3 — memory-hard mixing (configurable iterations) operating on 64-bit words */
        for (std::size_t iter = 0; iter < gKdfIterations; ++iter)
        {
            std::size_t idxw = static_cast<std::size_t>(
                st[iter & 7U] % (words - 8U));

            for (int j = 0; j < 8; ++j)
            {
                std::uint64_t mv = mem64[idxw + static_cast<std::size_t>(j)];
                st[j] ^= mv;
                st[j] = rotl64(st[j],
                               static_cast<unsigned>((iter + static_cast<std::size_t>(j)) * 7U + 5U) % 64U);
                st[j] += st[(j + 1) & 7] ^ 0x9E3779B97F4A7C15ULL;
                mem64[idxw + static_cast<std::size_t>(j)] = st[j];
            }
        }

        /* phase 4 — extract round keys */
        HardenedKeySchedule ks{};
        for (std::size_t r = 0; r < kRoundsV5; ++r)
        {
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

        /* MAC seeds from final state */
        for (int i = 0; i < 4; ++i)
        {
            st[i] ^= st[i + 4] + 0x2718281828459045ULL;
            ks.macSeeds[i] = st[i];
        }

        /* wipe transient CPU state before returning */
        for (std::size_t i = 0; i < st.size(); ++i) st[i] = 0;

        return ks;
    }

    /* enhanced round function with dual s-box substitution passes */
    std::uint64_t enhancedRoundFunction(std::uint64_t half,
                                        std::uint64_t keyA,
                                        std::uint64_t keyB,
                                        std::uint64_t keyC)
    {
        const auto &sb = sbox();

        /* first substitution pass */
        half ^= keyA;
        half = applySBoxToWord(half, sb);

        /* diffusion */
        half = rotl64(half, 19U);
        half += keyB;
        half ^= rotl64(half, 41U);
        half *= 0xD6E8FEB86659CDD9ULL;
        half ^= (half >> 33U);

        /* second substitution pass with key-dependent mixing */
        half = applySBoxToWord(half ^ keyC, sb);

        /* final avalanche */
        half = rotl64(half, 13U) ^ rotl64(half, 29U);
        half += keyA ^ keyC;
        half ^= (half >> 37U);

        return half;
    }

    void encryptBlockV5(std::uint64_t &L, std::uint64_t &R,
                        const HardenedKeySchedule &ks)
    {
        /* pre-whitening */
        L ^= ks.rka[0] ^ _kSentinelA;
        R ^= ks.rkb[0] ^ _kSentinelB;

        for (std::size_t r = 0; r < kRoundsV5; ++r)
        {
            std::uint64_t f = enhancedRoundFunction(
                R, ks.rka[r], ks.rkb[r], ks.rkc[r]);
            std::uint64_t nL = R;
            std::uint64_t nR = L ^ f;
            L = nL;
            R = nR;
        }

        /* post-whitening */
        L ^= ks.rka[kRoundsV5 - 1] ^ _kSentinelB;
        R ^= ks.rkb[kRoundsV5 - 1] ^ _kSentinelA;
    }

    void decryptBlockV5(std::uint64_t &L, std::uint64_t &R,
                        const HardenedKeySchedule &ks)
    {
        /* undo post-whitening */
        L ^= ks.rka[kRoundsV5 - 1] ^ _kSentinelB;
        R ^= ks.rkb[kRoundsV5 - 1] ^ _kSentinelA;

        for (std::size_t r = kRoundsV5; r-- > 0;)
        {
            std::uint64_t curL = R;
            std::uint64_t f = enhancedRoundFunction(
                curL, ks.rka[r], ks.rkb[r], ks.rkc[r]);
            std::uint64_t curR = L ^ f;
            R = curL;
            L = curR;
        }

        /* undo pre-whitening */
        L ^= ks.rka[0] ^ _kSentinelA;
        R ^= ks.rkb[0] ^ _kSentinelB;
    }

    /* ctr-mode cipher using v5 block cipher */
    void applyEnhancedCipher(const ByteVector &in, ByteVector &out,
                             const HardenedKeySchedule &ks,
                             const ByteVector &salt)
    {
        out.resize(in.size());
        std::array<std::uint8_t, kBlockSize> ctr{};

        /* initialise counter from salt */
        std::uint64_t sL = 0x6A09E667F3BCC909ULL;
        std::uint64_t sR = 0xBB67AE8584CAA73BULL;
        for (std::size_t i = 0; i < salt.size(); ++i)
        {
            sL ^= static_cast<std::uint64_t>(salt[i]) << ((i % 8U) * 8U);
            sL = rotl64(sL, 9U);
            sR ^= static_cast<std::uint64_t>(salt[i]) << (((i + 3U) % 8U) * 8U);
            sR = rotl64(sR, 13U);
        }
        store64LE(ctr.data(), sL);
        store64LE(ctr.data() + 8, sR);

        std::array<std::uint8_t, kBlockSize> ksBuf{};
        std::size_t off = 0;
        while (off < in.size())
        {
            std::uint64_t l = load64LE(ctr.data());
            std::uint64_t r = load64LE(ctr.data() + 8);
            encryptBlockV5(l, r, ks);
            store64LE(ksBuf.data(), l);
            store64LE(ksBuf.data() + 8, r);

            std::size_t chunk = std::min<std::size_t>(kBlockSize, in.size() - off);
            const std::size_t full_words = chunk / 8;
            for (std::size_t j = 0; j < full_words; ++j)
            {
                std::uint64_t win = 0, ksw = 0;
                std::memcpy(&win, in.data() + off + j * 8, 8);
                std::memcpy(&ksw, ksBuf.data() + j * 8, 8);
                win ^= ksw;
                std::memcpy(out.data() + off + j * 8, &win, 8);
            }
            for (std::size_t i = full_words * 8; i < chunk; ++i)
                out[off + i] = static_cast<std::uint8_t>(in[off + i] ^ ksBuf[i]);

            incrementCounter(ctr);
            off += chunk;
        }
    }

    /* ═══════════════════════════════════════════════════════════════════════
     *  256-BIT CASCADED MAC (4 independent FNV-like chains, cross-mixed)
     * ═══════════════════════════════════════════════════════════════════ */

    struct Mac256
    {
        std::uint64_t h[4];
    };

    bool constantTimeMacEq(const Mac256 &a, const Mac256 &b)
    {
        volatile std::uint64_t diff = 0;
        diff |= a.h[0] ^ b.h[0];
        diff |= a.h[1] ^ b.h[1];
        diff |= a.h[2] ^ b.h[2];
        diff |= a.h[3] ^ b.h[3];
        return diff == 0;
    }

    // Forward-declare the streaming helpers inside the anonymous namespace
    namespace {
        inline void macFeedBuffer(Mac256 &mac, const std::uint8_t *buf, std::size_t len);
        inline Mac256 macInit(const std::string &pass,
                              const ByteVector &salt1,
                              const ByteVector &salt2,
                              std::uint32_t plainSize);
        inline void macFinalize(Mac256 &mac);
    }

    Mac256 computeHardenedMac(const ByteVector &plain,
                              const std::string &pass,
                              const ByteVector &salt1,
                              const ByteVector &salt2)
    {
        // Use the streaming helpers so that the buffer-fed path benefits
        // from widened/word-wise processing implemented in macFeedBuffer.
        Mac256 mac = macInit(pass, salt1, salt2, static_cast<std::uint32_t>(plain.size()));
        if (!plain.empty()) macFeedBuffer(mac, plain.data(), plain.size());
        macFinalize(mac);
        return mac;
    }

    /* Streaming / incremental MAC helpers and streaming CTR cipher helpers */
    namespace
    {
        // Forward declarations for stateful double-pass streaming helpers
        // (placed inside this anonymous namespace so they match the
        // definitions later in the same scope).
        struct DoublePassStreamCtx;
        inline void dpInit(DoublePassStreamCtx &ctx,
                           const HardenedKeySchedule &ks1,
                           const HardenedKeySchedule &ks2,
                           const std::array<std::uint8_t, kBlockSize> &startCtr1,
                           const std::array<std::uint8_t, kBlockSize> &startCtr2);
        inline void dpProcess(DoublePassStreamCtx &ctx,
                              const std::uint8_t *in,
                              std::size_t inLen,
                              std::uint8_t *out);

        constexpr std::uint64_t kMacPrimes[4] = {
            0x100000001B3ULL,
            0x1000000016FULL,
            0x10000000233ULL,
            0x10000000259ULL
        };

        inline void macFeedByte(Mac256 &mac, std::uint8_t byte)
        {
            for (int i = 0; i < 4; ++i)
            {
                mac.h[i] ^= byte;
                mac.h[i] *= kMacPrimes[i];
                mac.h[i] ^= (mac.h[i] >> 33U);
            }
            mac.h[0] ^= rotl64(mac.h[3], 7U);
            mac.h[1] ^= rotl64(mac.h[0], 11U);
            mac.h[2] ^= rotl64(mac.h[1], 17U);
            mac.h[3] ^= rotl64(mac.h[2], 23U);
        }

        inline void macFeedBuffer(Mac256 &mac, const std::uint8_t *buf, std::size_t len)
        {
            // Word-wise processing: copy state to registers, process 8 bytes at a time
            std::uint64_t h0 = mac.h[0];
            std::uint64_t h1 = mac.h[1];
            std::uint64_t h2 = mac.h[2];
            std::uint64_t h3 = mac.h[3];

            std::size_t i = 0;
            // handle leading bytes until 8-byte alignment or small lengths
            for (; i < len && ((reinterpret_cast<std::uintptr_t>(buf + i) & 7U) != 0U); ++i)
            {
                std::uint8_t b = buf[i];
                h0 ^= b; h0 *= kMacPrimes[0]; h0 ^= (h0 >> 33U);
                h1 ^= b; h1 *= kMacPrimes[1]; h1 ^= (h1 >> 33U);
                h2 ^= b; h2 *= kMacPrimes[2]; h2 ^= (h2 >> 33U);
                h3 ^= b; h3 *= kMacPrimes[3]; h3 ^= (h3 >> 33U);
                h0 ^= rotl64(h3, 7U);
                h1 ^= rotl64(h0, 11U);
                h2 ^= rotl64(h1, 17U);
                h3 ^= rotl64(h2, 23U);
            }

            // process full 64-bit words (8 bytes) at a time
            const std::size_t words = (len - i) / 8U;
            for (std::size_t w = 0; w < words; ++w)
            {
                std::uint64_t v = load64LE(buf + i + w * 8);
                // unroll per-byte processing inside the 64-bit word
                for (unsigned b = 0; b < 8; ++b)
                {
                    std::uint8_t byte = static_cast<std::uint8_t>((v >> (b * 8U)) & 0xFFU);
                    h0 ^= byte; h0 *= kMacPrimes[0]; h0 ^= (h0 >> 33U);
                    h1 ^= byte; h1 *= kMacPrimes[1]; h1 ^= (h1 >> 33U);
                    h2 ^= byte; h2 *= kMacPrimes[2]; h2 ^= (h2 >> 33U);
                    h3 ^= byte; h3 *= kMacPrimes[3]; h3 ^= (h3 >> 33U);
                    h0 ^= rotl64(h3, 7U);
                    h1 ^= rotl64(h0, 11U);
                    h2 ^= rotl64(h1, 17U);
                    h3 ^= rotl64(h2, 23U);
                }
            }
            i += words * 8U;

            // tail bytes
            for (; i < len; ++i)
            {
                std::uint8_t b = buf[i];
                h0 ^= b; h0 *= kMacPrimes[0]; h0 ^= (h0 >> 33U);
                h1 ^= b; h1 *= kMacPrimes[1]; h1 ^= (h1 >> 33U);
                h2 ^= b; h2 *= kMacPrimes[2]; h2 ^= (h2 >> 33U);
                h3 ^= b; h3 *= kMacPrimes[3]; h3 ^= (h3 >> 33U);
                h0 ^= rotl64(h3, 7U);
                h1 ^= rotl64(h0, 11U);
                h2 ^= rotl64(h1, 17U);
                h3 ^= rotl64(h2, 23U);
            }

            mac.h[0] = h0;
            mac.h[1] = h1;
            mac.h[2] = h2;
            mac.h[3] = h3;

            // SIMD acceleration can be added later; scalar path kept for clarity.
        }

        inline Mac256 macInit(const std::string &pass,
                              const ByteVector &salt1,
                              const ByteVector &salt2,
                              std::uint32_t plainSize)
        {
            Mac256 mac;
            mac.h[0] = 0xCBF29CE484222325ULL;
            mac.h[1] = 0x6C62272E07BB0142ULL;
            mac.h[2] = 0xAF63BD4C8601B7DFULL;
            mac.h[3] = 0x340E1D2B2C67F689ULL;

            // feed passphrase length (2 bytes)
            macFeedByte(mac, static_cast<std::uint8_t>(pass.size() & 0xFFU));
            macFeedByte(mac, static_cast<std::uint8_t>((pass.size() >> 8U) & 0xFFU));
            // feed passphrase
            for (unsigned char ch : pass) macFeedByte(mac, static_cast<std::uint8_t>(ch));
            // feed salts and separators
            for (std::uint8_t b : salt1) macFeedByte(mac, b);
            macFeedByte(mac, 0xFFU);
            for (std::uint8_t b : salt2) macFeedByte(mac, b);
            macFeedByte(mac, 0xFEU);
            // encode data length (4 bytes little-endian)
            macFeedByte(mac, static_cast<std::uint8_t>(plainSize & 0xFFU));
            macFeedByte(mac, static_cast<std::uint8_t>((plainSize >> 8U) & 0xFFU));
            macFeedByte(mac, static_cast<std::uint8_t>((plainSize >> 16U) & 0xFFU));
            macFeedByte(mac, static_cast<std::uint8_t>((plainSize >> 24U) & 0xFFU));

            return mac;
        }

        inline void macFinalize(Mac256 &mac)
        {
            for (int round = 0; round < 8; ++round)
                for (int i = 0; i < 4; ++i)
                {
                    mac.h[i] ^= rotl64(mac.h[(i + 1) & 3], 19U);
                    mac.h[i] *= kMacPrimes[i];
                    mac.h[i] ^= (mac.h[i] >> 29U);
                }
        }

        inline std::array<std::uint8_t, kBlockSize> initCtrFromSalt(const ByteVector &salt)
        {
            std::array<std::uint8_t, kBlockSize> ctr{};
            std::uint64_t sL = 0x6A09E667F3BCC909ULL;
            std::uint64_t sR = 0xBB67AE8584CAA73BULL;
            for (std::size_t i = 0; i < salt.size(); ++i)
            {
                sL ^= static_cast<std::uint64_t>(salt[i]) << ((i % 8U) * 8U);
                sL = rotl64(sL, 9U);
                sR ^= static_cast<std::uint64_t>(salt[i]) << (((i + 3U) % 8U) * 8U);
                sR = rotl64(sR, 13U);
            }
            store64LE(ctr.data(), sL);
            store64LE(ctr.data() + 8, sR);
            return ctr;
        }

        void applyEnhancedCipherChunk(const std::uint8_t *in,
                                       std::size_t inLen,
                                       std::uint8_t *out,
                                       const HardenedKeySchedule &ks,
                                       std::array<std::uint8_t, kBlockSize> &ctr)
        {
            std::array<std::uint8_t, kBlockSize> ksBuf{};
            std::size_t off = 0;
            while (off < inLen)
            {
                std::uint64_t l = load64LE(ctr.data());
                std::uint64_t r = load64LE(ctr.data() + 8);
                encryptBlockV5(l, r, ks);
                store64LE(ksBuf.data(), l);
                store64LE(ksBuf.data() + 8, r);

                (void)0;

                std::size_t chunk = std::min<std::size_t>(kBlockSize, inLen - off);
                const std::size_t full_words = chunk / 8;
                for (std::size_t j = 0; j < full_words; ++j)
                {
                    std::uint64_t win = 0, ksw = 0;
                    std::memcpy(&win, in + off + j * 8, 8);
                    std::memcpy(&ksw, ksBuf.data() + j * 8, 8);
                    win ^= ksw;
                    std::memcpy(out + off + j * 8, &win, 8);
                }
                for (std::size_t i = full_words * 8; i < chunk; ++i)
                    out[off + i] = static_cast<std::uint8_t>(in[off + i] ^ ksBuf[i]);

                // increment counter using the canonical helper to avoid
                // subtle endianness/carry differences across implementations
                incrementCounter(ctr);

                off += chunk;
            }
        }

        

        

        // Stateful streaming context for double-pass CTR keystream so that
        // partial-block calls across multiple process() invocations produce
        // identical results to processing the concatenated data in one call.
        struct DoublePassStreamCtx
        {
            const HardenedKeySchedule *ks1 = nullptr;
            const HardenedKeySchedule *ks2 = nullptr;
            std::array<std::uint8_t, kBlockSize> ctr1{};
            std::array<std::uint8_t, kBlockSize> ctr2{};
            std::array<std::uint8_t, kBlockSize> ks1Buf{};
            std::array<std::uint8_t, kBlockSize> ks2Buf{};
            std::size_t posInBlock = 0; // 0..kBlockSize-1: next byte index within current ks block
        };

        inline void dpInit(DoublePassStreamCtx &ctx,
                           const HardenedKeySchedule &ks1,
                           const HardenedKeySchedule &ks2,
                           const std::array<std::uint8_t, kBlockSize> &startCtr1,
                           const std::array<std::uint8_t, kBlockSize> &startCtr2)
        {
            ctx.ks1 = &ks1;
            ctx.ks2 = &ks2;
            ctx.ctr1 = startCtr1;
            ctx.ctr2 = startCtr2;
            ctx.posInBlock = 0;
        }

        inline void dpProcess(DoublePassStreamCtx &ctx,
                              const std::uint8_t *in,
                              std::size_t inLen,
                              std::uint8_t *out)
        {
            std::size_t off = 0;
            const char *dbg_env = std::getenv("THERAPIST_DEBUG_STREAM");
            const bool dbg = dbg_env && dbg_env[0] != '\0';
            if (dbg)
            {
                std::ostringstream s; s << "[info] dpProcess enter pos=" << ctx.posInBlock << " inLen=" << inLen << std::endl; std::cerr << s.str();
            }

            while (off < inLen)
            {
                if (ctx.posInBlock == 0)
                {
                    if (dbg)
                    {
                        std::ostringstream s;
                        s << "[info] generate keystream block (inLen=" << inLen << ")\n";
                        s << "[info] ctr1 before: ";
                        for (std::size_t ii = 0; ii < kBlockSize; ++ii)
                            s << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(ctx.ctr1[ii]);
                        s << "\n[info] ctr2 before: ";
                        for (std::size_t ii = 0; ii < kBlockSize; ++ii)
                            s << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(ctx.ctr2[ii]);
                        s << std::dec << std::endl;
                        std::cerr << s.str();
                    }

                    // produce keystream block for ks1
                    std::uint64_t l1 = load64LE(ctx.ctr1.data());
                    std::uint64_t r1 = load64LE(ctx.ctr1.data() + 8);
                    encryptBlockV5(l1, r1, *ctx.ks1);
                    store64LE(ctx.ks1Buf.data(), l1);
                    store64LE(ctx.ks1Buf.data() + 8, r1);

                    // produce keystream block for ks2
                    std::uint64_t l2 = load64LE(ctx.ctr2.data());
                    std::uint64_t r2 = load64LE(ctx.ctr2.data() + 8);
                    encryptBlockV5(l2, r2, *ctx.ks2);
                    store64LE(ctx.ks2Buf.data(), l2);
                    store64LE(ctx.ks2Buf.data() + 8, r2);

                    if (dbg)
                    {
                        std::ostringstream s2;
                        s2 << "[info] ks1: ";
                        for (std::size_t ii = 0; ii < kBlockSize; ++ii)
                            s2 << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(ctx.ks1Buf[ii]);
                        s2 << "\n[info] ks2: ";
                        for (std::size_t ii = 0; ii < kBlockSize; ++ii)
                            s2 << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(ctx.ks2Buf[ii]);
                        s2 << "\n[info] ks combined: ";
                        for (std::size_t ii = 0; ii < kBlockSize; ++ii)
                            s2 << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(ctx.ks1Buf[ii] ^ ctx.ks2Buf[ii]);
                        s2 << std::dec << std::endl;
                        std::cerr << s2.str();
                    }

                    // advance counters for next block
                    incrementCounter(ctx.ctr1);
                    incrementCounter(ctx.ctr2);

                    if (dbg)
                    {
                        std::ostringstream s3;
                        s3 << "[info] ctr1 after: ";
                        for (std::size_t ii = 0; ii < kBlockSize; ++ii)
                            s3 << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(ctx.ctr1[ii]);
                        s3 << "\n[info] ctr2 after: ";
                        for (std::size_t ii = 0; ii < kBlockSize; ++ii)
                            s3 << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(ctx.ctr2[ii]);
                        s3 << std::dec << std::endl;
                        std::cerr << s3.str();
                    }
                }

                std::size_t avail = kBlockSize - ctx.posInBlock;
                std::size_t toCopy = std::min<std::size_t>(avail, inLen - off);
                // XOR combined keystream
                for (std::size_t i = 0; i < toCopy; ++i)
                {
                    out[off + i] = static_cast<std::uint8_t>(in[off + i] ^ (ctx.ks1Buf[ctx.posInBlock + i] ^ ctx.ks2Buf[ctx.posInBlock + i]));
                }
                if (dbg)
                {
                    std::ostringstream sx;
                    sx << "[info] dpProcess chunk off=" << off << " toCopy=" << toCopy << " newPos=" << ((ctx.posInBlock + toCopy) % kBlockSize) << " out[:min(32)]= ";
                    for (std::size_t ii = 0; ii < std::min<std::size_t>(toCopy, 32); ++ii)
                        sx << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(out[off + ii]);
                    sx << std::dec << std::endl;
                    std::cerr << sx.str();
                }
                off += toCopy;
                ctx.posInBlock = (ctx.posInBlock + toCopy) % kBlockSize;
            }
            if (dbg)
            {
                std::ostringstream sfin; sfin << "[info] dpProcess exit pos=" << ctx.posInBlock << std::endl; std::cerr << sfin.str();
            }
        }

        // Combined double-pass CTR: generate keystream from ks1 and ks2
        // and XOR together to produce final keystream. This avoids
        // two-pass buffering and reduces chances of subtle ordering bugs.
        void applyDoublePassCipherChunk(const std::uint8_t *in,
                                        std::size_t inLen,
                                        std::uint8_t *out,
                                        const HardenedKeySchedule &ks1,
                                        const HardenedKeySchedule &ks2,
                                        std::array<std::uint8_t, kBlockSize> &ctr1,
                                        std::array<std::uint8_t, kBlockSize> &ctr2)
        {
            // Reuse the canonical stateful streaming path to ensure identical
            // semantics with dpProcess. This prevents subtle counter/posInBlock
            // mismatches when callers split data into small chunks.
            DoublePassStreamCtx tmpCtx;
            dpInit(tmpCtx, ks1, ks2, ctr1, ctr2);
            dpProcess(tmpCtx, in, inLen, out);
            // copy back advanced counters
            ctr1 = tmpCtx.ctr1;
            ctr2 = tmpCtx.ctr2;
        }

        void encryptFileStreamToFile(const std::string &inPath,
                                     const std::string &outPath,
                                     const std::string &passphrase)
        {
            std::ifstream in(inPath, std::ios::binary);
            if (!in)
            {
                std::ostringstream oss;
                oss << "unable to open input file: " << inPath;
                throw std::runtime_error(oss.str());
            }

            std::ofstream out(outPath, std::ios::binary | std::ios::trunc);
            if (!out)
            {
                std::ostringstream oss;
                oss << "unable to open output file: " << outPath;
                throw std::runtime_error(oss.str());
            }

            // prepare header and salts
            ByteVector salt1 = generateSalt(kSaltSizeV5);
            ByteVector salt2 = generateSalt(kSaltSizeV5);

            // write header with placeholder MAC (we will seek-back to write real MAC)
            out.write(reinterpret_cast<const char *>(kMagicV5.data()), static_cast<std::streamsize>(kMagicV5.size()));
            out.put(static_cast<char>(kVersionV5));
            out.put(static_cast<char>(static_cast<unsigned>(kSaltSizeV5)));
            out.put(static_cast<char>(static_cast<unsigned>(kMacSizeV5)));
            out.write(reinterpret_cast<const char *>(salt1.data()), static_cast<std::streamsize>(salt1.size()));
            out.write(reinterpret_cast<const char *>(salt2.data()), static_cast<std::streamsize>(salt2.size()));
            std::streampos macPos = out.tellp();
            std::vector<std::uint8_t> zeroMac(static_cast<std::size_t>(kMacSizeV5), 0);
            out.write(reinterpret_cast<const char *>(zeroMac.data()), static_cast<std::streamsize>(zeroMac.size()));

            // derive key schedules (may be expensive)
            auto ks1 = deriveHardenedSchedule(passphrase, salt1);
            auto ks2 = deriveHardenedSchedule(passphrase, salt2);

            // print a few schedule words for verification
            {
                std::ostringstream ss;
                ss << "[info] ks1.rka[0..2]: ";
                for (int i=0;i<3;++i) ss << std::hex << ks1.rka[i] << " ";
                ss << " ks2.rka[0..2]: ";
                for (int i=0;i<3;++i) ss << std::hex << ks2.rka[i] << " ";
                ss << std::dec << std::endl;
                std::cerr << ss.str();
            }

            // init counters from salts
            auto ctr1 = initCtrFromSalt(salt1);
            auto ctr2 = initCtrFromSalt(salt2);

            // print initial counters
            {
                auto printCtr = [](const std::array<std::uint8_t, kBlockSize> &c, const char *name)
                {
                    std::ostringstream ss;
                    ss << "[info] " << name << " ctr: ";
                    for (std::size_t i = 0; i < c.size(); ++i)
                        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c[i]);
                    ss << std::dec << std::endl;
                    std::cerr << ss.str();
                };
                printCtr(ctr1, "enc ctr1");
                printCtr(ctr2, "enc ctr2");
            }

            // determine plaintext size (needed by MAC init). If not seekable, fall back to in-memory path.
            in.seekg(0, std::ios::end);
            std::streamoff s = in.tellg();
            if (s < 0)
            {
                // non-seekable input — fall back to robust in-memory operation
                in.clear();
                in.seekg(0, std::ios::beg);
                ByteVector data{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
                // wipe header placeholder and close out before writing via helper
                out.close();
                ByteVector outv = encryptPayloadAuto(data, passphrase);
                writeBinaryFile(outPath, outv);
                return;
            }
            const std::size_t plainSize = static_cast<std::size_t>(s);
            in.seekg(0, std::ios::beg);

            // initialize MAC with known plaintext size
            Mac256 mac = macInit(passphrase, salt1, salt2, static_cast<std::uint32_t>(plainSize));

            // generate chaff header+body
            std::uint8_t one = 0;
            fillCryptoRandom(&one, 1);
            std::size_t chaffLen = kChaffMinBytes + (static_cast<std::size_t>(one) % (kChaffMaxBytes - kChaffMinBytes + 1));
            ByteVector chaff;
            if (chaffLen > 0)
            {
                chaff.resize(chaffLen);
                fillCryptoRandom(chaff.data(), chaffLen);
            }
            std::uint8_t chaffHeader[2] = { static_cast<std::uint8_t>(chaffLen & 0xFFU), static_cast<std::uint8_t>((chaffLen >> 8U) & 0xFFU) };

            // buffers
            ByteVector inBuf;
            inBuf.resize(kStreamChunkSize);
            ByteVector midBuf;
            midBuf.resize(kStreamChunkSize);
            ByteVector outBuf;
            outBuf.resize(kStreamChunkSize);

            // small helper: stateful streaming double-pass processor
            DoublePassStreamCtx streamCtx;
            dpInit(streamCtx, ks1, ks2, ctr1, ctr2);
            bool debugEncPrinted = false;
            bool debugPlainPrinted = false;
            auto pipelineEncrypt = [&](const std::uint8_t *data, std::size_t len)
            {
                std::size_t pos = 0;
                while (pos < len)
                {
                    std::size_t chunk = std::min<std::size_t>(kStreamChunkSize, len - pos);
                    if (outBuf.size() < chunk) outBuf.resize(chunk);
                    dpProcess(streamCtx, data + pos, chunk, outBuf.data());
                    if (!debugEncPrinted)
                    {
                        std::ostringstream s;
                        s << "[info] encrypt first chunk out: ";
                        for (std::size_t i = 0; i < std::min<std::size_t>(chunk, 32); ++i)
                            s << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(outBuf[i]);
                        s << std::dec << std::endl;
                        std::cerr << s.str();
                        debugEncPrinted = true;
                    }
                    out.write(reinterpret_cast<const char *>(outBuf.data()), static_cast<std::streamsize>(chunk));
                    if (!out) throw std::runtime_error("failed to write encrypted data");
                    pos += chunk;
                }
            };

            // write chaff header and body first (not part of MAC)
            pipelineEncrypt(chaffHeader, 2);
            if (chaffLen > 0) pipelineEncrypt(chaff.data(), chaffLen);

            // counters after chaff
            {
                auto printCtr = [](const std::array<std::uint8_t, kBlockSize> &c, const char *name)
                {
                    std::ostringstream ss;
                    ss << "[info] " << name << " after chaff: ";
                    for (std::size_t i = 0; i < c.size(); ++i)
                        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c[i]);
                    ss << std::dec << std::endl;
                    std::cerr << ss.str();
                };
                printCtr(ctr1, "enc ctr1");
                printCtr(ctr2, "enc ctr2");
            }

            // stream plaintext: update MAC and encrypt
            while (in)
            {
                in.read(reinterpret_cast<char *>(inBuf.data()), static_cast<std::streamsize>(inBuf.size()));
                std::streamsize got = in.gcount();
                if (got <= 0) break;
                const std::size_t got_sz = static_cast<std::size_t>(got);
                if (!debugPlainPrinted)
                {
                    std::ostringstream s;
                    s << "[info] plaintext first chunk: ";
                    for (std::size_t i = 0; i < std::min<std::size_t>(got_sz, 32); ++i)
                        s << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(inBuf[i]);
                    s << std::dec << std::endl;
                    std::cerr << s.str();
                    debugPlainPrinted = true;
                }
                // feed MAC with plaintext
                macFeedBuffer(mac, inBuf.data(), got_sz);
                // encrypt and write
                if (midBuf.size() < got_sz) midBuf.resize(got_sz);
                if (outBuf.size() < got_sz) outBuf.resize(got_sz);
                dpProcess(streamCtx, inBuf.data(), got_sz, outBuf.data());
                out.write(reinterpret_cast<const char *>(outBuf.data()), static_cast<std::streamsize>(got_sz));
                if (!out) throw std::runtime_error("failed to write encrypted data");
                // counters after writing this plaintext chunk
                if (!debugPlainPrinted)
                {
                    auto printCtr = [](const std::array<std::uint8_t, kBlockSize> &c, const char *name)
                    {
                        std::ostringstream ss;
                        ss << "[info] " << name << " after first plain chunk: ";
                        for (std::size_t i = 0; i < c.size(); ++i)
                            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c[i]);
                        ss << std::dec << std::endl;
                        std::cerr << ss.str();
                    };
                    printCtr(ctr1, "enc ctr1");
                    printCtr(ctr2, "enc ctr2");
                }
            }

            // finalize mac and write into header position
            macFinalize(mac);
            // print computed MAC (hex)
            {
                std::ostringstream oss;
                oss << "[info] encrypt mac: ";
                for (int ii = 0; ii < 4; ++ii)
                {
                    oss << std::hex << std::setfill('0');
                    for (int shift = 56; shift >= 0; shift -= 8)
                        oss << std::setw(2) << static_cast<int>((mac.h[ii] >> shift) & 0xFFU);
                }
                std::cerr << oss.str() << std::dec << std::endl;
            }
            out.flush();
            out.seekp(macPos);
            if (!out) throw std::runtime_error("failed to seek output file to write MAC");
            for (int i = 0; i < 4; ++i)
                for (int shift = 56; shift >= 0; shift -= 8)
                    out.put(static_cast<char>((mac.h[i] >> shift) & 0xFFU));
            out.flush();

            // wipe key schedules from stack
            volatile std::uint8_t *p1 = reinterpret_cast<volatile std::uint8_t *>(&ks1);
            for (std::size_t i = 0; i < sizeof(ks1); ++i) p1[i] = 0;
            volatile std::uint8_t *p2 = reinterpret_cast<volatile std::uint8_t *>(&ks2);
            for (std::size_t i = 0; i < sizeof(ks2); ++i) p2[i] = 0;

            out.close();
            in.close();
        }

        void decryptFileStreamToFile(const std::string &inPath,
                                     const std::string &outPath,
                                     const std::string &passphrase)
        {
            std::ifstream in(inPath, std::ios::binary);
            if (!in)
            {
                std::ostringstream oss;
                oss << "unable to open input file: " << inPath;
                throw std::runtime_error(oss.str());
            }

            // read and parse header (baseHdr + salts + mac)
            const std::size_t baseHdr = kMagicV5.size() + 3;
            std::array<char, 7> hdr{};
            in.read(hdr.data(), static_cast<std::streamsize>(hdr.size()));
            if (static_cast<std::size_t>(in.gcount()) != hdr.size())
                throw std::invalid_argument("encrypted data is too short");
            if (!std::equal(kMagicV5.begin(), kMagicV5.end(), reinterpret_cast<const std::uint8_t *>(hdr.data())))
                throw std::runtime_error("encrypted data header mismatch");
            if (static_cast<unsigned char>(hdr[kMagicV5.size()]) != kVersionV5)
                throw std::runtime_error("unsupported encrypted data version");

            std::uint8_t saltLen = static_cast<std::uint8_t>(hdr[kMagicV5.size() + 1]);
            std::uint8_t macLen  = static_cast<std::uint8_t>(hdr[kMagicV5.size() + 2]);
            if (saltLen == 0 || macLen == 0 || macLen != kMacSizeV5)
                throw std::runtime_error("corrupted encrypted data header");

            // read salts and stored MAC
            ByteVector salt1(static_cast<std::size_t>(saltLen));
            ByteVector salt2(static_cast<std::size_t>(saltLen));
            in.read(reinterpret_cast<char *>(salt1.data()), static_cast<std::streamsize>(salt1.size()));
            in.read(reinterpret_cast<char *>(salt2.data()), static_cast<std::streamsize>(salt2.size()));
            Mac256 storedMac{};
            ByteVector macBytes(static_cast<std::size_t>(macLen));
            in.read(reinterpret_cast<char *>(macBytes.data()), static_cast<std::streamsize>(macBytes.size()));
            if (static_cast<std::size_t>(in.gcount()) != macBytes.size())
                throw std::runtime_error("encrypted data truncated while reading MAC");
            // decode big-endian mac
            for (int i = 0; i < 4; ++i)
            {
                storedMac.h[i] = 0;
                for (int j = 0; j < 8; ++j)
                    storedMac.h[i] = (storedMac.h[i] << 8U) |
                                     static_cast<std::uint64_t>(macBytes[static_cast<std::size_t>(i) * 8U + static_cast<std::size_t>(j)]);
            }

            // derive schedules
            auto ks2 = deriveHardenedSchedule(passphrase, salt2);
            auto ks1 = deriveHardenedSchedule(passphrase, salt1);

            // print a few schedule words for verification
            {
                std::ostringstream ss;
                ss << "[info] ks1.rka[0..2]: ";
                for (int i=0;i<3;++i) ss << std::hex << ks1.rka[i] << " ";
                ss << " ks2.rka[0..2]: ";
                for (int i=0;i<3;++i) ss << std::hex << ks2.rka[i] << " ";
                ss << std::dec << std::endl;
                std::cerr << ss.str();
            }

            auto ctr2 = initCtrFromSalt(salt2);
            auto ctr1 = initCtrFromSalt(salt1);

            // initialize streaming double-pass context
            DoublePassStreamCtx streamCtx;
            dpInit(streamCtx, ks1, ks2, ctr1, ctr2);

            // print initial decrypt counters
            {
                auto printCtr = [](const std::array<std::uint8_t, kBlockSize> &c, const char *name)
                {
                    std::ostringstream ss;
                    ss << "[info] " << name << " ctr: ";
                    for (std::size_t i = 0; i < c.size(); ++i)
                        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c[i]);
                    ss << std::dec << std::endl;
                    std::cerr << ss.str();
                };
                printCtr(ctr2, "dec ctr2");
                printCtr(ctr1, "dec ctr1");
            }

            // temporary output file (rename on success)
            std::string tmpOut = outPath + ".tmp." + std::to_string(currentTimeSeconds());
            std::ofstream out(tmpOut, std::ios::binary | std::ios::trunc);
            if (!out)
            {
                std::ostringstream oss;
                oss << "unable to open temporary output file: " << tmpOut;
                throw std::runtime_error(oss.str());
            }

            // buffers
            ByteVector inBuf;
            inBuf.resize(kStreamChunkSize);
            ByteVector midBuf;
            midBuf.resize(kStreamChunkSize);
            ByteVector augBuf;
            augBuf.reserve(kStreamChunkSize);
            std::vector<std::uint8_t> pending;

            bool parsedChaff = false;
            std::size_t chaffToSkip = 0;
            std::size_t plainSize = 0;
            bool debugPrinted = false;

            // process ciphertext stream; input file current pos is at start of ciphertext
            while (in)
            {
                in.read(reinterpret_cast<char *>(inBuf.data()), static_cast<std::streamsize>(inBuf.size()));
                std::streamsize got = in.gcount();
                if (got <= 0) break;
                const std::size_t got_sz = static_cast<std::size_t>(got);

                // pass through combined double-pass decryption using streaming ctx
                if (midBuf.size() < got_sz) midBuf.resize(got_sz);
                if (augBuf.size() < got_sz) augBuf.resize(got_sz);
                dpProcess(streamCtx, inBuf.data(), got_sz, augBuf.data());

                if (!debugPrinted)
                {
                    std::ostringstream s;
                    s << "[info] first chunk cipher: ";
                    for (std::size_t i = 0; i < std::min<std::size_t>(got_sz, 32); ++i)
                        s << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(inBuf[i]);
                    s << std::dec << std::endl;
                    std::cerr << s.str();
                    std::ostringstream s2;
                    s2 << "[info] first chunk mid:    ";
                    for (std::size_t i = 0; i < std::min<std::size_t>(got_sz, 32); ++i)
                        s2 << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(midBuf[i]);
                    s2 << std::dec << std::endl;
                    std::cerr << s2.str();
                    std::ostringstream s3;
                    s3 << "[info] first chunk aug:    ";
                    for (std::size_t i = 0; i < std::min<std::size_t>(got_sz, 32); ++i)
                        s3 << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(augBuf[i]);
                    s3 << std::dec << std::endl;
                    std::cerr << s3.str();
                    debugPrinted = true;
                }

                    // print counters after first decryption pass
                    if (debugPrinted)
                    {
                        auto printCtr = [](const std::array<std::uint8_t, kBlockSize> &c, const char *name)
                        {
                            std::ostringstream ss;
                            ss << "[info] " << name << " after first chunk: ";
                            for (std::size_t i = 0; i < c.size(); ++i)
                                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c[i]);
                            ss << std::dec << std::endl;
                            std::cerr << ss.str();
                        };
                        printCtr(streamCtx.ctr2, "dec ctr2");
                        printCtr(streamCtx.ctr1, "dec ctr1");
                    }

                // append augmented bytes to pending buffer and process
                pending.insert(pending.end(), augBuf.begin(), augBuf.begin() + got_sz);

                // process as much as possible from pending: first parse header, skip chaff, then write plaintext
                while (true)
                {
                    if (!parsedChaff)
                    {
                        // if we already have remaining chaff to skip from a previous round, consume it first
                        if (chaffToSkip > 0)
                        {
                            std::size_t toDiscard = std::min(pending.size(), chaffToSkip);
                            if (toDiscard > 0) pending.erase(pending.begin(), pending.begin() + toDiscard);
                            chaffToSkip -= toDiscard;
                            if (chaffToSkip > 0) break; // need more data to finish skipping
                            parsedChaff = true; // finished skipping
                        }

                        if (!parsedChaff)
                        {
                            if (pending.size() < 2) break; // need header
                            // read chaff length (2-byte LE)
                            std::size_t chLen = static_cast<std::size_t>(pending[0]) | (static_cast<std::size_t>(pending[1]) << 8U);
                            // remove header bytes
                            pending.erase(pending.begin(), pending.begin() + 2);
                            if (pending.size() >= chLen)
                            {
                                // we have all chaff bytes in pending; drop them and switch to plaintext mode
                                pending.erase(pending.begin(), pending.begin() + chLen);
                                parsedChaff = true;
                                // any remaining pending bytes are plaintext; fall through to write
                            }
                            else
                            {
                                // not enough chaff bytes yet; set remaining and wait for more data
                                chaffToSkip = chLen - pending.size();
                                pending.clear();
                                break;
                            }
                        }
                    }

                    if (parsedChaff)
                    {
                        if (pending.empty()) break;
                        // print the first bytes of plaintext being written
                        {
                            std::ostringstream dbg;
                            dbg << "[info] writing plaintext chunk (" << pending.size() << ") : ";
                            for (std::size_t ii = 0; ii < std::min<std::size_t>(pending.size(), 32); ++ii)
                                dbg << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(pending[ii]);
                            dbg << std::dec << std::endl;
                            std::cerr << dbg.str();
                        }
                        out.write(reinterpret_cast<const char *>(pending.data()), static_cast<std::streamsize>(pending.size()));
                        if (!out) throw std::runtime_error("failed to write decrypted data");
                        plainSize += pending.size();
                        pending.clear();
                        break;
                    }
                }
            }

            out.flush();
            out.close();
            in.close();

            // compute MAC over plaintext (second pass) and verify
            Mac256 mac = macInit(passphrase, salt1, salt2, static_cast<std::uint32_t>(plainSize));
            std::ifstream tmpIn(tmpOut, std::ios::binary);
            if (!tmpIn) { std::remove(tmpOut.c_str()); throw std::runtime_error("failed to open temporary decrypted file for MAC verification"); }
            ByteVector readBuf;
            readBuf.resize(kStreamChunkSize);
            while (tmpIn)
            {
                tmpIn.read(reinterpret_cast<char *>(readBuf.data()), static_cast<std::streamsize>(readBuf.size()));
                std::streamsize got = tmpIn.gcount();
                if (got <= 0) break;
                macFeedBuffer(mac, readBuf.data(), static_cast<std::size_t>(got));
            }
            tmpIn.close();
            macFinalize(mac);
            // print stored and computed MACs
            {
                std::ostringstream s1, s2;
                s1 << "[info] stored mac:  ";
                s2 << "[info] computed mac:";
                for (int ii = 0; ii < 4; ++ii)
                {
                    s1 << std::hex << std::setfill('0');
                    s2 << std::hex << std::setfill('0');
                    for (int shift = 56; shift >= 0; shift -= 8)
                        s1 << std::setw(2) << static_cast<int>((storedMac.h[ii] >> shift) & 0xFFU);
                    for (int shift = 56; shift >= 0; shift -= 8)
                        s2 << std::setw(2) << static_cast<int>((mac.h[ii] >> shift) & 0xFFU);
                }
                std::cerr << s1.str() << std::dec << std::endl;
                std::cerr << s2.str() << std::dec << std::endl;
            }

            if (!constantTimeMacEq(mac, storedMac))
            {
                // preserve the bad output for debugging
                std::string badPath = outPath + ".bad";
                std::rename(tmpOut.c_str(), badPath.c_str());
                std::cerr << "[info] preserved bad output: " << badPath << std::endl;
                throw std::runtime_error("authentication failed wrong passphrase or corrupted data");
            }

            // rename temporary file to final output
            if (std::rename(tmpOut.c_str(), outPath.c_str()) != 0)
            {
                // on failure attempt to copy then remove
                ByteVector data = readBinaryFile(tmpOut);
                writeBinaryFile(outPath, data);
                std::remove(tmpOut.c_str());
            }

            // wipe key schedules
            volatile std::uint8_t *p2 = reinterpret_cast<volatile std::uint8_t *>(&ks2);
            for (std::size_t i = 0; i < sizeof(ks2); ++i) p2[i] = 0;
            volatile std::uint8_t *p1 = reinterpret_cast<volatile std::uint8_t *>(&ks1);
            for (std::size_t i = 0; i < sizeof(ks1); ++i) p1[i] = 0;
        }
    }

    /* ═══════════════════════════════════════════════════════════════════════
     *  CHAFF random padding
     * ═══════════════════════════════════════════════════════════════════ */

    ByteVector addChaffPadding(const ByteVector &plain)
    {
        std::uint8_t rndByte[1];
        fillCryptoRandom(rndByte, 1);
        std::size_t chaffLen =
            kChaffMinBytes + (static_cast<std::size_t>(rndByte[0]) %
                              (kChaffMaxBytes - kChaffMinBytes + 1));

        ByteVector augmented;
        augmented.reserve(2 + chaffLen + plain.size());
        /* store chaff length as 2-byte LE */
        augmented.push_back(static_cast<std::uint8_t>(chaffLen & 0xFFU));
        augmented.push_back(static_cast<std::uint8_t>((chaffLen >> 8U) & 0xFFU));
        /* random chaff bytes */
        augmented.resize(2 + chaffLen);
        fillCryptoRandom(augmented.data() + 2, chaffLen);
        /* original plaintext */
        augmented.insert(augmented.end(), plain.begin(), plain.end());
        return augmented;
    }

    ByteVector removeChaffPadding(const ByteVector &augmented)
    {
        if (augmented.size() < 2)
            throw std::runtime_error(
                "authentication failed wrong passphrase or corrupted data");

        std::size_t chaffLen =
            static_cast<std::size_t>(augmented[0]) |
            (static_cast<std::size_t>(augmented[1]) << 8U);

        if (chaffLen < kChaffMinBytes || chaffLen > kChaffMaxBytes ||
            2 + chaffLen > augmented.size())
            throw std::runtime_error(
                "authentication failed wrong passphrase or corrupted data");

        return ByteVector(augmented.begin() + 2 + static_cast<std::ptrdiff_t>(chaffLen),
                          augmented.end());
    }

    /* ═══════════════════════════════════════════════════════════════════════
     *  V5 ENCRYPT / DECRYPT
     *  double encryption with independent salts & key schedules
     * ═══════════════════════════════════════════════════════════════════ */

    ByteVector encryptPayloadV5(const ByteVector &plain,
                                const std::string &passphrase)
    {
        /* generate two independent salts */
        ByteVector salt1 = generateSalt(kSaltSizeV5);
        ByteVector salt2 = generateSalt(kSaltSizeV5);

        /* add random chaff padding */
        ByteVector augmented = addChaffPadding(plain);

        /* first encryption pass */
        auto ks1 = deriveHardenedSchedule(passphrase, salt1);
        // ensure ks1 zeroed on scope exit
        auto ks1_wipe = std::unique_ptr<HardenedKeySchedule, std::function<void(HardenedKeySchedule*)>>( 
            &ks1, [](HardenedKeySchedule *p){ volatile std::uint8_t *vp = reinterpret_cast<volatile std::uint8_t *>(p); for (std::size_t i=0;i<sizeof(HardenedKeySchedule);++i) vp[i]=0; });
        ByteVector pass1;
        applyEnhancedCipher(augmented, pass1, ks1, salt1);

        /* second encryption pass with independent key */
        auto ks2 = deriveHardenedSchedule(passphrase, salt2);
        auto ks2_wipe = std::unique_ptr<HardenedKeySchedule, std::function<void(HardenedKeySchedule*)>>( 
            &ks2, [](HardenedKeySchedule *p){ volatile std::uint8_t *vp = reinterpret_cast<volatile std::uint8_t *>(p); for (std::size_t i=0;i<sizeof(HardenedKeySchedule);++i) vp[i]=0; });
        ByteVector pass2;
        applyEnhancedCipher(pass1, pass2, ks2, salt2);

        /* compute 256-bit MAC over original plaintext */
        Mac256 mac = computeHardenedMac(plain, passphrase, salt1, salt2);

        /* build output:
           [4: magic] [1: version] [1: salt_len] [1: mac_len]
           [32: salt1] [32: salt2] [32: mac] [N: double-encrypted data] */
        ByteVector output;
        output.reserve(4 + 3 + kSaltSizeV5 * 2 + kMacSizeV5 + pass2.size());

        output.insert(output.end(), kMagicV5.begin(), kMagicV5.end());
        output.push_back(kVersionV5);
        output.push_back(static_cast<std::uint8_t>(kSaltSizeV5));
        output.push_back(static_cast<std::uint8_t>(kMacSizeV5));
        output.insert(output.end(), salt1.begin(), salt1.end());
        output.insert(output.end(), salt2.begin(), salt2.end());

        /* store MAC as 4 x 8-byte big-endian */
        for (int i = 0; i < 4; ++i)
            for (int shift = 56; shift >= 0; shift -= 8)
                output.push_back(
                    static_cast<std::uint8_t>((mac.h[i] >> shift) & 0xFFU));

        output.insert(output.end(), pass2.begin(), pass2.end());

        // wipe intermediate buffers that may hold plaintext or transient data
        secure_wipe(augmented);
        secure_wipe(pass1);
        secure_wipe(pass2);
        return output;
    }

    ByteVector decryptPayloadV5(const ByteVector &input,
                                const std::string &passphrase)
    {
        /* header: magic(4) + version(1) + saltLen(1) + macLen(1) = 7 */
        const std::size_t baseHdr = kMagicV5.size() + 3;
        if (input.size() < baseHdr)
            throw std::invalid_argument("encrypted data is too short");
        if (!std::equal(kMagicV5.begin(), kMagicV5.end(), input.begin()))
            throw std::runtime_error("encrypted data header mismatch");
        if (input[kMagicV5.size()] != kVersionV5)
            throw std::runtime_error("unsupported encrypted data version");

        std::uint8_t saltLen = input[kMagicV5.size() + 1];
        std::uint8_t macLen  = input[kMagicV5.size() + 2];

        if (saltLen == 0 || macLen == 0 || macLen != kMacSizeV5)
            throw std::runtime_error("corrupted encrypted data header");

        /* two salts + mac + at least 1 byte of cipher */
        std::size_t totalHdr = baseHdr + static_cast<std::size_t>(saltLen) * 2U +
                               static_cast<std::size_t>(macLen);
        if (input.size() < totalHdr)
            throw std::runtime_error("encrypted data truncated");

        ByteVector salt1(input.begin() + baseHdr,
                         input.begin() + baseHdr + saltLen);
        ByteVector salt2(input.begin() + baseHdr + saltLen,
                         input.begin() + baseHdr + saltLen * 2);

        /* read 256-bit MAC */
        Mac256 storedMac{};
        std::size_t macOff = baseHdr + static_cast<std::size_t>(saltLen) * 2U;
        for (int i = 0; i < 4; ++i)
        {
            storedMac.h[i] = 0;
            for (int j = 0; j < 8; ++j)
                storedMac.h[i] = (storedMac.h[i] << 8U) |
                                 static_cast<std::uint64_t>(
                                     input[macOff + static_cast<std::size_t>(i) * 8U +
                                           static_cast<std::size_t>(j)]);
        }

        ByteVector cipher(input.begin() + totalHdr, input.end());

        /* reverse double encryption: undo pass 2 first, then pass 1 */
        auto ks2 = deriveHardenedSchedule(passphrase, salt2);
        ByteVector pass1;
        applyEnhancedCipher(cipher, pass1, ks2, salt2);

        auto ks1 = deriveHardenedSchedule(passphrase, salt1);
        ByteVector augmented;
        applyEnhancedCipher(pass1, augmented, ks1, salt1);

        /* remove chaff */
        ByteVector plain = removeChaffPadding(augmented);

        /* verify 256-bit MAC with constant-time comparison */
        Mac256 computed = computeHardenedMac(plain, passphrase, salt1, salt2);
        if (!constantTimeMacEq(computed, storedMac))
            throw std::runtime_error(
                "authentication failed wrong passphrase or corrupted data");

        return plain;
    }

    /* ═══════════════════════════════════════════════════════════════════════
     *  AUTO-DISPATCH: detects v4 vs v5 on decrypt, always uses v5 on encrypt
     * ═══════════════════════════════════════════════════════════════════ */

    ByteVector encryptPayloadAuto(const ByteVector &plain,
                                  const std::string &passphrase)
    {
        return encryptPayloadV5(plain, passphrase);
    }

    ByteVector decryptPayloadAuto(const ByteVector &input,
                                  const std::string &passphrase)
    {
        /* detect version by magic bytes */
        if (input.size() >= kMagicV4.size() &&
            std::equal(kMagicV4.begin(), kMagicV4.end(), input.begin()))
        {
            return decryptPayloadV4(input, passphrase);
        }

        if (input.size() >= kMagicV5.size() &&
            std::equal(kMagicV5.begin(), kMagicV5.end(), input.begin()))
        {
            return decryptPayloadV5(input, passphrase);
        }

        throw std::runtime_error("encrypted data header mismatch");
    }

    /* ═══════════════════════════════════════════════════════════════════════
     *  OBFUSCATED DISPATCH (intent masking + debugger probes)
     * ═══════════════════════════════════════════════════════════════════ */

    bool maskIntentDecision(bool requested, const std::string &passphrase)
    {
        std::uint32_t acc = 0xA5366B4DU;
        for (unsigned char ch : passphrase)
        {
            acc = (acc << 3U) | (acc >> 29U);
            acc ^= static_cast<std::uint32_t>(ch) * 0x045D9F3BU;
            acc += 0x9E3779B9U;
        }
        acc ^= static_cast<std::uint32_t>(
            (passphrase.size() + 11U) * 0x9E3779B1U);
        bool hint = (acc & 0x200U) != 0U;
        bool flip = ((acc >> 7U) & 0x1U) != 0U;
        bool candidate = requested ^ flip;
        bool decision = hint ? !candidate : candidate;
        return decision == requested ? decision : requested;
    }

    ByteVector executeEncryptLane(const ByteVector &in,
                                  const std::string &pass)
    {
        return encryptPayloadAuto(in, pass);
    }

    ByteVector executeDecryptLane(const ByteVector &in,
                                  const std::string &pass)
    {
        return decryptPayloadAuto(in, pass);
    }

    ByteVector dispatchSensitiveTransform(const ByteVector &in,
                                          const std::string &pass,
                                          bool decryptMode)
    {
        bool d1 = maskIntentDecision(decryptMode, pass);
        bool d2 = maskIntentDecision(d1, pass);

        if (OPAQUE_TRUE(d1))
        {
            if (d1 && d2)       return executeDecryptLane(in, pass);
            if (d1 != d2)       return executeDecryptLane(in, pass);
            return executeEncryptLane(in, pass);
        }

        /* opaque dead path — never reached */
        ByteVector decoy(in);
        if (OPAQUE_FALSE(d2))
        {
            for (auto &b : decoy) b ^= 0xAAU;
        }
        return decoy;
    }

    bool debuggerProbeSignature(const std::string &pass, bool dm)
    {
        if (!detectDebugger()) return false;
        std::uint32_t e = 0x4D2C6F3AU ^
                          static_cast<std::uint32_t>(pass.size() * 1315423911U);
        e ^= dm ? 0xA5A5A5A5U : 0x5A5A5A5AU;
        for (unsigned char ch : pass)
        {
            e = (e << 5U) | (e >> 27U);
            e ^= static_cast<std::uint32_t>(ch) + 0x9E3779B9U;
            e += 0x7F4A7C15U;
        }
        return (e & 0x3FU) == 0x2BU;
    }

    ByteVector fabricateDebuggerDecoy(const ByteVector &in, bool dm)
    {
        ByteVector decoy(in);
        std::uint8_t scatter = dm ? 0x7DU : 0xC3U;
        for (std::size_t i = 0; i < decoy.size(); ++i)
        {
            scatter = static_cast<std::uint8_t>(scatter * 33U + 17U);
            decoy[i] ^= static_cast<std::uint8_t>(
                scatter ^ static_cast<std::uint8_t>(i * 19U));
        }
        if (decoy.empty())
            decoy.push_back(static_cast<std::uint8_t>(scatter ^ 0xAAU));
        return decoy;
    }

    ByteVector customTransform(const ByteVector &in,
                               const std::string &pass,
                               bool decryptMode)
    {
        if (pass.empty())
            throw std::invalid_argument("passphrase must not be empty");

        if (debuggerProbeSignature(pass, decryptMode))
            return fabricateDebuggerDecoy(in, decryptMode);

        return dispatchSensitiveTransform(in, pass, decryptMode);
    }

    /* ═══════════════════════════════════════════════════════════════════════
     *  FILE I/O
     * ═══════════════════════════════════════════════════════════════════ */

    ByteVector readBinaryFile(const std::string &path)
    {
        std::ifstream input(path, std::ios::binary);
        if (!input)
        {
            std::ostringstream oss;
            oss << "unable to open input file: " << path;
            throw std::runtime_error(oss.str());
        }

        // Prefer sized read using seek/tell to avoid repeated reallocations
        input.seekg(0, std::ios::end);
        std::streamoff s = input.tellg();
        if (s < 0)
        {
            // tellg failed (e.g., non-seekable stream) — fall back to iterator read
            input.clear();
            input.seekg(0, std::ios::beg);
            return ByteVector{std::istreambuf_iterator<char>(input),
                              std::istreambuf_iterator<char>()};
        }

        input.seekg(0, std::ios::beg);
        std::size_t size = static_cast<std::size_t>(s);
        ByteVector data;
        data.resize(size);
        if (size > 0)
        {
            input.read(reinterpret_cast<char *>(data.data()), static_cast<std::streamsize>(size));
            if (static_cast<std::size_t>(input.gcount()) != size)
            {
                std::ostringstream oss;
                oss << "failed to read input file: " << path;
                throw std::runtime_error(oss.str());
            }
        }
        return data;
    }

    void writeBinaryFile(const std::string &path, const ByteVector &data)
    {
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        if (!output)
        {
            std::ostringstream oss;
            oss << "unable to open output file: " << path;
            throw std::runtime_error(oss.str());
        }
        output.write(reinterpret_cast<const char *>(data.data()),
                     static_cast<std::streamsize>(data.size()));
        if (!output)
        {
            std::ostringstream oss;
            oss << "failed to write all encrypted bytes to: " << path;
            throw std::runtime_error(oss.str());
        }
    }

    std::string buildOutputPath(const std::string &inputPath, bool decryptMode)
    {
        if (!decryptMode) return inputPath + ".encrypt";
        if (inputPath.size() > 8 &&
            inputPath.substr(inputPath.size() - 8) == ".encrypt")
            return inputPath.substr(0, inputPath.size() - 8);
        return inputPath + ".decrypted";
    }

    std::string executableDirectory(int argc, char *argv[])
    {
#ifdef _WIN32
        char buf[MAX_PATH];
        DWORD len = GetModuleFileNameA(nullptr, buf, static_cast<DWORD>(sizeof(buf)));
        if (len > 0 && len < sizeof(buf))
        {
            std::string p(buf, len);
            auto pos = p.find_last_of("\\/");
            if (pos != std::string::npos) return p.substr(0, pos);
        }
#endif
        if (argc > 0 && argv[0])
        {
            std::string p(argv[0]);
            auto pos = p.find_last_of("\\/");
            if (pos != std::string::npos) return p.substr(0, pos);
        }
        return ".";
    }

    bool isAbsolutePath(const std::string &p)
    {
        if (p.empty()) return false;
#ifdef _WIN32
        if (p.size() > 2 &&
            std::isalpha(static_cast<unsigned char>(p[0])) &&
            p[1] == ':' && (p[2] == '\\' || p[2] == '/'))
            return true;
        if (p.size() > 1 && p[0] == '\\' && p[1] == '\\')
            return true;
#endif
        return p[0] == '/';
    }

    std::string joinPath(const std::string &dir, const std::string &name)
    {
        if (dir.empty() || dir == "." || dir == "./" || dir == ".\\")
            return name;
        char last = dir.back();
        if (last == '/' || last == '\\') return dir + name;
#ifdef _WIN32
        return dir + "\\" + name;
#else
        return dir + "/" + name;
#endif
    }

    bool fileExists(const std::string &path)
    {
        std::ifstream f(path, std::ios::binary);
        return static_cast<bool>(f);
    }

    std::string trimCopy(const std::string &text)
    {
        auto b = text.begin(), e = text.end();
        while (b != e && std::isspace(static_cast<unsigned char>(*b))) ++b;
        while (e != b && std::isspace(static_cast<unsigned char>(*(e - 1)))) --e;
        return std::string(b, e);
    }

    /* ═══════════════════════════════════════════════════════════════════════
     *  MESSAGE HANDLING
     * ═══════════════════════════════════════════════════════════════════ */

    constexpr char kMessageMagic[] = {'M', 'S', 'G', '1'};

    std::uint64_t currentTimeSeconds()
    {
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count());
    }

    ByteVector buildMessagePayload(const std::string &msg,
                                   std::uint64_t ts)
    {
        ByteVector p;
        p.reserve(sizeof(kMessageMagic) + sizeof(ts) + msg.size());
        p.insert(p.end(), std::begin(kMessageMagic), std::end(kMessageMagic));
        for (int s = 56; s >= 0; s -= 8)
            p.push_back(static_cast<std::uint8_t>((ts >> s) & 0xFFU));
        p.insert(p.end(), msg.begin(), msg.end());
        return p;
    }

    bool parseMessagePayload(const ByteVector &data,
                             std::string &msgOut,
                             std::uint64_t &tsOut)
    {
        const std::size_t hs = sizeof(kMessageMagic) + sizeof(std::uint64_t);
        if (data.size() < hs) return false;
        if (!std::equal(std::begin(kMessageMagic),
                        std::end(kMessageMagic), data.begin()))
            return false;
        std::uint64_t ts = 0;
        for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i)
            ts = (ts << 8U) |
                 static_cast<std::uint64_t>(data[sizeof(kMessageMagic) + i]);
        msgOut.assign(data.begin() + hs, data.end());
        tsOut = ts;
        return true;
    }

    std::string formatTimestamp(std::uint64_t ts)
    {
        std::time_t raw = static_cast<std::time_t>(ts);
        std::tm ti{};
#ifdef _WIN32
#if defined(_MSC_VER)
        if (localtime_s(&ti, &raw) != 0) return "unknown";
#else
        if (std::tm *tmp = std::localtime(&raw)) ti = *tmp;
        else return "unknown";
#endif
#else
        if (localtime_r(&raw, &ti) == nullptr) return "unknown";
#endif
        std::ostringstream oss;
        oss << std::put_time(&ti, "%Y-%m-%d %H:%M:%S");
        return oss.str();
    }

    void sleepForDelay(std::chrono::milliseconds delay)
    {
#ifdef _WIN32
        auto c = delay.count() < 0 ? 0 : delay.count();
        ::Sleep(static_cast<DWORD>(c));
#else
        std::this_thread::sleep_for(delay);
#endif
    }

    void typeOutAnimated(const std::string &text,
                         std::chrono::milliseconds charDelay,
                         std::chrono::milliseconds nlDelay)
    {
        for (unsigned char uch : text)
        {
            char ch = static_cast<char>(uch);
            std::cout << ch;
            std::cout.flush();
            if (ch == '\r') continue;
            auto d = (ch == '\n') ? nlDelay : charDelay;
            if (d.count() > 0) sleepForDelay(d);
        }
    }

    std::vector<std::string> listMessageFiles(const std::string &dir)
    {
        std::vector<std::string> files;
#ifdef _WIN32
        std::string pat = joinPath(dir, "file_*");
        WIN32_FIND_DATAA fd{};
        HANDLE h = FindFirstFileA(pat.c_str(), &fd);
        if (h != INVALID_HANDLE_VALUE)
        {
            do
            {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                    files.emplace_back(fd.cFileName);
            } while (FindNextFileA(h, &fd));
            FindClose(h);
        }
#else
        std::string dp = dir.empty() ? "." : dir;
        if (DIR *d = opendir(dp.c_str()))
        {
            while (dirent *e = readdir(d))
            {
                std::string n(e->d_name);
                if (n == "." || n == "..") continue;
                if (n.rfind("file_", 0) == 0) files.push_back(n);
            }
            closedir(d);
        }
#endif
        std::sort(files.begin(), files.end());
        return files;
    }

    bool isDigits(const std::string &t)
    {
        return !t.empty() && std::all_of(t.begin(), t.end(),
                                         [](unsigned char ch)
                                         { return std::isdigit(ch) != 0; });
    }

    std::string generateMessageFilePath(const std::string &baseDir)
    {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::system_clock::now().time_since_epoch())
                      .count();
        std::string cand;
        std::size_t attempt = 0;
        do
        {
            std::ostringstream oss;
            oss << "file_" << ms;
            if (attempt > 0) oss << '_' << attempt;
            cand = joinPath(baseDir, oss.str());
            ++attempt;
        } while (fileExists(cand));
        return cand;
    }

    std::string resolveRelativeToExe(const std::string &exeDir,
                                     const std::string &userProvided)
    {
        if (isAbsolutePath(userProvided)) return userProvided;
        return joinPath(exeDir, userProvided);
    }

    // Basic built-in self-tests that validate in-memory and streaming paths.
    bool runSelfTestsInternal(const std::string &exeDir)
    {
        try
        {
            std::string pass = "therapist-selftest";

            std::cout << "self-test: empty payload round-trip" << std::endl;
            // test 1: empty payload round-trip
            ByteVector empty;
            ByteVector e1 = encryptPayloadAuto(empty, pass);
            ByteVector d1 = decryptPayloadAuto(e1, pass);
            if (d1 != empty) throw std::runtime_error("empty payload round-trip failed");

            std::cout << "self-test: small payload round-trip" << std::endl;
            // test 2: small payload round-trip
            ByteVector small = {'h', 'e', 'l', 'l', 'o'};
            ByteVector e2 = encryptPayloadAuto(small, pass);
            ByteVector d2 = decryptPayloadAuto(e2, pass);
            if (d2 != small) throw std::runtime_error("small payload round-trip failed");

            std::cout << "self-test: chunked pipeline round-trip (in-memory)" << std::endl;
            {
                // build small plaintext and augmented payload
                ByteVector pl = {'T','e','s','t','C','h','u','n','k'};
                ByteVector augmented = addChaffPadding(pl);
                ByteVector s1 = generateSalt(kSaltSizeV5);
                ByteVector s2 = generateSalt(kSaltSizeV5);
                auto k1 = deriveHardenedSchedule(pass, s1);
                auto k2 = deriveHardenedSchedule(pass, s2);
                auto c1 = initCtrFromSalt(s1);
                auto c2 = initCtrFromSalt(s2);

                // simulate chunked two-pass encryption
                ByteVector cipherStream;
                cipherStream.reserve(augmented.size());
                const std::size_t chunkSz = 3; // small chunk to exercise boundaries
                std::size_t p = 0;
                while (p < augmented.size())
                {
                    std::size_t chunk = std::min(chunkSz, augmented.size() - p);
                    ByteVector outchunk(chunk);
                    applyDoublePassCipherChunk(augmented.data() + p, chunk, outchunk.data(), k1, k2, c1, c2);
                    cipherStream.insert(cipherStream.end(), outchunk.begin(), outchunk.end());
                    p += chunk;
                }

                // now decrypt with chunked pipeline
                auto d2c = initCtrFromSalt(s2);
                auto d1c = initCtrFromSalt(s1);
                ByteVector recovered;
                recovered.reserve(cipherStream.size());
                p = 0;
                while (p < cipherStream.size())
                {
                    std::size_t chunk = std::min(chunkSz, cipherStream.size() - p);
                    ByteVector outchunk(chunk);
                    applyDoublePassCipherChunk(cipherStream.data() + p, chunk, outchunk.data(), k1, k2, d1c, d2c);
                    recovered.insert(recovered.end(), outchunk.begin(), outchunk.end());
                    p += chunk;
                }

                if (recovered != augmented)
                    throw std::runtime_error("chunked in-memory pipeline round-trip failed");
            }

            std::cout << "self-test: simulated streaming pipeline (in-memory)" << std::endl;
            {
                // simulate exact streaming call sequence used by encryptFileStreamToFile
                ByteVector pl = {'T','e','s','t','1','\n'};
                // generate chaff header + chaff as streaming code does
                std::uint8_t onec = 0; fillCryptoRandom(&onec, 1);
                std::size_t chLen = kChaffMinBytes + (static_cast<std::size_t>(onec) % (kChaffMaxBytes - kChaffMinBytes + 1));
                ByteVector chaff(chLen);
                if (chLen > 0) fillCryptoRandom(chaff.data(), chLen);
                std::uint8_t chHeader[2] = { static_cast<std::uint8_t>(chLen & 0xFFU), static_cast<std::uint8_t>((chLen >> 8U) & 0xFFU) };

                ByteVector s1 = generateSalt(kSaltSizeV5);
                ByteVector s2 = generateSalt(kSaltSizeV5);
                auto k1 = deriveHardenedSchedule(pass, s1);
                auto k2 = deriveHardenedSchedule(pass, s2);
                auto c1 = initCtrFromSalt(s1);
                auto c2 = initCtrFromSalt(s2);

                // encryption streaming simulation: use the same stateful DP stream
                ByteVector streamCipher;
                DoublePassStreamCtx ectx;
                dpInit(ectx, k1, k2, c1, c2);

                // chHeader
                {
                    std::size_t chunk = 2;
                    ByteVector out(chunk);
                    dpProcess(ectx, chHeader, chunk, out.data());
                    streamCipher.insert(streamCipher.end(), out.begin(), out.end());
                }
                // chaff
                if (chLen > 0)
                {
                    std::size_t p2 = 0;
                    while (p2 < chLen)
                    {
                        std::size_t chunk = std::min<std::size_t>(kStreamChunkSize, chLen - p2);
                        ByteVector out(chunk);
                        dpProcess(ectx, chaff.data() + p2, chunk, out.data());
                        streamCipher.insert(streamCipher.end(), out.begin(), out.end());
                        p2 += chunk;
                    }
                }
                // plaintext
                std::size_t p = 0;
                const std::size_t chunkSz = 3;
                while (p < pl.size())
                {
                    std::size_t chunk = std::min(chunkSz, pl.size() - p);
                    ByteVector out(chunk);
                    dpProcess(ectx, pl.data() + p, chunk, out.data());
                    streamCipher.insert(streamCipher.end(), out.begin(), out.end());
                    p += chunk;
                }

                // now simulate decrypt streaming reading same chunk sizes
                auto dk2 = deriveHardenedSchedule(pass, s2);
                auto dk1 = deriveHardenedSchedule(pass, s1);
                auto dc2 = initCtrFromSalt(s2);
                auto dc1 = initCtrFromSalt(s1);

                ByteVector pending2;
                std::size_t idx = 0;
                bool parsed = false;
                std::size_t skip = 0;
                ByteVector recovered2;
                DoublePassStreamCtx dctx;
                dpInit(dctx, dk1, dk2, dc1, dc2);
                while (idx < streamCipher.size())
                {
                    std::size_t chunk = std::min<std::size_t>(chunkSz, streamCipher.size() - idx);
                    ByteVector aug(chunk);
                    dpProcess(dctx, streamCipher.data() + idx, chunk, aug.data());
                    // append augmented bytes
                    pending2.insert(pending2.end(), aug.begin(), aug.end());

                    // parse header and skip chaff
                    while (true)
                    {
                        if (!parsed)
                        {
                            if (skip > 0)
                            {
                                std::size_t toDiscard = std::min(pending2.size(), skip);
                                if (toDiscard > 0) pending2.erase(pending2.begin(), pending2.begin() + toDiscard);
                                skip -= toDiscard;
                                if (skip > 0) break;
                                parsed = true;
                            }
                            if (!parsed)
                            {
                                if (pending2.size() < 2) break;
                                std::size_t clen = static_cast<std::size_t>(pending2[0]) | (static_cast<std::size_t>(pending2[1]) << 8U);
                                pending2.erase(pending2.begin(), pending2.begin() + 2);
                                if (pending2.size() >= clen)
                                {
                                    pending2.erase(pending2.begin(), pending2.begin() + clen);
                                    parsed = true;
                                }
                                else
                                {
                                    skip = clen - pending2.size();
                                    pending2.clear();
                                    break;
                                }
                            }
                        }
                        if (parsed)
                        {
                            if (pending2.empty()) break;
                            recovered2.insert(recovered2.end(), pending2.begin(), pending2.end());
                            pending2.clear();
                            break;
                        }
                    }

                    idx += chunk;
                }

                // compute expected combined keystream for the entire augmented stream
                auto generateKeystream = [&](const HardenedKeySchedule &k1,
                                             const HardenedKeySchedule &k2,
                                             std::array<std::uint8_t, kBlockSize> ctr,
                                             std::size_t totalLen)
                {
                    ByteVector ks(totalLen);
                    std::size_t off = 0;
                    while (off < totalLen)
                    {
                        std::array<std::uint8_t, kBlockSize> b1{}, b2{};
                        std::uint64_t l1 = load64LE(ctr.data());
                        std::uint64_t r1 = load64LE(ctr.data() + 8);
                        encryptBlockV5(l1, r1, k1);
                        store64LE(b1.data(), l1);
                        store64LE(b1.data() + 8, r1);
                        std::uint64_t l2 = load64LE(ctr.data());
                        std::uint64_t r2 = load64LE(ctr.data() + 8);
                        // note: advance ctr for k2 separately
                        incrementCounter(ctr);
                        l2 = load64LE(ctr.data()); // load new ctr for k2 (simplified placeholder)
                        (void)l2; (void)r2;
                        // produce combined by XORing b1 and b2 (approx - used only for debugging)
                        for (std::size_t i = 0; i < kBlockSize && off + i < totalLen; ++i)
                            ks[off + i] = static_cast<std::uint8_t>(b1[i] ^ b2[i]);
                        off += kBlockSize;
                    }
                    return ks;
                };

                if (recovered2 != pl) {
                    std::ostringstream ss; ss << "simulated streaming mismatch: got:";
                    for (auto b: recovered2) ss << std::hex << (int)b << ",";
                    ss << " expected:";
                    for (auto b: pl) ss << std::hex << (int)b << ",";
                    ss << std::dec << std::endl;
                    std::cerr << ss.str();
                    throw std::runtime_error("simulated streaming pipeline failed");
                }
            }

            std::cout << "self-test: streaming file round-trip" << std::endl;
            // test 3: streaming encrypt/decrypt to temporary files
            char inName[L_tmpnam] = {};
            char encName[L_tmpnam] = {};
            char decName[L_tmpnam] = {};
            if (!std::tmpnam(inName) || !std::tmpnam(encName) || !std::tmpnam(decName))
                throw std::runtime_error("tmpnam failed");

            const std::string inp(inName);
            const std::string enc(encName);
            const std::string dec(decName);

            ByteVector payload = {'T', 'e', 's', 't', '1', '\n'};
            writeBinaryFile(inp, payload);
            encryptFileStreamToFile(inp, enc, pass);
            decryptFileStreamToFile(enc, dec, pass);

            ByteVector r1 = readBinaryFile(inp);
            ByteVector r2 = readBinaryFile(dec);

            // cleanup
            std::remove(inp.c_str());
            std::remove(enc.c_str());
            std::remove(dec.c_str());

            if (r1 != r2) throw std::runtime_error("streaming round-trip failed");

            return true;
        }
        catch (const std::exception &ex)
        {
            std::cerr << "self-test exception: " << ex.what() << std::endl;
            return false;
        }
        catch (...)
        {
            std::cerr << "self-test unknown exception" << std::endl;
            return false;
        }
    }

} // namespace therapist

/* ═══════════════════════════════════════════════════════════════════════════════
 *  MAIN
 * ═══════════════════════════════════════════════════════════════════════════ */

using namespace therapist;

int main(int argc, char *argv[])
{
    bool interactiveMode = false;
    const bool ansiEnabled = enableAnsiColors();
    (void)ansiEnabled;
    applyProgramNameToConsoleWindow();

#ifdef _WIN32
    // Honor THERAPIST_DISABLE_SELF_PROTECTION to allow running without
    // attempting an administrator relaunch (useful for CI, testing,
    // and developer machines where elevation is not desired).
    const char *disable_prot = std::getenv("THERAPIST_DISABLE_SELF_PROTECTION");
    if (!(disable_prot && disable_prot[0] != '\0'))
    {
        switch (ensureAdministratorLaunch())
        {
        case AdminLaunchResult::Continue:
            break;
        case AdminLaunchResult::Relaunched:
            return 0;
        case AdminLaunchResult::Failed:
            std::cerr << Color::error
                      << "failed to obtain administrator privileges"
                      << Color::reset << std::endl;
            return 1;
        }
    }
#endif

    auto waitForMenu = [&]()
    {
        printDivider();
        std::cout << Color::muted << "press enter to return to the menu"
                  << Color::reset;
        std::string dummy;
        if (!std::getline(std::cin, dummy))
            throw std::runtime_error("failed to read confirmation from console");
        clearConsole(ansiEnabled);
    };

    auto finish = [&](int status)
    {
        if (interactiveMode) waitForMenu();
        return status;
    };

    hardenAgainstDebuggers();
    const std::string exeDir = executableDirectory(argc, argv);

    // --- parse KDF overrides from environment variables ---
    if (const char *e = std::getenv("THERAPIST_KDF_ITERATIONS"))
    {
        try { std::size_t v = static_cast<std::size_t>(std::stoull(e)); if (v > 0) gKdfIterations = v; } catch (...) {}
    }
    if (const char *e = std::getenv("THERAPIST_KDF_MEMORY_BYTES"))
    {
        std::size_t v = 0;
        if (parseSizeWithSuffix(std::string(e), v)) gKdfMemoryBytes = v;
        else try { std::size_t vv = static_cast<std::size_t>(std::stoull(e)); if (vv > 0) gKdfMemoryBytes = vv; } catch (...) {}
    }
    if (const char *e2 = std::getenv("THERAPIST_KDF_MEMORY_MB"))
    {
        try { std::size_t mb = static_cast<std::size_t>(std::stoull(e2)); if (mb > 0) gKdfMemoryBytes = mb * 1024ULL * 1024ULL; } catch (...) {}
    }

    // --- parse CLI options (consume --kdf-iterations / --kdf-memory) ---
    std::vector<std::string> residualArgs;
    bool requestSelfTest = false;
    for (int i = 1; i < argc; ++i)
    {
        std::string a(argv[i]);
        if (a.rfind("--kdf-iterations=", 0) == 0)
        {
            std::string val = a.substr(sizeof("--kdf-iterations=") - 1);
            try { std::size_t v = static_cast<std::size_t>(std::stoull(val)); if (v > 0) gKdfIterations = v; } catch (...) {}
            continue;
        }
        if (a == "--kdf-iterations")
        {
            if (i + 1 < argc) { try { std::size_t v = static_cast<std::size_t>(std::stoull(argv[++i])); if (v > 0) gKdfIterations = v; } catch (...) {} }
            continue;
        }
        if (a.rfind("--kdf-memory=", 0) == 0)
        {
            std::string val = a.substr(sizeof("--kdf-memory=") - 1);
            std::size_t v = 0;
            if (parseSizeWithSuffix(val, v)) gKdfMemoryBytes = v;
            else try { std::size_t vv = static_cast<std::size_t>(std::stoull(val)); if (vv > 0) gKdfMemoryBytes = vv; } catch (...) {}
            continue;
        }
        if (a == "--kdf-memory")
        {
            if (i + 1 < argc)
            {
                std::string val(argv[++i]);
                std::size_t v = 0;
                if (parseSizeWithSuffix(val, v)) gKdfMemoryBytes = v;
                else try { std::size_t vv = static_cast<std::size_t>(std::stoull(val)); if (vv > 0) gKdfMemoryBytes = vv; } catch (...) {}
            }
            continue;
        }
        if (a == "--self-test" || a == "--run-self-test")
        {
            requestSelfTest = true;
            continue;
        }
        residualArgs.push_back(a);
    }

    if (requestSelfTest || std::getenv("THERAPIST_SELF_TEST"))
    {
        std::cout << "running self-tests..." << std::endl;
        bool ok = runSelfTestsInternal(exeDir);
        std::cout << (ok ? "self-tests passed" : "self-tests failed") << std::endl;
        return ok ? 0 : 2;
    }

    while (true)
    {
        try
        {
            hardenAgainstDebuggers();
            bool decryptMode    = false;
            bool messageMode    = false;
            bool messageDecrypt = false;
            std::string inputPath;
            std::string passphrase;
            std::string messageBuffer;
            std::string messageFilePath;
            std::string resolvedMessagePath;

            if (!interactiveMode && residualArgs.size() == 2)
            {
                inputPath  = residualArgs[0];
                passphrase = residualArgs[1];
            }
            else if (!interactiveMode && residualArgs.size() == 3 &&
                     residualArgs[0] == "decrypt")
            {
                decryptMode = true;
                inputPath   = residualArgs[1];
                passphrase  = residualArgs[2];
            }
            else
            {
                interactiveMode = true;
                clearConsole(ansiEnabled);
                printBanner(ansiEnabled);
                printDivider();
                std::cout << Color::accent << "  [1] " << Color::reset
                          << "encrypt" << std::endl;
                std::cout << Color::accent << "  [2] " << Color::reset
                          << "decrypt" << std::endl;
                std::cout << Color::accent << "  [0] " << Color::reset
                          << "exit" << std::endl;
                printDivider();
                std::cout << Color::muted << "enter choice : " << Color::reset;
                std::string choice;
                if (!std::getline(std::cin, choice))
                    throw std::runtime_error(
                        "failed to read mode selection from console");

                char modeChar = '\0';
                for (unsigned char ch : choice)
                {
                    if (!std::isspace(ch))
                    {
                        modeChar = static_cast<char>(std::tolower(ch));
                        break;
                    }
                }

                if (modeChar == '0' || modeChar == 'q')
                {
                    waitForMenu();
                    continue;
                }
                else if (modeChar == '1' || modeChar == 'e' || modeChar == 'm')
                {
                    messageMode = true;
                }
                else if (modeChar == '2' || modeChar == 'd' || modeChar == 'x')
                {
                    messageMode = true;
                    messageDecrypt = true;
                }
                else
                {
                    std::cout << Color::warning
                              << "please choose a valid option from the menu"
                              << Color::reset << std::endl;
                    printDivider();
                    continue;
                }

                clearConsole(ansiEnabled);
                printBanner(ansiEnabled);
                printDivider();

                if (messageMode)
                {
                    if (messageDecrypt)
                    {
                        const auto available = listMessageFiles(exeDir);
                        if (!available.empty())
                        {
                            printDivider();
                            std::cout << Color::accent
                                      << "what session would you like to review? "
                                      << exeDir << ':' << Color::reset << '\n';
                            for (std::size_t i = 0; i < available.size(); ++i)
                                std::cout << Color::accent << "  ["
                                          << (i + 1) << "] " << Color::reset
                                          << available[i] << '\n';
                            printDivider();
                            std::cout << Color::muted << "enter choice (1-"
                                      << available.size()
                                      << ") or 0 to use a filename: "
                                      << Color::reset;
                            std::string sel;
                            if (!std::getline(std::cin, sel))
                                throw std::runtime_error(
                                    "failed to read selection from console");
                            sel = trimCopy(sel);
                            if (isDigits(sel))
                            {
                                int idx = std::stoi(sel);
                                if (idx >= 1 &&
                                    static_cast<std::size_t>(idx) <= available.size())
                                    messageFilePath =
                                        available[static_cast<std::size_t>(idx) - 1];
                                else if (idx != 0)
                                    std::cout << Color::warning
                                              << "invalid selection you can type "
                                                 "a filename instead"
                                              << Color::reset << std::endl;
                            }
                            else if (!sel.empty())
                            {
                                messageFilePath = sel;
                            }
                        }

                        if (messageFilePath.empty())
                        {
                            std::cout << Color::muted
                                      << "tell me which one would you like to "
                                         "review? (stored next to the others): "
                                      << Color::reset;
                            if (!std::getline(std::cin, messageFilePath))
                                throw std::runtime_error(
                                    "failed to read encrypted message filename "
                                    "from console");
                            messageFilePath = trimCopy(messageFilePath);
                            if (messageFilePath.empty())
                                throw std::invalid_argument(
                                    "filename must not be empty");
                        }
                    }
                    else
                    {
                        std::cout << Color::muted
                                  << "what'd you like to tell me?: "
                                  << Color::reset;
                        if (!std::getline(std::cin, messageBuffer))
                            throw std::runtime_error(
                                "failed to read message from console");
                        if (messageBuffer.empty())
                            throw std::invalid_argument(
                                "you've to tell me something to hide your secret");
                    }
                }
                else
                {
                    std::cout << Color::muted
                              << "enter the path to the input file: "
                              << Color::reset;
                    if (!std::getline(std::cin, inputPath))
                        throw std::runtime_error(
                            "failed to read input file path from console");
                    inputPath = trimCopy(inputPath);
                    if (inputPath.empty())
                        throw std::invalid_argument(
                            "input file path must not be empty");
                }

                const bool reqDecPass = (messageMode && messageDecrypt) ||
                                        (!messageMode && decryptMode);
                const char *pp = reqDecPass
                                     ? "tell me a our passphrase: "
                                     : "tell me a passphrase to hide your secret: ";
                std::cout << Color::muted << pp << Color::reset;
                if (!std::getline(std::cin, passphrase))
                    throw std::runtime_error(
                        "failed to read passphrase from console");
            }

            if (passphrase.empty())
                throw std::invalid_argument(
                    "the passphrase must contain at least one character");

            ByteVector inputData;
            if (messageMode)
            {
                if (messageDecrypt)
                {
                    resolvedMessagePath =
                        resolveRelativeToExe(exeDir, messageFilePath);
                    inputData = readBinaryFile(resolvedMessagePath);
                    if (inputData.empty())
                        std::cout << Color::warning
                                  << "warning: encrypted message file was empty "
                                     "the decrypted output will be empty as well"
                                  << Color::reset << std::endl;
                }
                else
                {
                    std::uint64_t ts = currentTimeSeconds();
                    inputData = buildMessagePayload(messageBuffer, ts);
                    resolvedMessagePath = generateMessageFilePath(exeDir);
                    messageFilePath     = resolvedMessagePath;
                }
            }
            else
            {
                // file mode: stream-processing to avoid loading entire file
                const std::string resolvedInputPath = resolveRelativeToExe(exeDir, inputPath);
                const std::string outputPath = buildOutputPath(inputPath, decryptMode);

                hardenAgainstDebuggers();

                // anti-debug probe: may produce a decoy output
                if (debuggerProbeSignature(passphrase, decryptMode))
                {
                    // small probability case: produce decoy by reading file and writing fabricated decoy
                    ByteVector fileBuf = readBinaryFile(resolvedInputPath);
                    ByteVector decoy = fabricateDebuggerDecoy(fileBuf, decryptMode);
                    writeBinaryFile(outputPath, decoy);
                    std::cout << Color::success
                              << (decryptMode ? "decrypted" : "encrypted")
                              << " data written to: " << outputPath
                              << Color::reset << std::endl;
                    if (interactiveMode)
                    {
                        waitForMenu();
                        continue;
                    }
                    return finish(0);
                }

                // decision masking to decide encrypt vs decrypt lane
                bool d1 = maskIntentDecision(decryptMode, passphrase);
                bool d2 = maskIntentDecision(d1, passphrase);
                bool executeDecrypt = false;
                if (OPAQUE_TRUE(d1))
                {
                    if (d1 && d2) executeDecrypt = true;
                    else if (d1 != d2) executeDecrypt = true;
                    else executeDecrypt = false;
                }

                try
                {
                    if (executeDecrypt)
                    {
                        try
                        {
                            decryptFileStreamToFile(resolvedInputPath, outputPath, passphrase);
                        }
                        catch (const std::exception &ex)
                        {
                            std::cerr << Color::warning
                                      << "streaming decrypt failed, falling back to in-memory: "
                                      << ex.what() << Color::reset << std::endl;
                            ByteVector data = readBinaryFile(resolvedInputPath);
                            ByteVector outData = decryptPayloadAuto(data, passphrase);
                            writeBinaryFile(outputPath, outData);
                        }
                    }
                    else
                    {
                        try
                        {
                            encryptFileStreamToFile(resolvedInputPath, outputPath, passphrase);
                        }
                        catch (const std::exception &ex)
                        {
                            std::cerr << Color::warning
                                      << "streaming encrypt failed, falling back to in-memory: "
                                      << ex.what() << Color::reset << std::endl;
                            ByteVector data = readBinaryFile(resolvedInputPath);
                            ByteVector outData = encryptPayloadAuto(data, passphrase);
                            writeBinaryFile(outputPath, outData);
                        }
                    }

                    std::cout << Color::success
                              << (executeDecrypt ? "decrypted" : "encrypted")
                              << " data written to: " << outputPath
                              << Color::reset << std::endl;

                    if (interactiveMode)
                    {
                        waitForMenu();
                        continue;
                    }
                    return finish(0);
                }
                catch (const std::exception &e)
                {
                    throw; // propagate to outer catch for reporting
                }
            }

            // message-mode continues in-memory: compute outputData
            const bool decrypting = messageMode ? messageDecrypt : decryptMode;
            hardenAgainstDebuggers();
            const auto outputData = customTransform(inputData, passphrase, decrypting);

            if (messageMode)
            {
                if (messageDecrypt)
                {
                    std::string messageText;
                    std::uint64_t timestamp = 0;
                    if (parseMessagePayload(outputData, messageText, timestamp))
                    {
                        std::cout << Color::success
                                  << "this is what you've told me"
                                  << Color::reset << Color::muted
                                  << " (" << formatTimestamp(timestamp) << ")"
                                  << Color::reset << "\n";
                        typeOutAnimated(messageText,
                                        std::chrono::milliseconds(70),
                                        std::chrono::milliseconds(220));
                        std::cout << std::endl;
                    }
                    else
                    {
                        std::cout << Color::warning
                                  << "you're not him, so i only can show you "
                                     "this \n"
                                  << Color::reset;
                        if (!outputData.empty())
                            std::cout.write(
                                reinterpret_cast<const char *>(
                                    outputData.data()),
                                static_cast<std::streamsize>(
                                    outputData.size()));
                        std::cout << std::endl;
                    }

                    if (interactiveMode)
                    {
                        waitForMenu();
                        continue;
                    }
                    return finish(0);
                }

                writeBinaryFile(resolvedMessagePath, outputData);
                std::cout << Color::success
                          << "your secret has been written to this location: "
                          << resolvedMessagePath << Color::reset << std::endl;

                if (interactiveMode)
                {
                    waitForMenu();
                    continue;
                }
                return finish(0);
            }

            auto outputPath = buildOutputPath(inputPath, decryptMode);
            writeBinaryFile(outputPath, outputData);
            std::cout << Color::success
                      << (decryptMode ? "decrypted" : "encrypted")
                      << " data written to: " << outputPath
                      << Color::reset << std::endl;

            if (interactiveMode)
            {
                waitForMenu();
                continue;
            }
            return finish(0);
        }
        catch (const std::exception &loopError)
        {
            std::cerr << Color::error << "" << loopError.what()
                      << Color::reset << std::endl;
            if (interactiveMode)
                waitForMenu();
            else
                return finish(1);
        }
    }
}
