#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
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
        catch (...) { return false; }
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
          const std::size_t words = memBytes / 8U;
          if (words <= 8U) throw std::invalid_argument("KDF memory too small");

          // allocate cache-line aligned scratch
          std::uint64_t *mem64 = static_cast<std::uint64_t *>(aligned_alloc_portable(alignBytes, memBytes));
          if (!mem64) throw std::bad_alloc();

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

        // optional mlock/VirtualLock if user opts in via env
        bool locked = false;
        const char *lockEnv = std::getenv("THERAPIST_KDF_MLOCK");
        if (lockEnv && lockEnv[0] != '\0')
        {
            // best-effort: don't fail KDF if locking not permitted
            locked = lock_memory(mem64, memBytes);
        }

        // prefetch the scratch region to reduce page faults during mixing
        prefetch_range(mem64, memBytes);

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

        /* wipe scratch buffer (mem64) */
        volatile std::uint8_t *vp = reinterpret_cast<volatile std::uint8_t *>(mem64);
        for (std::size_t i = 0; i < memBytes; ++i) vp[i] = 0;

        if (locked) unlock_memory(mem64, memBytes);
        aligned_free_portable(mem64);

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

                // increment counter
                for (std::size_t i = 0; i < ctr.size(); ++i)
                    if (++ctr[i] != 0U) break;

                off += chunk;
            }
        }

        void encryptFileStreamToFile(const std::string &inPath,
                                     const std::string &outPath,
                                     const std::string &passphrase)
        {
            std::ifstream fin(inPath, std::ios::binary);
            if (!fin) throw std::runtime_error("unable to open input file: " + inPath);
            fin.seekg(0, std::ios::end);
            std::size_t plainSize = static_cast<std::size_t>(fin.tellg());
            fin.seekg(0, std::ios::beg);

            // generate salts and chaff
            ByteVector salt1 = generateSalt(kSaltSizeV5);
            ByteVector salt2 = generateSalt(kSaltSizeV5);
            std::uint8_t rndByte[1];
            fillCryptoRandom(rndByte, 1);
            std::size_t chaffLen = kChaffMinBytes + (static_cast<std::size_t>(rndByte[0]) % (kChaffMaxBytes - kChaffMinBytes + 1));
            ByteVector chaff(static_cast<std::size_t>(chaffLen));
            fillCryptoRandom(chaff.data(), chaffLen);

            // derive key schedules (sequential — portable)
            HardenedKeySchedule ks1 = deriveHardenedSchedule(passphrase, salt1);
            HardenedKeySchedule ks2 = deriveHardenedSchedule(passphrase, salt2);

            // open output and write header (magic + ver + lengths + salts + placeholder mac)
            std::ofstream fout(outPath, std::ios::binary | std::ios::trunc);
            if (!fout) throw std::runtime_error("unable to open output file: " + outPath);

            fout.write(reinterpret_cast<const char *>(kMagicV5.data()), static_cast<std::streamsize>(kMagicV5.size()));
            fout.put(static_cast<char>(kVersionV5));
            fout.put(static_cast<char>(static_cast<std::uint8_t>(kSaltSizeV5)));
            fout.put(static_cast<char>(static_cast<std::uint8_t>(kMacSizeV5)));
            fout.write(reinterpret_cast<const char *>(salt1.data()), static_cast<std::streamsize>(salt1.size()));
            fout.write(reinterpret_cast<const char *>(salt2.data()), static_cast<std::streamsize>(salt2.size()));

            std::streamoff macPos = static_cast<std::streamoff>(kMagicV5.size() + 3 + kSaltSizeV5 * 2);
            // reserve mac bytes
            std::vector<char> zeros(kMacSizeV5, 0);
            fout.write(zeros.data(), static_cast<std::streamsize>(zeros.size()));

            (void)0; // no-op: schedules already derived

            // initial counters
            auto ctr1 = initCtrFromSalt(salt1);
            auto ctr2 = initCtrFromSalt(salt2);

            // prepare MAC state
            Mac256 mac = macInit(passphrase, salt1, salt2, static_cast<std::uint32_t>(plainSize));

            // encrypt preamble (chaff length + chaff bytes)
            std::vector<std::uint8_t> preamble;
            preamble.reserve(2 + chaffLen);
            preamble.push_back(static_cast<std::uint8_t>(chaffLen & 0xFFU));
            preamble.push_back(static_cast<std::uint8_t>((chaffLen >> 8U) & 0xFFU));
            preamble.insert(preamble.end(), chaff.begin(), chaff.end());

            std::vector<std::uint8_t> tmp1(preamble.size()), tmp2(preamble.size());
            applyEnhancedCipherChunk(preamble.data(), preamble.size(), tmp1.data(), ks1, ctr1);
            applyEnhancedCipherChunk(tmp1.data(), tmp1.size(), tmp2.data(), ks2, ctr2);
            fout.write(reinterpret_cast<const char *>(tmp2.data()), static_cast<std::streamsize>(tmp2.size()));

            // stream plaintext
            std::vector<std::uint8_t> inBuf(kStreamChunkSize);
            std::vector<std::uint8_t> out1Buf(kStreamChunkSize);
            std::vector<std::uint8_t> out2Buf(kStreamChunkSize);
            while (fin)
            {
                fin.read(reinterpret_cast<char *>(inBuf.data()), static_cast<std::streamsize>(inBuf.size()));
                std::streamsize got = fin.gcount();
                if (got <= 0) break;
                std::size_t gotu = static_cast<std::size_t>(got);

                // feed MAC over plaintext bytes
                macFeedBuffer(mac, inBuf.data(), gotu);

                // first pass
                applyEnhancedCipherChunk(inBuf.data(), gotu, out1Buf.data(), ks1, ctr1);
                // second pass
                applyEnhancedCipherChunk(out1Buf.data(), gotu, out2Buf.data(), ks2, ctr2);

                fout.write(reinterpret_cast<const char *>(out2Buf.data()), static_cast<std::streamsize>(gotu));
            }

            // finalise MAC and write into header
            macFinalize(mac);
            // write mac as 4 x 8-byte big-endian
            fout.seekp(macPos);
            for (int i = 0; i < 4; ++i)
                for (int shift = 56; shift >= 0; shift -= 8)
                {
                    unsigned char b = static_cast<unsigned char>((mac.h[i] >> shift) & 0xFFU);
                    fout.put(static_cast<char>(b));
                }

            fout.flush();
        }

        void decryptFileStreamToFile(const std::string &inPath,
                                     const std::string &outPath,
                                     const std::string &passphrase)
        {
            std::ifstream fin(inPath, std::ios::binary);
            if (!fin) throw std::runtime_error("unable to open input file: " + inPath);
            fin.seekg(0, std::ios::end);
            std::size_t fileSize = static_cast<std::size_t>(fin.tellg());
            fin.seekg(0, std::ios::beg);

            // read header
            std::array<char, 4> magicBuf{};
            fin.read(magicBuf.data(), 4);
            if (!fin) throw std::runtime_error("failed to read header");
            if (!std::equal(magicBuf.begin(), magicBuf.end(), reinterpret_cast<const char *>(kMagicV5.data())))
                throw std::runtime_error("encrypted data header mismatch");
            int version = fin.get();
            if (version != kVersionV5) throw std::runtime_error("unsupported encrypted data version");
            int saltLen = fin.get();
            int macLen = fin.get();
            if (saltLen <= 0 || macLen != static_cast<int>(kMacSizeV5))
                throw std::runtime_error("corrupted encrypted data header");

            ByteVector salt1(static_cast<std::size_t>(saltLen));
            ByteVector salt2(static_cast<std::size_t>(saltLen));
            fin.read(reinterpret_cast<char *>(salt1.data()), static_cast<std::streamsize>(salt1.size()));
            fin.read(reinterpret_cast<char *>(salt2.data()), static_cast<std::streamsize>(salt2.size()));

            Mac256 storedMac{};
            for (int i = 0; i < 4; ++i)
            {
                storedMac.h[i] = 0;
                for (int j = 0; j < 8; ++j)
                {
                    int ch = fin.get();
                    if (ch == EOF) throw std::runtime_error("truncated mac in header");
                    storedMac.h[i] = (storedMac.h[i] << 8U) | static_cast<std::uint64_t>(static_cast<unsigned char>(ch));
                }
            }

            std::size_t hdrSize = static_cast<std::size_t>(kMagicV5.size() + 3 + saltLen * 2 + macLen);
            std::size_t cipherSize = fileSize - hdrSize;

            // derive both key schedules (sequential — portable)
            HardenedKeySchedule ks1 = deriveHardenedSchedule(passphrase, salt1);
            HardenedKeySchedule ks2 = deriveHardenedSchedule(passphrase, salt2);

            // initial counters
            auto ctr1 = initCtrFromSalt(salt1);
            auto ctr2 = initCtrFromSalt(salt2);

            // prepare output
            std::ofstream fout(outPath, std::ios::binary | std::ios::trunc);
            if (!fout) throw std::runtime_error("unable to open output file: " + outPath);

            // stream decryption: read first chunk to extract chaff length
            std::vector<std::uint8_t> inBuf(kStreamChunkSize);
            std::vector<std::uint8_t> tmp1(kStreamChunkSize);
            std::vector<std::uint8_t> tmp2(kStreamChunkSize);

            // read and process first chunk
            fin.read(reinterpret_cast<char *>(inBuf.data()), static_cast<std::streamsize>(inBuf.size()));
            std::streamsize got = fin.gcount();
            if (got <= 0) return; // nothing to do
            std::size_t gotu = static_cast<std::size_t>(got);

            // undo pass2 then pass1 on first chunk
            applyEnhancedCipherChunk(inBuf.data(), gotu, tmp1.data(), ks2, ctr2);
            applyEnhancedCipherChunk(tmp1.data(), gotu, tmp2.data(), ks1, ctr1);

            // augmented size equals cipherSize
            std::size_t augmentedSize = cipherSize;
            if (gotu < 2)
            {
                // read until we have at least two decrypted bytes
                std::vector<std::uint8_t> extra(2 - gotu);
                fin.read(reinterpret_cast<char *>(extra.data()), static_cast<std::streamsize>(extra.size()));
                std::streamsize got2 = fin.gcount();
                if (got2 <= 0) throw std::runtime_error("truncated augmented header");
                // decrypt additional bytes
                std::size_t extrau = static_cast<std::size_t>(got2);
                // process extra ciphertext
                std::vector<std::uint8_t> tmpA(extrau);
                fin.read(reinterpret_cast<char *>(inBuf.data()), static_cast<std::streamsize>(extrau));
            }

            // read chaff length from first two bytes
            if (gotu < 2) throw std::runtime_error("failed to read chaff length");
            std::size_t chaffLen = static_cast<std::size_t>(tmp2[0]) | (static_cast<std::size_t>(tmp2[1]) << 8U);
            if (chaffLen < kChaffMinBytes || chaffLen > kChaffMaxBytes) throw std::runtime_error("invalid chaff length");

            std::size_t plainSize = 0;
            if (augmentedSize < 2 + chaffLen) throw std::runtime_error("corrupted augmented size");
            plainSize = augmentedSize - 2 - chaffLen;

            // initialize MAC with known plaintext size
            Mac256 mac = macInit(passphrase, salt1, salt2, static_cast<std::uint32_t>(plainSize));

            // handle initial decrypted bytes: skip 2 + chaffLen bytes from augmented
            std::size_t skip = 2 + chaffLen;
            std::size_t consumed = 0;
            if (gotu > skip)
            {
                std::size_t plainPart = gotu - skip;
                macFeedBuffer(mac, tmp2.data() + skip, plainPart);
                fout.write(reinterpret_cast<const char *>(tmp2.data() + skip), static_cast<std::streamsize>(plainPart));
                consumed = gotu;
            }
            else if (gotu <= skip)
            {
                // still in chaff area; nothing to write
                consumed = gotu;
            }

            // continue streaming remaining ciphertext
            while (fin)
            {
                fin.read(reinterpret_cast<char *>(inBuf.data()), static_cast<std::streamsize>(inBuf.size()));
                std::streamsize g = fin.gcount();
                if (g <= 0) break;
                std::size_t gu = static_cast<std::size_t>(g);

                applyEnhancedCipherChunk(inBuf.data(), gu, tmp1.data(), ks2, ctr2);
                applyEnhancedCipherChunk(tmp1.data(), gu, tmp2.data(), ks1, ctr1);

                // if we haven't finished skipping chaff, handle that
                if (consumed < skip)
                {
                    std::size_t to_skip = std::min(skip - consumed, gu);
                    if (to_skip < gu)
                    {
                        // some plaintext in this chunk
                        std::size_t plainPart = gu - to_skip;
                        macFeedBuffer(mac, tmp2.data() + to_skip, plainPart);
                        fout.write(reinterpret_cast<const char *>(tmp2.data() + to_skip), static_cast<std::streamsize>(plainPart));
                    }
                    // else entirely chaff
                    consumed += gu;
                }
                else
                {
                    // all plaintext
                    macFeedBuffer(mac, tmp2.data(), gu);
                    fout.write(reinterpret_cast<const char *>(tmp2.data()), static_cast<std::streamsize>(gu));
                }
            }

            // finalise and compare MAC
            macFinalize(mac);
            if (!constantTimeMacEq(mac, storedMac))
                throw std::runtime_error("authentication failed wrong passphrase or corrupted data");
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
        ByteVector pass1;
        applyEnhancedCipher(augmented, pass1, ks1, salt1);

        /* second encryption pass with independent key */
        auto ks2 = deriveHardenedSchedule(passphrase, salt2);
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
        residualArgs.push_back(a);
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
                        decryptFileStreamToFile(resolvedInputPath, outputPath, passphrase);
                    else
                        encryptFileStreamToFile(resolvedInputPath, outputPath, passphrase);

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
