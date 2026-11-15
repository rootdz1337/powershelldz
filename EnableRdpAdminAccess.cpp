// EnableRdpAdminAccess.cpp
// Compile: cl /EHsc /W4 /std:c++17 EnableRdpAdminAccess.cpp netapi32.lib advapi32.lib user32.lib
//
// Same behaviour as Enable-RdpAdminAccess.ps1:
//   - creates a NAMED local user
//   - adds to Remote Desktop Users ONLY (not Administrators)
//   - sets account expiry
//   - enables RDP + NLA + firewall
//   - writes an append-only audit log
//
// Deliberately NOT implemented:
//   - hiding from logon screen / net user / Computer Management
//   - adding to Administrators
//   - non-expiring password
//   - service persistence for the account
//   - log clearing / audit policy change

#define UNICODE
#define _UNICODE
#include <windows.h>
#include <lm.h>
#include <netfw.h>
#include <string>
#include <iostream>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <random>

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// ---------- audit ----------
static std::wstring g_auditFile;

static void InitAudit()
{
    wchar_t programData[MAX_PATH]{};
    DWORD n = GetEnvironmentVariableW(L"ProgramData", programData, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return;

    std::wstring dir = std::wstring(programData) + L"\\RdpAdminAudit";
    CreateDirectoryW(dir.c_str(), nullptr);

    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t name[64];
    swprintf_s(name, L"rdp-audit-%04d%02d%02d.log", st.wYear, st.wMonth, st.wDay);
    g_auditFile = dir + L"\\" + name;
}

static std::wstring NowIso()
{
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t buf[32];
    swprintf_s(buf, L"%04d-%02d-%02dT%02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

static void Audit(const std::wstring& msg)
{
    if (g_auditFile.empty()) return;

    wchar_t user[256]{}; DWORD ulen = 256;
    GetUserNameW(user, &ulen);

    wchar_t comp[256]{}; DWORD clen = 256;
    GetComputerNameW(comp, &clen);

    std::wostringstream w;
    w << NowIso() << L" | " << user << L" | " << comp << L" | " << msg << L"\n";

    std::wofstream f(g_auditFile, std::ios::app);
    f << w.str();

    std::wcout << L"[audit] " << msg << L"\n";
}

// ---------- helpers ----------
static bool IsElevated()
{
    HANDLE h = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &h)) return false;
    TOKEN_ELEVATION e{};
    DWORD sz = sizeof(e);
    BOOL ok = GetTokenInformation(h, TokenElevation, &e, sz, &sz);
    CloseHandle(h);
    return ok && e.TokenIsElevated;
}

static std::wstring RandomPassword(int len = 20)
{
    // System.Web.Security.Membership::GeneratePassword equivalent
    static const wchar_t* sets[] = {
        L"abcdefghijkmnopqrstuvwxyz",
        L"ABCDEFGHJKLMNPQRSTUVWXYZ",
        L"23456789",
        L"!@#$%^&*()-_=+[]{}"
    };
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> setPick(0, 3);

    std::wstring out;
    for (int i = 0; i < len; ++i)
    {
        int s = setPick(gen);
        std::uniform_int_distribution<> chPick(0, (int)wcslen(sets[s]) - 1);
        out.push_back(sets[s][chPick(gen)]);
    }
    return out;
}

// ---------- user creation ----------
static bool CreateLocalUser(const std::wstring& user,
                            const std::wstring& pass,
                            int expiresInDays)
{
    USER_INFO_1 ui{};
    ui.usri1_name     = const_cast<LPWSTR>(user.c_str());
    ui.usri1_password = const_cast<LPWSTR>(pass.c_str());
    ui.usri1_priv     = USER_PRIV_USER;
    ui.usri1_home_dir = nullptr;
    ui.usri1_comment  = const_cast<LPWSTR>(L"RDP access - temporary");
    ui.usri1_flags    = UF_SCRIPT; // no DONT_EXPIRE_PASSWD, no PASSWD_CANT_CHANGE

    DWORD err = NetUserAdd(nullptr, 1, (LPBYTE)&ui, nullptr);
    if (err != NERR_Success) {
        std::wcerr << L"NetUserAdd failed: " << err << L"\n";
        return false;
    }

    // set account expiry (seconds since 1970-01-01 UTC)
    if (expiresInDays > 0)
    {
        FILETIME ft; GetSystemTimeAsFileTime(&ft);
        ULARGE_INTEGER u; u.LowPart = ft.dwLowDateTime; u.HighPart = ft.dwHighDateTime;
        // FILETIME is 100ns since 1601 -> convert to seconds since 1970
        long long secs = (long long)((u.QuadPart - 116444736000000000ULL) / 10000000ULL);
        secs += (long long)expiresInDays * 86400LL;

        USER_INFO_1008 expiry{};
        expiry.usri1008_flags = 0; // no additional flag
        // use USER_INFO_1017 for account expiry
        USER_INFO_1017 ui17{};
        ui17.usri1017_acct_expires = (DWORD)secs;
        NetUserSetInfo(nullptr, user.c_str(), 1017, (LPBYTE)&ui17, nullptr);
    }

    return true;
}

static bool AddToGroup(const std::wstring& user, const std::wstring& group)
{
    LOCALGROUP_MEMBERS_INFO_3 member{};
    member.lgrmi3_domainandname = const_cast<LPWSTR>(user.c_str());
    DWORD err = NetLocalGroupAddMembers(
        nullptr, group.c_str(), 3, (LPBYTE)&member, 1);
    if (err != NERR_Success && err != ERROR_MEMBER_IN_GROUP) {
        std::wcerr << L"NetLocalGroupAddMembers(" << group << L") failed: " << err << L"\n";
        return false;
    }
    return true;
}

static bool IsInGroup(const std::wstring& user, const std::wstring& group)
{
    DWORD read = 0, total = 0;
    LOCALGROUP_MEMBERS_INFO_3* buf = nullptr;
    DWORD err = NetLocalGroupGetMembers(
        nullptr, group.c_str(), 3, (LPBYTE*)&buf,
        MAX_PREFERRED_LENGTH, &read, &total, nullptr);
    if (err != NERR_Success) return false;

    bool found = false;
    for (DWORD i = 0; i < read; ++i) {
        if (buf[i].lgrmi3_domainandname &&
            _wcsicmp(buf[i].lgrmi3_domainandname, user.c_str()) == 0) {
            found = true; break;
        }
    }
    NetApiBufferFree(buf);
    return found;
}

static bool RemoveFromGroup(const std::wstring& user, const std::wstring& group)
{
    LOCALGROUP_MEMBERS_INFO_3 member{};
    member.lgrmi3_domainandname = const_cast<LPWSTR>(user.c_str());
    DWORD err = NetLocalGroupDelMembers(
        nullptr, group.c_str(), 3, (LPBYTE)&member, 1);
    return err == NERR_Success;
}

// ---------- RDP enable ----------
static bool EnableRdp()
{
    HKEY h{};
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
            0, KEY_SET_VALUE, &h) != ERROR_SUCCESS) return false;

    DWORD zero = 0;
    RegSetValueExW(h, L"fDenyTSConnections", 0, REG_DWORD,
                   (const BYTE*)&zero, sizeof(zero));
    RegCloseKey(h);

    // NLA
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
            0, KEY_SET_VALUE, &h) == ERROR_SUCCESS) {
        DWORD one = 1;
        RegSetValueExW(h, L"UserAuthentication", 0, REG_DWORD,
                       (const BYTE*)&one, sizeof(one));
        RegCloseKey(h);
    }
    return true;
}

static bool EnableRdpFirewall()
{
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) return false;

    INetFwPolicy2* policy = nullptr;
    hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr,
                          CLSCTX_INPROC_SERVER,
                          __uuidof(INetFwPolicy2), (void**)&policy);
    if (FAILED(hr)) { CoUninitialize(); return false; }

    INetFwRules* rules = nullptr;
    hr = policy->get_Rules(&rules);
    if (FAILED(hr)) { policy->Release(); CoUninitialize(); return false; }

    // Enable the built-in "Remote Desktop" rules by group name
    IUnknown* unk = nullptr;
    rules->get__NewEnum(&unk);
    IEnumVARIANT* e = nullptr;
    unk->QueryInterface(__uuidof(IEnumVARIANT), (void**)&e);

    VARIANT v{}; ULONG fetched = 0;
    while (e->Next(1, &v, &fetched) == S_OK && fetched) {
        if (v.vt == VT_DISPATCH && v.pdispVal) {
            INetFwRule* r = nullptr;
            if (SUCCEEDED(v.pdispVal->QueryInterface(__uuidof(INetFwRule), (void**)&r))) {
                BSTR grp = nullptr;
                r->get_Grouping(&grp);
                if (grp && wcscmp(grp, L"@FirewallAPI.dll,-28752") == 0) {
                    r->put_Enabled(VARIANT_TRUE);
                }
                SysFreeString(grp);
                r->Release();
            }
        }
        VariantClear(&v);
    }
    e->Release();
    rules->Release();
    policy->Release();
    CoUninitialize();
    return true;
}

// ---------- main ----------
int wmain(int argc, wchar_t** argv)
{
    if (!IsElevated()) {
        std::wcerr << L"Run elevated.\n";
        return 1;
    }
    InitAudit();

    std::wstring user;
    int expires = 30;
    bool force = false;

    for (int i = 1; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"--user" && i + 1 < argc)      user = argv[++i];
        else if (a == L"--expires" && i + 1 < argc) expires = _wtoi(argv[++i]);
        else if (a == L"--force")                force = true;
    }

    if (user.empty() || user.size() < 3 || user.size() > 20) {
        std::wcerr << L"Usage: EnableRdpAdminAccess.exe --user NAME [--expires DAYS] [--force]\n";
        return 1;
    }

    static const wchar_t* blocked[] = {
        L"admin", L"administrator", L"root", L"sysadmin",
        L"support", L"helpdesk", L"backup", L"default",
        L"guest", L"user", L"test"
    };
    for (auto b : blocked)
        if (_wcsicmp(user.c_str(), b) == 0) {
            std::wcerr << L"Refusing generic account name.\n";
            return 1;
        }

    // existing?
    LPUSER_INFO_0 info = nullptr;
    if (NetUserGetInfo(nullptr, user.c_str(), 0, (LPBYTE*)&info) == NERR_Success) {
        NetApiBufferFree(info);
        std::wcerr << L"User already exists.\n";
        return 1;
    }

    if (expires <= 0 && !force) {
        std::wcerr << L"No expiry requires --force.\n";
        return 1;
    }

    std::wstring pass = RandomPassword(20);

    Audit(L"ACTION=create-user TARGET=" + user +
          L" EXPIRY=" + std::to_wstring(expires));

    if (!CreateLocalUser(user, pass, expires)) {
        Audit(L"FAIL create-user TARGET=" + user);
        return 2;
    }

    Audit(L"ACTION=add-group GROUP=Remote Desktop Users TARGET=" + user);
    if (!AddToGroup(user, L"Remote Desktop Users")) {
        Audit(L"FAIL add-group TARGET=" + user);
        return 3;
    }

    // ensure NOT admin
    if (IsInGroup(user, L"Administrators")) {
        Audit(L"WARN user in Administrators - removing TARGET=" + user);
        RemoveFromGroup(user, L"Administrators");
    }

    Audit(L"ACTION=enable-rdp");
    EnableRdp();
    EnableRdpFirewall();

    Audit(L"ACTION=complete TARGET=" + user +
          L" GROUPS=Remote Desktop Users EXPIRY=" + std::to_wstring(expires));

    std::wcout << L"\n=== User created ===\n"
               << L"  Username: " << user << L"\n"
               << L"  Groups:   Remote Desktop Users\n"
               << L"  Expiry:   " << expires << L" days\n"
               << L"  Password: " << pass << L"\n"
               << L"  ** Shown once. **\n"
               << L"\nAudit: " << g_auditFile << L"\n";

    return 0;
}
