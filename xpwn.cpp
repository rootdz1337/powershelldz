// AllInOne.cpp
// Build: cl /EHsc /W3 /DUNICODE /D_UNICODE AllInOne.cpp advapi32.lib wbemuuid.lib ole32.lib oleaut32.lib
// Run as Administrator.

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <tlhelp32.h>
#include <wbemidl.h>
#include <comdef.h>
#include <sddl.h>
#include <aclapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// ============================================================
//  Utilities
// ============================================================
static void PrintError(const wchar_t* what) {
    wprintf(L"[!] %s failed. GetLastError=%lu\n", what, GetLastError());
}

static bool IsElevated() {
    HANDLE hTok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hTok)) return false;
    TOKEN_ELEVATION te{};
    DWORD sz = sizeof(te);
    bool elevated = false;
    if (GetTokenInformation(hTok, TokenElevation, &te, sz, &sz))
        elevated = te.TokenIsElevated != 0;
    CloseHandle(hTok);
    return elevated;
}

static bool EnablePrivilege(HANDLE hToken, const wchar_t* priv) {
    TOKEN_PRIVILEGES tp{};
    LUID luid;
    if (!LookupPrivilegeValueW(nullptr, priv, &luid)) return false;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    SetLastError(ERROR_SUCCESS);
    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    return ok && GetLastError() == ERROR_SUCCESS;
}

// ============================================================
//  1) SpecialAccounts\UserList  (logon-screen hiding)
// ============================================================
static const wchar_t* kUserListPath =
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\"
    L"SpecialAccounts\\UserList";

static std::vector<std::wstring> EnumHiddenAccounts() {
    std::vector<std::wstring> out;
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kUserListPath, 0,
                      KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS)
        return out;

    DWORD idx = 0;
    wchar_t name[512];
    DWORD nameLen, type, data;
    BYTE buf[64];

    for (;;) {
        nameLen = 512;
        DWORD dataLen = sizeof(buf);
        LSTATUS st = RegEnumValueW(hKey, idx++, name, &nameLen, nullptr, &type,
                                   buf, &dataLen);
        if (st == ERROR_NO_MORE_ITEMS) break;
        if (st != ERROR_SUCCESS) continue;
        if (type == REG_DWORD && dataLen >= sizeof(DWORD)) {
            data = *(DWORD*)buf;
            wchar_t line[600];
            swprintf_s(line, L"%s  -> value=%lu (%s)",
                       name, data,
                       data == 0 ? L"hidden" : L"shown");
            out.push_back(line);
        } else {
            out.push_back(std::wstring(name) + L"  -> (non-DWORD value)");
        }
    }
    RegCloseKey(hKey);
    return out;
}

static bool SetAccountHidden(const std::wstring& account, bool hide) {
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kUserListPath, 0, nullptr,
                        REG_OPTION_NON_VOLATILE,
                        KEY_SET_VALUE | KEY_WOW64_64KEY, nullptr,
                        &hKey, nullptr) != ERROR_SUCCESS) {
        PrintError(L"RegCreateKeyExW(UserList)");
        return false;
    }
    DWORD val = hide ? 0u : 1u;
    LSTATUS st = RegSetValueExW(hKey, account.c_str(), 0, REG_DWORD,
                                (const BYTE*)&val, sizeof(val));
    RegCloseKey(hKey);
    return st == ERROR_SUCCESS;
}

static bool RemoveAccountHidden(const std::wstring& account) {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kUserListPath, 0,
                      KEY_SET_VALUE | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS)
        return false;
    LSTATUS st = RegDeleteValueW(hKey, account.c_str());
    RegCloseKey(hKey);
    return st == ERROR_SUCCESS;
}

// ============================================================
//  2) SYSTEM impersonation  (to access HKLM\SAM)
// ============================================================
static DWORD FindProcessId(const wchar_t* exeName) {
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, exeName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

// Duplicate winlogon's SYSTEM token and impersonate it on the current thread.
// Returns the duplicated token (must ImpersonateLoggedOnUser will be reverted
// with RevertToSelf). Caller owns returned handle.
static HANDLE ImpersonateSystem() {
    HANDLE hProc = nullptr;
    DWORD pid = FindProcessId(L"winlogon.exe");
    if (pid) {
        hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    }
    if (!hProc) {
        // Fallback: get PID of services.exe
        pid = FindProcessId(L"services.exe");
        if (pid)
            hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    }
    if (!hProc) { PrintError(L"OpenProcess(winlogon/services)"); return nullptr; }

    HANDLE hTok = nullptr;
    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, &hTok)) {
        PrintError(L"OpenProcessToken"); CloseHandle(hProc); return nullptr;
    }
    CloseHandle(hProc);

    HANDLE hDup = nullptr;
    if (!DuplicateTokenEx(hTok, TOKEN_ALL_ACCESS, nullptr,
                          SecurityImpersonation, TokenImpersonation, &hDup)) {
        PrintError(L"DuplicateTokenEx"); CloseHandle(hTok); return nullptr;
    }
    CloseHandle(hTok);

    if (!ImpersonateLoggedOnUser(hDup)) {
        PrintError(L"ImpersonateLoggedOnUser");
        CloseHandle(hDup);
        return nullptr;
    }
    return hDup;
}

// ============================================================
//  3) SAM ACL manipulation + SAM reading
// ============================================================
// Grant BUILTIN\Administrators full access (READ included) to HKLM\SAM
static bool GrantSamAccess() {
    HANDLE hTok = ImpersonateSystem();
    if (!hTok) { wprintf(L"[!] Could not impersonate SYSTEM.\n"); return false; }

    bool ok = false;
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SAM", 0,
                      READ_CONTROL | WRITE_DAC, &hKey) != ERROR_SUCCESS) {
        PrintError(L"RegOpenKeyExW(SAM)");
    } else {
        PSECURITY_DESCRIPTOR pSD = nullptr;
        PACL pOldDacl = nullptr;
        if (GetSecurityInfo(hKey, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION,
                            nullptr, nullptr, &pOldDacl, nullptr, &pSD)
            == ERROR_SUCCESS) {
            PSID pAdmins = nullptr;
            // S-1-5-32-544 = BUILTIN\Administrators
            if (ConvertStringSidToSidW(L"S-1-5-32-544", &pAdmins)) {
                EXPLICIT_ACCESS_W ea{};
                ea.grfAccessPermissions = KEY_ALL_ACCESS;
                ea.grfAccessMode        = GRANT_ACCESS;
                ea.grfInheritance       = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
                ea.Trustee.TrusteeForm  = TRUSTEE_IS_SID;
                ea.Trustee.TrusteeType  = TRUSTEE_IS_GROUP;
                ea.Trustee.ptstrName    = (LPWSTR)pAdmins;

                PACL pNewDacl = nullptr;
                if (SetEntriesInAclW(1, &ea, pOldDacl, &pNewDacl) == ERROR_SUCCESS) {
                    if (SetSecurityInfo(hKey, SE_REGISTRY_KEY,
                                        DACL_SECURITY_INFORMATION,
                                        nullptr, nullptr, pNewDacl, nullptr)
                        == ERROR_SUCCESS)
                        ok = true;
                    else
                        PrintError(L"SetSecurityInfo(SAM)");
                    LocalFree(pNewDacl);
                } else {
                    PrintError(L"SetEntriesInAcl");
                }
                LocalFree(pAdmins);
            } else {
                PrintError(L"ConvertStringSidToSid");
            }
            LocalFree(pSD);
        } else {
            PrintError(L"GetSecurityInfo(SAM)");
        }
        RegCloseKey(hKey);
    }

    RevertToSelf();
    CloseHandle(hTok);
    return ok;
}

// Read a user's "F" value flag (RID string is hex, e.g. L"000001F4")
static bool ReadSamUserFlags(const std::wstring& rid, DWORD* outFlags) {
    std::wstring path = L"SAM\\SAM\\Domains\\Account\\Users\\" + rid;
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_READ, &hKey)
        != ERROR_SUCCESS)
        return false;

    BYTE buf[0x100] = {};
    DWORD sz = sizeof(buf), type = 0;
    LSTATUS st = RegQueryValueExW(hKey, L"F", nullptr, &type, buf, &sz);
    RegCloseKey(hKey);
    if (st != ERROR_SUCCESS || sz < 0x3C) return false;

    // F layout: offset 0x38 = DWORD user flags.
    *outFlags = *(DWORD*)(buf + 0x38);
    return true;
}

// Enumerate SAM user RID subkeys and print flag status.
static void EnumerateSamUsers() {
    HANDLE hTok = ImpersonateSystem();
    if (!hTok) { wprintf(L"[!] Cannot impersonate SYSTEM.\n"); return; }

    HKEY hUsers;
    std::wstring base = L"SAM\\SAM\\Domains\\Account\\Users";
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, base.c_str(), 0,
                      KEY_READ, &hUsers) != ERROR_SUCCESS) {
        PrintError(L"RegOpenKeyExW(Users)");
        RevertToSelf(); CloseHandle(hTok);
        wprintf(L"[i] Tip: run option [2] first to grant Administrators access to SAM.\n");
        return;
    }

    wprintf(L"%-10s  %-10s  %s\n", L"RID(hex)", L"Flags", L"Status");
    wprintf(L"---------------------------------------------\n");

    DWORD idx = 0;
    wchar_t sub[256];
    for (;;) {
        DWORD subLen = 256;
        LSTATUS st = RegEnumKeyExW(hUsers, idx++, sub, &subLen, nullptr,
                                   nullptr, nullptr, nullptr);
        if (st == ERROR_NO_MORE_ITEMS) break;
        if (st != ERROR_SUCCESS) continue;
        if (_wcsicmp(sub, L"Names") == 0) continue;

        DWORD flags = 0;
        if (ReadSamUserFlags(sub, &flags)) {
            bool disabled = (flags & 0x0002) != 0;  // UF_ACCOUNTDISABLE
            bool locked   = (flags & 0x0010) != 0;  // UF_LOCKOUT
            bool pwdNever = (flags & 0x0020) != 0;  // UF_PASSWD_NOTREQD
            wprintf(L"%-10s  0x%08lX  %s%s%s\n", sub, flags,
                    disabled ? L"[disabled] " : L"",
                    locked   ? L"[locked] "   : L"",
                    pwdNever ? L"[pwd-not-required]" : L"");
        } else {
            wprintf(L"%-10s  (no F value)\n", sub);
        }
    }
    RegCloseKey(hUsers);
    RevertToSelf();
    CloseHandle(hTok);
}

// ============================================================
//  4) WMI  — local accounts, disabled/hidden status
// ============================================================
static void QueryWmiLocalAccounts() {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool comInit = SUCCEEDED(hr);

    hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
                              RPC_C_AUTHN_LEVEL_DEFAULT,
                              RPC_C_IMP_LEVEL_IMPERSONATE,
                              nullptr, EOAC_NONE, nullptr);
    if (FAILED(hr) && hr != RPC_E_TOO_LATE)
        wprintf(L"[!] CoInitializeSecurity hr=0x%08lX\n", hr);

    IWbemLocator* pLoc = nullptr;
    IWbemServices* pSvc = nullptr;
    IEnumWbemClassObject* pEnum = nullptr;

    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
                          IID_IWbemLocator, (void**)&pLoc);
    if (FAILED(hr)) { PrintError(L"CoCreateInstance(WbemLocator)"); goto cleanup; }

    hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), nullptr, nullptr, 0,
                             nullptr, 0, 0, &pSvc);
    if (FAILED(hr)) { PrintError(L"ConnectServer"); goto cleanup; }

    CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                      RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                      nullptr, EOAC_NONE);

    hr = pSvc->ExecQuery(
        _bstr_t(L"WQL"),
        _bstr_t(L"SELECT Name, SID, Disabled, Lockout, LocalAccount "
                L"FROM Win32_UserAccount WHERE LocalAccount = TRUE"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr, &pEnum);
    if (FAILED(hr)) { PrintError(L"ExecQuery"); goto cleanup; }

    {
        IWbemClassObject* pObj = nullptr;
        ULONG ret = 0;
        wprintf(L"%-20s %-48s %-9s %-9s\n", L"Name", L"SID", L"Disabled", L"Lockout");
        wprintf(L"---------------------------------------------------------------------------------------\n");
        while (pEnum->Next(WBEM_INFINITE, 1, &pObj, &ret) == S_OK) {
            VARIANT vName{}, vSid{}, vDis{}, vLock{};
            pObj->Get(L"Name",     0, &vName, nullptr, nullptr);
            pObj->Get(L"SID",      0, &vSid,  nullptr, nullptr);
            pObj->Get(L"Disabled", 0, &vDis,  nullptr, nullptr);
            pObj->Get(L"Lockout",  0, &vLock, nullptr, nullptr);
            wprintf(L"%-20s %-48s %-9ls %-9ls\n",
                    vName.bstrVal ? vName.bstrVal : L"",
                    vSid.bstrVal  ? vSid.bstrVal  : L"",
                    vDis.vt  == VT_BOOL ? (vDis.boolVal  ? L"TRUE" : L"FALSE") : L"?",
                    vLock.vt == VT_BOOL ? (vLock.boolVal ? L"TRUE" : L"FALSE") : L"?");
            VariantClear(&vName); VariantClear(&vSid);
            VariantClear(&vDis);  VariantClear(&vLock);
            pObj->Release();
            pObj = nullptr;
        }
    }

cleanup:
    if (pEnum) pEnum->Release();
    if (pSvc)  pSvc->Release();
    if (pLoc)  pLoc->Release();
    if (comInit) CoUninitialize();
}

// ============================================================
//  Menu
// ============================================================
static void PrintMenu() {
    wprintf(L"\n========= SAM / SpecialAccounts / WMI Utility =========\n");
    wprintf(L" [1] List SpecialAccounts\\UserList entries\n");
    wprintf(L" [2] Hide account from logon screen (add value=0)\n");
    wprintf(L" [3] Show account on logon screen (set value=1)\n");
    wprintf(L" [4] Remove UserList entry\n");
    wprintf(L" [5] Grant Administrators access to HKLM\\SAM (SYSTEM impersonation)\n");
    wprintf(L" [6] Enumerate SAM users and show flag status\n");
    wprintf(L" [7] Query WMI Win32_UserAccount (local accounts)\n");
    wprintf(L" [8] Run FULL audit (1 + 6 + 7)\n");
    wprintf(L" [0] Exit\n");
    wprintf(L"=======================================================\n");
    wprintf(L" Choice: ");
}

int wmain() {
    SetConsoleOutputCP(CP_UTF8);

    if (!IsElevated())
        wprintf(L"[!] Warning: not elevated. Most operations will fail.\n");

    HANDLE hSelf = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hSelf)) {
        EnablePrivilege(hSelf, SE_DEBUG_NAME);
        EnablePrivilege(hSelf, SE_BACKUP_NAME);
        EnablePrivilege(hSelf, SE_RESTORE_NAME);
        CloseHandle(hSelf);
    }

    for (;;) {
        PrintMenu();
        wchar_t line[64];
        if (!fgetws(line, 64, stdin)) break;
        int choice = _wtoi(line);

        switch (choice) {
        case 0: return 0;

        case 1: {
            auto items = EnumHiddenAccounts();
            if (items.empty()) wprintf(L"(no SpecialAccounts\\UserList entries)\n");
            for (auto& s : items) wprintf(L"  %s\n", s.c_str());
            break;
        }

        case 2: case 3: {
            wprintf(L" Account name: ");
            wchar_t acct[256] = {};
            if (!fgetws(acct, 256, stdin)) break;
            acct[wcslen(acct) > 0 ? wcslen(acct) - 1 : 0] = 0;
            if (SetAccountHidden(acct, choice == 2))
                wprintf(L"[+] UserList updated (%s)\n", choice == 2 ? L"hidden" : L"shown");
            else
                wprintf(L"[!] Failed.\n");
            break;
        }

        case 4: {
            wprintf(L" Account name: ");
            wchar_t acct[256] = {};
            if (!fgetws(acct, 256, stdin)) break;
            acct[wcslen(acct) > 0 ? wcslen(acct) - 1 : 0] = 0;
            if (RemoveAccountHidden(acct))
                wprintf(L"[+] Removed.\n");
            else
                wprintf(L"[!] Failed (or entry absent).\n");
            break;
        }

        case 5:
            wprintf(L"[*] Impersonating SYSTEM and updating SAM DACL...\n");
            if (GrantSamAccess())
                wprintf(L"[+] Administrators now have access to HKLM\\SAM.\n");
            else
                wprintf(L"[!] Failed.\n");
            break;

        case 6:
            EnumerateSamUsers();
            break;

        case 7:
            QueryWmiLocalAccounts();
            break;

        case 8: {
            wprintf(L"\n--- SpecialAccounts\\UserList ---\n");
            auto items = EnumHiddenAccounts();
            if (items.empty()) wprintf(L"(none)\n");
            for (auto& s : items) wprintf(L"  %s\n", s.c_str());

            wprintf(L"\n--- HKLM\\SAM users ---\n");
            EnumerateSamUsers();

            wprintf(L"\n--- WMI local accounts ---\n");
            QueryWmiLocalAccounts();
            break;
        }

        default:
            wprintf(L"Invalid choice.\n");
        }
    }
    return 0;
}
