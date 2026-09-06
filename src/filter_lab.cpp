#include "filter_lab.h"
#include <wrl/client.h>
#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>

using Microsoft::WRL::ComPtr;
using namespace swa::lab;
namespace {
void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
    std::cout << "PASS " << message << '\n';
}
ComPtr<ICredentialProviderFilter> makeFilter(Mode mode = Mode::Disabled, Preconditions conditions = {}) {
    ComPtr<ICredentialProviderFilter> result;
    result.Attach(new ProviderFilter(mode, conditions));
    return result;
}
void selfTest() {
    constexpr Preconditions ready{true, true, true};
    constexpr GUID unknown{0x64b8cb1f,0x6b32,0x458a,{0xb0,0xc3,0x8e,0xc5,0x77,0x66,0x22,0xef}};
    std::array<GUID, 8> ids{};
    ids[0] = CLSID_SovereignAuth;
    for (size_t i = 0; i < convenienceProviders.size(); ++i) ids[i + 1] = convenienceProviders[i].id;
    ids.back() = unknown;
    constexpr DWORD count = static_cast<DWORD>(ids.size());
    std::array<BOOL, 8> allowed{};
    const auto reset = [&] { allowed.fill(TRUE); };
    const auto unchanged = [&] { return std::all_of(allowed.begin(), allowed.end(), [](BOOL value) { return value == TRUE; }); };
    const auto invoke = [&](ICredentialProviderFilter* filter, CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, DWORD flags = 0) {
        check(filter->Filter(scenario, flags, ids.data(), allowed.data(), count) == S_OK, "Filter returns S_OK");
    };
    for (const auto mode : {Mode::Disabled, Mode::Diagnostic, static_cast<Mode>(99)}) {
        reset();
        auto filter = makeFilter(mode, ready);
        invoke(filter.Get(), CPUS_LOGON);
        check(unchanged(), "disabled, diagnostic and invalid modes preserve all decisions");
    }
    for (const auto conditions : {Preconditions{}, Preconditions{false, true, true},
                                  Preconditions{true, false, true}, Preconditions{true, true, false}}) {
        reset();
        auto filter = makeFilter(Mode::SimulateRestriction, conditions);
        invoke(filter.Get(), CPUS_LOGON);
        check(unchanged(), "missing recovery, account or inventory evidence preserves native options");
    }
    auto filter = makeFilter(Mode::SimulateRestriction, ready);
    for (const auto scenario : {CPUS_INVALID, CPUS_CREDUI, CPUS_CHANGE_PASSWORD, CPUS_PLAP,
                               static_cast<CREDENTIAL_PROVIDER_USAGE_SCENARIO>(99)}) {
        reset();
        invoke(filter.Get(), scenario);
        check(unchanged(), "unsupported scenarios preserve native options");
    }
    reset();
    invoke(filter.Get(), CPUS_LOGON, 1);
    check(unchanged(), "unrecognized flags preserve native options");
    for (const auto scenario : {CPUS_LOGON, CPUS_UNLOCK_WORKSTATION}) {
        reset();
        invoke(filter.Get(), scenario);
        check(allowed.front() && allowed.back(), "Sovereign and unknown provider remain available");
        check(std::none_of(allowed.begin() + 1, allowed.end() - 1, [](BOOL value) { return value != FALSE; }),
              "six identified convenience providers are hidden only in the simulated list");
    }
    reset();
    allowed.back() = FALSE;
    invoke(filter.Get(), CPUS_LOGON);
    check(!allowed.back(), "another filter's exclusion is never re-enabled");
    reset();
    allowed.front() = FALSE;
    const auto unavailable = allowed;
    invoke(filter.Get(), CPUS_LOGON);
    check(allowed == unavailable, "unavailable Sovereign leaves native options unchanged");
    reset();
    check(filter->Filter(CPUS_LOGON, 0, ids.data() + 1, allowed.data() + 1, count - 1) == S_OK && unchanged(),
          "absent Sovereign leaves native options unchanged");
    check(filter->Filter(CPUS_LOGON, 0, nullptr, nullptr, 0) == S_OK, "empty provider list is safe");
    check(filter->Filter(CPUS_LOGON, 0, nullptr, allowed.data(), count) == S_OK && unchanged(), "null provider array is passive");
    check(filter->Filter(CPUS_LOGON, 0, ids.data(), nullptr, count) == S_OK, "null decisions array is passive");
    ComPtr<IUnknown> identity;
    check(SUCCEEDED(filter.As(&identity)), "IUnknown is available");
    ComPtr<ICredentialProviderFilter> same;
    check(SUCCEEDED(identity.As(&same)) && same.Get() == filter.Get(), "COM identity round-trip is stable");
    void* unsupported = reinterpret_cast<void*>(1);
    check(filter->QueryInterface(IID_ICredentialProvider, &unsupported) == E_NOINTERFACE && !unsupported,
          "unsupported COM interfaces clear the output");
    check(filter->QueryInterface(IID_IUnknown, nullptr) == E_POINTER, "null interface output is rejected");
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION remote{};
    remote.cbSerialization = 42;
    check(filter->UpdateRemoteCredential(nullptr, &remote) == E_NOTIMPL && remote.cbSerialization == 0 && !remote.rgbSerialization,
          "remote credentials are not handled or forwarded");
    check(filter->UpdateRemoteCredential(nullptr, nullptr) == E_NOTIMPL, "null remote output is safe");
}

void inspect() {
    // Read provider identifiers only. No profiles, accounts, key identifiers,
    // credential bytes or sign-in preference values are collected or changed.
    HKEY key = nullptr;
    const auto opened = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers",
        0, KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &key);
    if (opened != ERROR_SUCCESS) throw std::runtime_error("Cannot enumerate registered credential providers");
    std::wcout << L"Read-only inventory. Registration does not prove a tile is visible or usable.\n";
    DWORD unreviewed = 0;
    LSTATUS result = ERROR_SUCCESS;
    for (DWORD index = 0; ; ++index) {
        wchar_t name[256]{};
        DWORD length = static_cast<DWORD>(std::size(name));
        result = RegEnumKeyExW(key, index, name, &length, nullptr, nullptr, nullptr, nullptr);
        if (result == ERROR_NO_MORE_ITEMS) break;
        if (result != ERROR_SUCCESS) break;
        GUID id{};
        const bool valid = SUCCEEDED(CLSIDFromString(name, &id));
        const auto known = valid ? convenienceName(id) : nullptr;
        std::wcout << name << L" : ";
        if (valid && id == CLSID_SovereignAuth) std::wcout << L"Sovereign; preserve";
        else if (known) std::wcout << known << L"; candidate restriction in isolated tests";
        else { ++unreviewed; std::wcout << L"unreviewed; preserve"; }
        std::wcout << L'\n';
    }
    RegCloseKey(key);
    if (result != ERROR_NO_MORE_ITEMS) throw std::runtime_error("Credential-provider inventory was incomplete");
    std::wcout << L"Unreviewed registrations: " << unreviewed << L". This inventory does not establish key-only enforcement.\n";
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc == 2 && std::wstring(argv[1]) == L"--self-test") selfTest();
        else if (argc == 2 && std::wstring(argv[1]) == L"--inspect") inspect();
        else {
            std::cout << "Usage: swa_filter_lab --self-test | --inspect\n"
                      << "Isolated experiment only. This executable cannot install or activate a filter.\n";
            return 2;
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
