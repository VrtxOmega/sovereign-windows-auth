#include "filter_lab.h"
#include "filter_id.h"
#include <new>

namespace {
std::atomic<LONG> objects{0};
std::atomic<LONG> locks{0};
bool isLabVm() noexcept {
    wchar_t manufacturer[128]{};
    DWORD bytes = sizeof(manufacturer);
    return RegGetValueW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS",
        L"SystemManufacturer", RRF_RT_REG_SZ, nullptr, manufacturer, &bytes) == ERROR_SUCCESS &&
        _wcsicmp(manufacturer, L"QEMU") == 0;
}
DWORD configuredMode() noexcept {
    DWORD mode = 0;
    DWORD bytes = sizeof(mode);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, SovereignFilterConfiguration, L"Mode",
        RRF_RT_REG_DWORD, nullptr, &mode, &bytes) != ERROR_SUCCESS) return 0;
    return mode;
}
class VmFilter final : public ICredentialProviderFilter {
    std::atomic<ULONG> references_{1};
public:
    VmFilter() { ++objects; }
    ~VmFilter() { --objects; }
    IFACEMETHODIMP QueryInterface(REFIID iid, void** output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (iid != IID_IUnknown && iid != IID_ICredentialProviderFilter) return E_NOINTERFACE;
        *output = static_cast<ICredentialProviderFilter*>(this);
        AddRef();
        return S_OK;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++references_; }
    IFACEMETHODIMP_(ULONG) Release() override {
        const auto count = --references_;
        if (!count) delete this;
        return count;
    }
    IFACEMETHODIMP Filter(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, DWORD flags,
                         GUID* providers, BOOL* allow, DWORD count) override {
        // This build is deliberately limited to the disposable QEMU guest. No
        // configuration setting can enable it on the physical development PC.
        // Firmware strings are a lab guard, not an authentication boundary.
        if (!isLabVm() || configuredMode() != 2) return S_OK;
        swa::lab::ProviderFilter policy(swa::lab::Mode::SimulateRestriction, {true, true, true});
        const auto result = policy.Filter(scenario, flags, providers, allow, count);
        if (providers && allow && (scenario == CPUS_LOGON || scenario == CPUS_UNLOCK_WORKSTATION)) {
            DWORD excluded = 0;
            DWORD sovereignPresent = 0;
            for (DWORD i = 0; i < count; ++i)
            {
                if (swa::lab::convenienceName(providers[i]) && !allow[i]) ++excluded;
                if (providers[i] == CLSID_SovereignAuth) sovereignPresent = 1;
            }
            HKEY key = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, SovereignFilterConfiguration, 0, KEY_SET_VALUE, &key) == ERROR_SUCCESS) {
                const DWORD process = GetCurrentProcessId();
                RegSetValueExW(key, L"LastDesktopExcludedCount", 0, REG_DWORD,
                    reinterpret_cast<const BYTE*>(&excluded), sizeof(excluded));
                RegSetValueExW(key, L"LastDesktopProcessId", 0, REG_DWORD,
                    reinterpret_cast<const BYTE*>(&process), sizeof(process));
                RegSetValueExW(key, L"LastDesktopFlags", 0, REG_DWORD,
                    reinterpret_cast<const BYTE*>(&flags), sizeof(flags));
                RegSetValueExW(key, L"LastDesktopProviderCount", 0, REG_DWORD,
                    reinterpret_cast<const BYTE*>(&count), sizeof(count));
                RegSetValueExW(key, L"LastDesktopSovereignPresent", 0, REG_DWORD,
                    reinterpret_cast<const BYTE*>(&sovereignPresent), sizeof(sovereignPresent));
                RegCloseKey(key);
            }
        }
        return result;
    }
    IFACEMETHODIMP UpdateRemoteCredential(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*,
                                         CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* output) override {
        if (output) *output = {};
        return E_NOTIMPL;
    }
};
class Factory final : public IClassFactory {
    std::atomic<ULONG> references_{1};
public:
    Factory() { ++objects; }
    ~Factory() { --objects; }
    IFACEMETHODIMP QueryInterface(REFIID iid, void** output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (iid != IID_IUnknown && iid != IID_IClassFactory) return E_NOINTERFACE;
        *output = static_cast<IClassFactory*>(this);
        AddRef();
        return S_OK;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++references_; }
    IFACEMETHODIMP_(ULONG) Release() override {
        const auto count = --references_;
        if (!count) delete this;
        return count;
    }
    IFACEMETHODIMP CreateInstance(IUnknown* outer, REFIID iid, void** output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (outer) return CLASS_E_NOAGGREGATION;
        auto instance = new (std::nothrow) VmFilter;
        if (!instance) return E_OUTOFMEMORY;
        const auto result = instance->QueryInterface(iid, output);
        instance->Release();
        return result;
    }
    IFACEMETHODIMP LockServer(BOOL lock) override {
        if (lock) ++locks;
        else {
            auto count = locks.load();
            while (count > 0 && !locks.compare_exchange_weak(count, count - 1)) {}
            if (count <= 0) return E_UNEXPECTED;
        }
        return S_OK;
    }
};
}
extern "C" HRESULT __stdcall DllGetClassObject(REFCLSID clsid, REFIID iid, void** output) {
    if (!output) return E_POINTER;
    *output = nullptr;
    if (clsid != CLSID_SovereignFilter) return CLASS_E_CLASSNOTAVAILABLE;
    auto factory = new (std::nothrow) Factory;
    if (!factory) return E_OUTOFMEMORY;
    const auto result = factory->QueryInterface(iid, output);
    factory->Release();
    return result;
}
extern "C" HRESULT __stdcall DllCanUnloadNow() {
    return objects == 0 && locks == 0 ? S_OK : S_FALSE;
}
