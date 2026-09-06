#include <windows.h>
#include <credentialprovider.h>
#include <atomic>
#include <new>
#include "provider_id.h"

// Fault fixture only: it can load but never returns a credential. It exists to
// test offline recovery from an unusable provider, not to authenticate anyone.
namespace {
std::atomic<LONG> objects{0};
std::atomic<LONG> locks{0};
class Unavailable final : public ICredentialProvider {
    std::atomic<ULONG> references_{1};
public:
    Unavailable() { ++objects; }
    ~Unavailable() { --objects; }
    IFACEMETHODIMP QueryInterface(REFIID iid, void** output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (iid != IID_IUnknown && iid != IID_ICredentialProvider) return E_NOINTERFACE;
        *output = static_cast<ICredentialProvider*>(this);
        AddRef();
        return S_OK;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++references_; }
    IFACEMETHODIMP_(ULONG) Release() override { const auto n = --references_; if (!n) delete this; return n; }
    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, DWORD) override {
        return scenario == CPUS_LOGON || scenario == CPUS_UNLOCK_WORKSTATION ? S_OK : E_NOTIMPL;
    }
    IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*) override { return E_NOTIMPL; }
    IFACEMETHODIMP Advise(ICredentialProviderEvents*, UINT_PTR) override { return S_OK; }
    IFACEMETHODIMP UnAdvise() override { return S_OK; }
    IFACEMETHODIMP GetFieldDescriptorCount(DWORD* count) override { if (!count) return E_POINTER; *count = 0; return S_OK; }
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** output) override {
        if (!output) return E_POINTER; *output = nullptr; return E_INVALIDARG;
    }
    IFACEMETHODIMP GetCredentialCount(DWORD* count, DWORD* selected, BOOL* automatic) override {
        if (!count || !selected || !automatic) return E_POINTER;
        *count = 0; *selected = CREDENTIAL_PROVIDER_NO_DEFAULT; *automatic = FALSE;
        return S_OK;
    }
    IFACEMETHODIMP GetCredentialAt(DWORD, ICredentialProviderCredential** output) override {
        if (!output) return E_POINTER; *output = nullptr; return E_INVALIDARG;
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
        *output = static_cast<IClassFactory*>(this); AddRef(); return S_OK;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++references_; }
    IFACEMETHODIMP_(ULONG) Release() override { const auto n = --references_; if (!n) delete this; return n; }
    IFACEMETHODIMP CreateInstance(IUnknown* outer, REFIID iid, void** output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (outer) return CLASS_E_NOAGGREGATION;
        auto instance = new (std::nothrow) Unavailable;
        if (!instance) return E_OUTOFMEMORY;
        const auto result = instance->QueryInterface(iid, output);
        instance->Release(); return result;
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
    if (clsid != CLSID_SovereignAuth) return CLASS_E_CLASSNOTAVAILABLE;
    auto factory = new (std::nothrow) Factory;
    if (!factory) return E_OUTOFMEMORY;
    const auto result = factory->QueryInterface(iid, output);
    factory->Release(); return result;
}
extern "C" HRESULT __stdcall DllCanUnloadNow() { return objects == 0 && locks == 0 ? S_OK : S_FALSE; }
