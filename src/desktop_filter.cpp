#include "desktop_filter_policy.h"
#include "filter_id.h"
#include <new>

namespace {
std::atomic<LONG> objects{0},locks{0};
swa::desktop::Mode configuredMode() noexcept {
    DWORD version=0,mode=0,bytes=sizeof(version);
    if(RegGetValueW(HKEY_LOCAL_MACHINE,swa::desktop::Configuration,L"Version",RRF_RT_REG_DWORD,nullptr,&version,&bytes)!=ERROR_SUCCESS || version!=1)
        return swa::desktop::Mode::Off;
    bytes=sizeof(mode);
    if(RegGetValueW(HKEY_LOCAL_MACHINE,swa::desktop::Configuration,L"Mode",RRF_RT_REG_DWORD,nullptr,&mode,&bytes)!=ERROR_SUCCESS)
        return swa::desktop::Mode::Off;
    return static_cast<swa::desktop::Mode>(mode);
}
class DesktopFilter final : public ICredentialProviderFilter {
    std::atomic<ULONG> references_{1};
public:
    DesktopFilter(){++objects;}
    ~DesktopFilter(){--objects;}
    IFACEMETHODIMP QueryInterface(REFIID iid,void** output) override {
        if(!output)return E_POINTER;*output=nullptr;
        if(iid!=IID_IUnknown && iid!=IID_ICredentialProviderFilter)return E_NOINTERFACE;
        *output=static_cast<ICredentialProviderFilter*>(this);AddRef();return S_OK;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override{return ++references_;}
    IFACEMETHODIMP_(ULONG) Release() override{const auto count=--references_;if(!count)delete this;return count;}
    IFACEMETHODIMP Filter(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario,DWORD flags,GUID* providers,BOOL* allow,DWORD count) override {
        // Local console desktop only. Never affect generic prompts or remote credentials.
        if(GetSystemMetrics(SM_REMOTESESSION))return S_OK;
        const auto mode=configuredMode();
        const auto result=swa::desktop::apply(mode,scenario,flags,providers,allow,count);
        if(result.applicable){
            DWORD sovereignPresent=0;
            for(DWORD i=0;i<count;++i)if(providers[i]==CLSID_SovereignAuth)sovereignPresent=1;
            HKEY key=nullptr;
            if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,swa::desktop::Configuration,0,KEY_SET_VALUE,&key)==ERROR_SUCCESS){
                const DWORD values[]{GetCurrentProcessId(),static_cast<DWORD>(scenario),static_cast<DWORD>(mode),count,result.known,result.excluded,result.other,sovereignPresent,flags};
                const wchar_t* names[]{L"LastProcessId",L"LastScenario",L"LastMode",L"LastProviderCount",L"LastKnownCount",L"LastExcludedCount",L"LastOtherCount",L"LastSovereignPresent",L"LastFlags"};
                for(size_t i=0;i<std::size(values);++i)
                    RegSetValueExW(key,names[i],0,REG_DWORD,reinterpret_cast<const BYTE*>(&values[i]),sizeof(DWORD));
                RegCloseKey(key);
            }
        }
        return S_OK;
    }
    IFACEMETHODIMP UpdateRemoteCredential(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*,CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* output) override {
        if(output)*output={};return E_NOTIMPL;
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
        auto instance = new (std::nothrow) DesktopFilter;
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
