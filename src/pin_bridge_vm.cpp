#include "windows_pin.h"
#include "provider_id.h"
#include "filter_id.h"
#include <credentialprovider.h>
#include <shlwapi.h>
#include <wrl/client.h>
#include <atomic>
#include <optional>
#include <memory>
#include <new>

// Disposable-VM fixture. It requests the generated lab account's PIN directly
// to exercise the production WindowsPin class inside filtered LogonUI. It is
// deliberately not a YubiKey provider and must never be installed on real PCs.
using Microsoft::WRL::ComPtr;
namespace {
std::atomic<LONG> objects{0},locks{0};
enum Field : DWORD { Title,Description,Pin,Submit,FieldCount };
constexpr CREDENTIAL_PROVIDER_FIELD_TYPE Types[]{CPFT_LARGE_TEXT,CPFT_SMALL_TEXT,CPFT_PASSWORD_TEXT,CPFT_SUBMIT_BUTTON};
constexpr const wchar_t* Labels[]{L"PIN bridge lab",L"Disposable VM compatibility test",L"Lab PIN",L"Test sign-in"};
bool labArmed() noexcept {
    wchar_t manufacturer[128]{}; DWORD bytes=sizeof(manufacturer),armed=0,mode=0;
    if(RegGetValueW(HKEY_LOCAL_MACHINE,L"HARDWARE\\DESCRIPTION\\System\\BIOS",L"SystemManufacturer",
        RRF_RT_REG_SZ,nullptr,manufacturer,&bytes)!=ERROR_SUCCESS || _wcsicmp(manufacturer,L"QEMU")!=0) return false;
    bytes=sizeof(armed);
    if(RegGetValueW(HKEY_LOCAL_MACHINE,SovereignFilterConfiguration,L"BridgeArmed",RRF_RT_REG_DWORD,nullptr,&armed,&bytes)!=ERROR_SUCCESS || armed!=1) return false;
    bytes=sizeof(mode);
    if(RegGetValueW(HKEY_LOCAL_MACHINE,SovereignFilterConfiguration,L"Mode",RRF_RT_REG_DWORD,nullptr,&mode,&bytes)!=ERROR_SUCCESS || mode!=2) return false;
    const auto marker=GetFileAttributesW(L"C:\\SwaLab\\lab-installed.marker");
    return marker!=INVALID_FILE_ATTRIBUTES && !(marker&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT));
}
void report(const wchar_t* name,DWORD value) noexcept {
    HKEY key=nullptr;
    if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,SovereignFilterConfiguration,0,KEY_SET_VALUE,&key)==ERROR_SUCCESS) {
        RegSetValueExW(key,name,0,REG_DWORD,reinterpret_cast<const BYTE*>(&value),sizeof(value));
        RegCloseKey(key);
    }
}
HRESULT text(const wchar_t* value,PWSTR* output) {
    if(!output)return E_POINTER;
    *output=nullptr;
    return SHStrDupW(value,output);
}
class Credential final : public ICredentialProviderCredential2 {
    std::atomic<ULONG> refs_{1};
    ComPtr<ICredentialProviderUserArray> users_;
    ComPtr<ICredentialProviderCredentialEvents> events_;
    std::wstring sid_;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario_;
    std::optional<swa::Secret> pin_;
    std::unique_ptr<swa::WindowsPin> bridge_;
public:
    Credential(ICredentialProviderUserArray* users,std::wstring sid,CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario)
        :users_(users),sid_(std::move(sid)),scenario_(scenario) {++objects;}
    ~Credential(){pin_.reset();bridge_.reset();--objects;}
    IFACEMETHODIMP QueryInterface(REFIID iid,void** output) override {
        if(!output)return E_POINTER;*output=nullptr;
        if(iid!=IID_IUnknown && iid!=IID_ICredentialProviderCredential && iid!=IID_ICredentialProviderCredential2)return E_NOINTERFACE;
        *output=static_cast<ICredentialProviderCredential2*>(this);AddRef();return S_OK;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override{return ++refs_;}
    IFACEMETHODIMP_(ULONG) Release() override{const auto count=--refs_;if(!count)delete this;return count;}
    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents* events) override{events_=events;return events?S_OK:E_POINTER;}
    IFACEMETHODIMP UnAdvise() override{SetDeselected();events_.Reset();return S_OK;}
    IFACEMETHODIMP SetSelected(BOOL* automatic) override{if(!automatic)return E_POINTER;*automatic=FALSE;return S_OK;}
    IFACEMETHODIMP SetDeselected() override{pin_.reset();bridge_.reset();return S_OK;}
    IFACEMETHODIMP GetFieldState(DWORD id,CREDENTIAL_PROVIDER_FIELD_STATE* state,CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* interactive) override{
        if(!state||!interactive)return E_POINTER;if(id>=FieldCount)return E_INVALIDARG;
        *state=CPFS_DISPLAY_IN_SELECTED_TILE;*interactive=id==Pin?CPFIS_FOCUSED:CPFIS_NONE;return S_OK;
    }
    IFACEMETHODIMP GetStringValue(DWORD id,PWSTR* value) override{if(id>=FieldCount)return E_INVALIDARG;return text(id==Pin?L"":Labels[id],value);}
    IFACEMETHODIMP GetBitmapValue(DWORD,HBITMAP* value) override{if(value)*value=nullptr;return E_NOTIMPL;}
    IFACEMETHODIMP GetCheckboxValue(DWORD,BOOL*,PWSTR*) override{return E_NOTIMPL;}
    IFACEMETHODIMP GetSubmitButtonValue(DWORD id,DWORD* adjacent) override{if(!adjacent)return E_POINTER;if(id!=Submit)return E_INVALIDARG;*adjacent=Pin;return S_OK;}
    IFACEMETHODIMP GetComboBoxValueCount(DWORD,DWORD*,DWORD*) override{return E_NOTIMPL;}
    IFACEMETHODIMP GetComboBoxValueAt(DWORD,DWORD,PWSTR*) override{return E_NOTIMPL;}
    IFACEMETHODIMP SetStringValue(DWORD id,PCWSTR value) override{
        if(id!=Pin||!value)return E_INVALIDARG;
        pin_.reset();
        const auto length=wcsnlen_s(value,257);
        if(length>256)return E_INVALIDARG;
        if(!length)return S_OK;
        for(size_t i=0;i<length;++i)if(value[i]<L'0'||value[i]>L'9')return E_INVALIDARG;
        try{pin_.emplace((length+1)*sizeof(wchar_t));memcpy(pin_->data(),value,(length+1)*sizeof(wchar_t));return S_OK;}
        catch(...){return E_OUTOFMEMORY;}
    }
    IFACEMETHODIMP SetCheckboxValue(DWORD,BOOL) override{return E_NOTIMPL;}
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD,DWORD) override{return E_NOTIMPL;}
    IFACEMETHODIMP CommandLinkClicked(DWORD) override{return E_NOTIMPL;}
    IFACEMETHODIMP GetUserSid(PWSTR* sid) override{return text(sid_.c_str(),sid);}
    IFACEMETHODIMP GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialized,PWSTR* status,CREDENTIAL_PROVIDER_STATUS_ICON* icon) override{
        if(!response||!serialized||!status||!icon)return E_POINTER;
        *response=CPGSR_NO_CREDENTIAL_NOT_FINISHED;*serialized={};*status=nullptr;*icon=CPSI_NONE;
        if(!labArmed()||!pin_)return E_ACCESSDENIED;
        try{
            // Exactly the production bridge; no duplicate PIN serialization code.
            bridge_=std::make_unique<swa::WindowsPin>(users_.Get(),sid_,scenario_);
            auto auth=bridge_->serialize(reinterpret_cast<PCWSTR>(pin_->data()));
            pin_.reset();
            auto buffer=static_cast<BYTE*>(CoTaskMemAlloc(auth.buffer.size()));
            if(!buffer)return E_OUTOFMEMORY;
            memcpy(buffer,auth.buffer.data(),auth.buffer.size());
            serialized->ulAuthenticationPackage=auth.package;serialized->clsidCredentialProvider=CLSID_SovereignAuth;
            serialized->cbSerialization=static_cast<DWORD>(auth.buffer.size());serialized->rgbSerialization=buffer;
            *response=CPGSR_RETURN_CREDENTIAL_FINISHED;
            report(L"BridgeProduced",1);report(L"BridgeProcessId",GetCurrentProcessId());
            return S_OK;
        }catch(const std::exception& error){
            pin_.reset();bridge_.reset();*icon=CPSI_ERROR;report(L"BridgeProduced",0);
            // The shared WindowsPin class's exception text contains fixed stages
            // and status codes only. Do not include PIN/serialization material.
            const std::string message=error.what();
            const std::wstring wide(message.begin(),message.end());
            return text(wide.c_str(),status);
        }catch(...){pin_.reset();bridge_.reset();return E_FAIL;}
    }
    IFACEMETHODIMP ReportResult(NTSTATUS status,NTSTATUS substatus,PWSTR* message,CREDENTIAL_PROVIDER_STATUS_ICON* icon) override{
        if(!message||!icon)return E_POINTER;*message=nullptr;*icon=CPSI_NONE;
        report(L"BridgeStatus",static_cast<DWORD>(status));report(L"BridgeSubstatus",static_cast<DWORD>(substatus));
        SetDeselected();
        if(status<0){*icon=CPSI_ERROR;return text(L"The lab PIN was rejected. No automatic retry.",message);}return S_OK;
    }
};
class Provider final : public ICredentialProvider,public ICredentialProviderSetUserArray {
    std::atomic<ULONG> refs_{1};
    ComPtr<ICredentialProviderUserArray> users_;
    ComPtr<Credential> credential_;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario_=CPUS_INVALID;
public:
    Provider(){++objects;}
    ~Provider(){credential_.Reset();--objects;}
    IFACEMETHODIMP QueryInterface(REFIID iid,void** output) override{
        if(!output)return E_POINTER;*output=nullptr;
        if(iid==IID_IUnknown||iid==IID_ICredentialProvider)*output=static_cast<ICredentialProvider*>(this);
        else if(iid==IID_ICredentialProviderSetUserArray)*output=static_cast<ICredentialProviderSetUserArray*>(this);
        else return E_NOINTERFACE;AddRef();return S_OK;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override{return ++refs_;}
    IFACEMETHODIMP_(ULONG) Release() override{const auto count=--refs_;if(!count)delete this;return count;}
    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario,DWORD flags) override{
        credential_.Reset();scenario_=CPUS_INVALID;
        if(!labArmed()||flags||GetSystemMetrics(SM_REMOTESESSION)||(scenario!=CPUS_LOGON&&scenario!=CPUS_UNLOCK_WORKSTATION))return E_NOTIMPL;
        scenario_=scenario;return S_OK;
    }
    IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*) override{return E_NOTIMPL;}
    IFACEMETHODIMP Advise(ICredentialProviderEvents*,UINT_PTR) override{return S_OK;}
    IFACEMETHODIMP UnAdvise() override{credential_.Reset();return S_OK;}
    IFACEMETHODIMP SetUserArray(ICredentialProviderUserArray* users) override{credential_.Reset();users_=users;return users?S_OK:E_POINTER;}
    IFACEMETHODIMP GetFieldDescriptorCount(DWORD* count) override{if(!count)return E_POINTER;*count=FieldCount;return S_OK;}
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD index,CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** descriptor) override{
        if(!descriptor)return E_POINTER;*descriptor=nullptr;if(index>=FieldCount)return E_INVALIDARG;
        auto value=static_cast<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*>(CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR)));
        if(!value)return E_OUTOFMEMORY;*value={};value->dwFieldID=index;value->cpft=Types[index];
        const auto result=text(Labels[index],&value->pszLabel);if(FAILED(result)){CoTaskMemFree(value);return result;}*descriptor=value;return S_OK;
    }
    IFACEMETHODIMP GetCredentialCount(DWORD* count,DWORD* selected,BOOL* automatic) override{
        if(!count||!selected||!automatic)return E_POINTER;*count=0;*selected=CREDENTIAL_PROVIDER_NO_DEFAULT;*automatic=FALSE;
        if(!labArmed()||scenario_==CPUS_INVALID||!users_)return S_OK;
        try{
            if(!credential_){
                wchar_t expected[256]{};DWORD bytes=sizeof(expected);
                if(RegGetValueW(HKEY_LOCAL_MACHINE,SovereignFilterConfiguration,L"BridgeSid",RRF_RT_REG_SZ,nullptr,expected,&bytes)!=ERROR_SUCCESS||!expected[0])return E_ACCESSDENIED;
                DWORD total=0;if(FAILED(users_->GetCount(&total))||total>256)return E_FAIL;
                for(DWORD i=0;i<total;++i){
                    ComPtr<ICredentialProviderUser> user;if(FAILED(users_->GetAt(i,&user)))continue;
                    PWSTR sid=nullptr;const auto result=user->GetSid(&sid);
                    const bool matches=SUCCEEDED(result)&&sid&&wcscmp(expected,sid)==0;CoTaskMemFree(sid);
                    if(matches){if(credential_){credential_.Reset();return E_UNEXPECTED;}credential_.Attach(new Credential(users_.Get(),expected,scenario_));}
                }
            }
            if(credential_){*count=1;*selected=0;}return S_OK;
        }catch(...){credential_.Reset();return E_FAIL;}
    }
    IFACEMETHODIMP GetCredentialAt(DWORD index,ICredentialProviderCredential** credential) override{
        if(!credential)return E_POINTER;*credential=nullptr;if(index||!credential_)return E_INVALIDARG;
        return credential_->QueryInterface(IID_PPV_ARGS(credential));
    }
};
class Factory final : public IClassFactory {
    std::atomic<ULONG> refs_{1};
public:
    Factory(){++objects;}~Factory(){--objects;}
    IFACEMETHODIMP QueryInterface(REFIID iid,void** output) override{if(!output)return E_POINTER;*output=nullptr;if(iid!=IID_IUnknown&&iid!=IID_IClassFactory)return E_NOINTERFACE;*output=static_cast<IClassFactory*>(this);AddRef();return S_OK;}
    IFACEMETHODIMP_(ULONG) AddRef() override{return ++refs_;}
    IFACEMETHODIMP_(ULONG) Release() override{const auto count=--refs_;if(!count)delete this;return count;}
    IFACEMETHODIMP CreateInstance(IUnknown* outer,REFIID iid,void** output) override{
        if(!output)return E_POINTER;*output=nullptr;if(outer)return CLASS_E_NOAGGREGATION;
        auto provider=new(std::nothrow) Provider;if(!provider)return E_OUTOFMEMORY;
        const auto result=provider->QueryInterface(iid,output);provider->Release();return result;
    }
    IFACEMETHODIMP LockServer(BOOL lock) override{
        if(lock)++locks;else{auto count=locks.load();while(count>0&&!locks.compare_exchange_weak(count,count-1)){}if(count<=0)return E_UNEXPECTED;}return S_OK;
    }
};
}
extern "C" HRESULT __stdcall DllGetClassObject(REFCLSID clsid,REFIID iid,void** output){
    if(!output)return E_POINTER;*output=nullptr;if(clsid!=CLSID_SovereignAuth)return CLASS_E_CLASSNOTAVAILABLE;
    auto factory=new(std::nothrow) Factory;if(!factory)return E_OUTOFMEMORY;
    const auto result=factory->QueryInterface(iid,output);factory->Release();return result;
}
extern "C" HRESULT __stdcall DllCanUnloadNow(){return objects==0&&locks==0?S_OK:S_FALSE;}
