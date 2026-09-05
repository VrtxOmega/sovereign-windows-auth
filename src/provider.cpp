#include "core.h"
#include "windows_auth.h"
#include "windows_pin.h"
#include "provider_id.h"
#include <credentialprovider.h>
#include <propkey.h>
#include <shlwapi.h>
#include <shlguid.h>
#include <shlobj.h>
#include <wincred.h>
#include <ntsecapi.h>
#include <wrl/client.h>
#include <delayimp.h>
#include <atomic>
#include <chrono>
#include <mutex>
#include <optional>
#include <thread>
#include <cstdio>

using Microsoft::WRL::ComPtr;
namespace {
HMODULE moduleHandle=nullptr;
std::atomic<long> liveObjects=0;
std::atomic<long> serverLocks=0;
constexpr DWORD FieldCount=5;
enum Field : DWORD { Title=0, Status=1, Submit=2, Logo=3, ProviderLabel=4 };
const wchar_t* Labels[FieldCount]={L"Sovereign key",L"Touch your key to sign in",L"Sign in",L"Sovereign key icon",L"Sovereign key"};
const CREDENTIAL_PROVIDER_FIELD_TYPE Types[FieldCount]={CPFT_LARGE_TEXT,CPFT_SMALL_TEXT,CPFT_SUBMIT_BUTTON,CPFT_TILE_IMAGE,CPFT_SMALL_TEXT};
void trace(const char* stage,LONG value=0,LONG detail=0) noexcept {
    DWORD enabled=0,size=sizeof(enabled);
    if (RegGetValueW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\SovereignWindowsAuth",L"DiagnosticsEnabled",RRF_RT_REG_DWORD,nullptr,&enabled,&size)!=ERROR_SUCCESS || enabled!=1) return;
    wchar_t directory[MAX_PATH]{};
    if (FAILED(SHGetFolderPathW(nullptr,CSIDL_COMMON_APPDATA,nullptr,SHGFP_TYPE_CURRENT,directory))) return;
    if (wcscat_s(directory,L"\\SovereignWindowsAuth\\provider-trace.log")!=0) return;
    HANDLE file=CreateFileW(directory,FILE_APPEND_DATA|FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    if (file==INVALID_HANDLE_VALUE) return;
    BY_HANDLE_FILE_INFORMATION information{};
    if (!GetFileInformationByHandle(file,&information) || (information.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT) || information.nFileSizeHigh || information.nFileSizeLow>1048576) { CloseHandle(file); return; }
    SYSTEMTIME now{}; GetSystemTime(&now);
    char line[256]{};
    const int length=sprintf_s(line,"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ pid=%lu tid=%lu %s value=%ld detail=%ld\r\n",now.wYear,now.wMonth,now.wDay,now.wHour,now.wMinute,now.wSecond,now.wMilliseconds,GetCurrentProcessId(),GetCurrentThreadId(),stage,value,detail);
    if (length>0) { DWORD written=0; WriteFile(file,line,static_cast<DWORD>(length),&written,nullptr); }
    CloseHandle(file);
}
HRESULT keyLogo(HBITMAP* bitmap) {
    if (!bitmap) return E_POINTER;
    *bitmap=nullptr;
    BITMAPINFO info{};
    info.bmiHeader.biSize=sizeof(BITMAPINFOHEADER); info.bmiHeader.biWidth=64;
    info.bmiHeader.biHeight=-64; info.bmiHeader.biPlanes=1; info.bmiHeader.biBitCount=32; info.bmiHeader.biCompression=BI_RGB;
    void* pixels=nullptr;
    auto image=CreateDIBSection(nullptr,&info,DIB_RGB_COLORS,&pixels,nullptr,0);
    if (!image || !pixels) return E_OUTOFMEMORY;
    auto data=static_cast<DWORD*>(pixels);
    for (int y=0;y<64;++y) for (int x=0;x<64;++x) {
        const int radius=(x-18)*(x-18)+(y-26)*(y-26);
        const bool ring=radius<=144 && radius>=25;
        const bool shaft=x>=27 && x<=54 && y>=22 && y<=29;
        const bool teeth=((x>=39 && x<=44 && y>=29 && y<=39) || (x>=49 && x<=54 && y>=29 && y<=36));
        data[y*64+x]=(ring || shaft || teeth) ? 0xffffffffu : 0u;
    }
    *bitmap=image; return S_OK;
}
HRESULT textCopy(const wchar_t* value,PWSTR* out) {
    if (!out) return E_POINTER;
    *out=nullptr; return SHStrDupW(value,out);
}

class Credential final : public ICredentialProviderCredential2 {
    std::atomic<ULONG> references_{1};
    swa::AccountProfile profile_;
    ComPtr<ICredentialProviderUserArray> users_;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario_;
    std::shared_ptr<swa::WindowsPin> pinBridge_;
    ComPtr<ICredentialProviderEvents> providerEvents_;
    UINT_PTR eventContext_=0;
    std::mutex mutex_;
    std::optional<swa::Secret> readyPassword_;
    ULONGLONG readyAt_=0;
    uint64_t generation_=0;
    bool working_=false;
    const wchar_t* status_=L"Select Sign in, then touch your key.";

    HRESULT begin() {
        std::unique_lock lock(mutex_);
        if (working_) return S_FALSE;
        readyPassword_.reset();
        if (!providerEvents_) return E_UNEXPECTED;
        // A detached worker can execute its epilogue after its last COM Release.
        // Keep this module resident for the lifetime of this LogonUI process.
        HMODULE pinned=nullptr;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,
            reinterpret_cast<PCWSTR>(&moduleHandle),&pinned)) return HRESULT_FROM_WIN32(GetLastError());
        IStream* marshaled=nullptr;
        HRESULT hr=CoMarshalInterThreadInterfaceInStream(IID_ICredentialProviderEvents,providerEvents_.Get(),&marshaled);
        if (FAILED(hr)) return hr;
        const uint64_t attempt=++generation_;
        working_=true;
        status_=L"Touch your key. This request expires after 15 seconds.";
        AddRef();
        try {
            std::thread([this,marshaled,attempt,context=eventContext_] {
                const HRESULT initialized=CoInitializeEx(nullptr,COINIT_MULTITHREADED);
                ComPtr<ICredentialProviderEvents> notify;
                HRESULT unmarshal=E_FAIL;
                if (SUCCEEDED(initialized)) {
                    unmarshal=CoGetInterfaceAndReleaseStream(marshaled,IID_PPV_ARGS(&notify));
                } else {
                    // No COM calls or authentication if a worker cannot initialize.
                    marshaled->Release();
                }
                std::optional<swa::Secret> password;
                if (SUCCEEDED(unmarshal)) {
                    try {
                        password.emplace(swa::unlockAccount(profile_,15000));
                        const auto n=password->size();
                        if (n<4 || n>8192 || n%sizeof(wchar_t)!=0)
                            throw std::runtime_error("Invalid credential size");
                        auto value=reinterpret_cast<const wchar_t*>(password->data());
                        if (wcsnlen_s(value,n/sizeof(wchar_t))!=n/sizeof(wchar_t)-1)
                            throw std::runtime_error("Invalid credential encoding");
                    } catch (const std::exception& error) {
                        // The FIDO/core exceptions contain fixed protocol errors,
                        // never the decrypted credential or cryptographic material.
                        trace("KeyProofError"); trace(error.what()); password.reset();
                    } catch (...) { password.reset(); }
                }
                {
                    std::lock_guard finish(mutex_);
                    working_=false;
                    if (attempt==generation_ && password) {
                        readyPassword_=std::move(password);
                        readyAt_=GetTickCount64();
                        status_=L"Key verified. Signing in...";
                        trace("KeyProofReady");
                    } else if (attempt==generation_) {
                        status_=L"The key could not authenticate. Select Sign in to retry.";
                        trace("KeyProofFailed");
                    } else {
                        trace("KeyProofCanceled");
                    }
                }
                if (notify) notify->CredentialsChanged(context);
                notify.Reset();
                if (SUCCEEDED(initialized)) CoUninitialize();
                Release();
            }).detach();
        } catch (...) {
            working_=false; status_=L"Could not start authentication.";
            marshaled->Release(); Release(); return E_OUTOFMEMORY;
        }
        return S_OK;
    }
public:
    Credential(swa::AccountProfile profile,ICredentialProviderEvents* events,UINT_PTR context,
        ICredentialProviderUserArray* users,CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario)
        : profile_(std::move(profile)),users_(users),scenario_(scenario),providerEvents_(events),eventContext_(context) { ++liveObjects; }
    ~Credential() { --liveObjects; }
    void setProviderEvents(ICredentialProviderEvents* events,UINT_PTR context) {
        std::lock_guard lock(mutex_);
        providerEvents_=events; eventContext_=context;
    }
    bool ready() {
        std::lock_guard lock(mutex_);
        if (readyPassword_ && GetTickCount64()-readyAt_>30000) readyPassword_.reset();
        return readyPassword_.has_value();
    }
    IFACEMETHODIMP QueryInterface(REFIID iid,void** out) override {
        if (!out) return E_POINTER;
        *out=nullptr;
        if (iid==IID_IUnknown || iid==IID_ICredentialProviderCredential || iid==IID_ICredentialProviderCredential2)
            *out=static_cast<ICredentialProviderCredential2*>(this);
        else return E_NOINTERFACE;
        AddRef(); return S_OK;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++references_; }
    IFACEMETHODIMP_(ULONG) Release() override { auto n=--references_; if (!n) delete this; return n; }
    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents*) override { trace("CredentialAdvise"); return S_OK; }
    IFACEMETHODIMP UnAdvise() override {
        trace("CredentialUnAdvise");
        // LogonUI detaches and reattaches credential UI events when handling
        // CredentialsChanged, before querying the completed proof. This is not
        // a user deselection. No credential-level event pointer is retained here.
        // SetDeselected, provider teardown and expiry still invalidate the proof.
        return S_OK;
    }
    IFACEMETHODIMP SetSelected(BOOL* automatic) override {
        if (!automatic) return E_POINTER;
        *automatic=ready() ? TRUE : FALSE;
        trace("SetSelected",*automatic);
        return S_OK;
    }
    IFACEMETHODIMP SetDeselected() override {
        std::lock_guard lock(mutex_);
        trace("SetDeselected",readyPassword_ ? 1 : 0,working_ ? 1 : 0);
        ++generation_; readyPassword_.reset(); pinBridge_.reset();
        status_=working_ ? L"Authentication canceled; waiting for the key request to finish." : L"Select Sign in, then touch your key.";
        return S_OK;
    }
    IFACEMETHODIMP GetFieldState(DWORD field,CREDENTIAL_PROVIDER_FIELD_STATE* state,CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* interactive) override {
        if (!state || !interactive) return E_POINTER;
        if (field>=FieldCount) return E_INVALIDARG;
        *state=field==ProviderLabel ? CPFS_HIDDEN : (field==Title || field==Logo ? CPFS_DISPLAY_IN_BOTH : CPFS_DISPLAY_IN_SELECTED_TILE);
        *interactive=CPFIS_NONE; return S_OK;
    }
    IFACEMETHODIMP GetStringValue(DWORD field,PWSTR* value) override {
        if (field>=FieldCount) return E_INVALIDARG;
        std::lock_guard lock(mutex_);
        return textCopy(field==Status ? status_ : Labels[field],value);
    }
    IFACEMETHODIMP GetBitmapValue(DWORD field,HBITMAP* bitmap) override {
        trace("GetBitmapValue",field);
        if (!bitmap) return E_POINTER;
        *bitmap=nullptr;
        return field==Logo ? keyLogo(bitmap) : E_INVALIDARG;
    }
    IFACEMETHODIMP GetCheckboxValue(DWORD,BOOL*,PWSTR*) override { return E_NOTIMPL; }
    IFACEMETHODIMP GetComboBoxValueCount(DWORD,DWORD*,DWORD*) override { return E_NOTIMPL; }
    IFACEMETHODIMP GetComboBoxValueAt(DWORD,DWORD,PWSTR*) override { return E_NOTIMPL; }
    IFACEMETHODIMP GetSubmitButtonValue(DWORD field,DWORD* adjacent) override {
        if (!adjacent) return E_POINTER;
        if (field!=Submit) return E_INVALIDARG;
        *adjacent=Status; return S_OK;
    }
    IFACEMETHODIMP SetStringValue(DWORD,PCWSTR) override { return E_NOTIMPL; }
    IFACEMETHODIMP SetCheckboxValue(DWORD,BOOL) override { return E_NOTIMPL; }
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD,DWORD) override { return E_NOTIMPL; }
    IFACEMETHODIMP CommandLinkClicked(DWORD) override { return E_NOTIMPL; }
    IFACEMETHODIMP GetUserSid(PWSTR* sid) override { return textCopy(profile_.sid.c_str(),sid); }
    IFACEMETHODIMP GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialized,PWSTR* status,CREDENTIAL_PROVIDER_STATUS_ICON* icon) override {
        trace("GetSerialization");
        if (!response || !serialized || !status || !icon) return E_POINTER;
        *response=CPGSR_NO_CREDENTIAL_NOT_FINISHED; *serialized={}; *status=nullptr; *icon=CPSI_NONE;
        try {
            std::optional<swa::Secret> password;
            uint64_t attempt=0;
            {
                std::lock_guard lock(mutex_);
                attempt=generation_;
                if (readyPassword_ && GetTickCount64()-readyAt_<=30000) password=std::move(readyPassword_);
                readyPassword_.reset();
            }
            if (!password) {
                HRESULT started=begin();
                textCopy(SUCCEEDED(started) ? L"Touch your key to sign in." : L"Key authentication could not start.",status);
                *icon=SUCCEEDED(started) ? CPSI_NONE : CPSI_ERROR;
                return S_OK;
            }
            std::shared_ptr<swa::WindowsPin> pinBridge;
            if (profile_.kind==swa::CredentialKind::WindowsPin)
                pinBridge=std::make_shared<swa::WindowsPin>(users_.Get(),profile_.sid,scenario_);
            auto auth=pinBridge ? pinBridge->serialize(reinterpret_cast<PCWSTR>(password->data())) :
                swa::WindowsCredentialBuffer{swa::windowsAuthenticationPackage(),swa::packWindowsCredential(profile_.account,reinterpret_cast<PCWSTR>(password->data()))};
            password.reset();
            std::lock_guard completion(mutex_);
            if (generation_!=attempt) return S_OK;
            pinBridge_=std::move(pinBridge);
            const DWORD size=static_cast<DWORD>(auth.buffer.size());
            auto buffer=static_cast<BYTE*>(CoTaskMemAlloc(size));
            if (!buffer) return E_OUTOFMEMORY;
            memcpy(buffer,auth.buffer.data(),size);
            serialized->ulAuthenticationPackage=auth.package;
            serialized->clsidCredentialProvider=CLSID_SovereignAuth;
            serialized->cbSerialization=size; serialized->rgbSerialization=buffer;
            *response=CPGSR_RETURN_CREDENTIAL_FINISHED;
            trace("CredentialProduced");
            return S_OK;
        } catch (const std::exception& error) {
            // WindowsPin/packing errors contain only fixed stages and status codes.
            trace("SerializationFailed"); trace(error.what()); *icon=CPSI_ERROR; return E_FAIL;
        } catch (...) { trace("SerializationFailed"); *icon=CPSI_ERROR; return E_FAIL; }
    }
    IFACEMETHODIMP ReportResult(NTSTATUS status,NTSTATUS substatus,PWSTR* text,CREDENTIAL_PROVIDER_STATUS_ICON* icon) override {
        trace("ReportResult",status,substatus);
        if (!text || !icon) return E_POINTER;
        *text=nullptr; *icon=CPSI_NONE; SetDeselected();
        if (status<0) { *icon=CPSI_ERROR; return textCopy(L"Windows rejected the enrolled credential. Use your usual Windows sign-in. If your PIN changed, re-enroll the keys.",text); }
        return S_OK;
    }
};

class Provider final : public ICredentialProvider,public ICredentialProviderSetUserArray {
    std::atomic<ULONG> references_{1};
    ComPtr<ICredentialProviderEvents> events_;
    ComPtr<ICredentialProviderUserArray> users_;
    UINT_PTR context_=0;
    std::vector<ComPtr<Credential>> credentials_;
    bool enumerated_=false;
    bool supported_=false;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario_=CPUS_INVALID;
    void enumerate() {
        if (enumerated_ || !supported_ || !users_) return;
        enumerated_=true;
        DWORD count=0;
        const auto counted=users_->GetCount(&count);
        trace("UserCount",counted,count);
        if (FAILED(counted) || count>256) return;
        for (DWORD i=0;i<count;++i) {
            ComPtr<ICredentialProviderUser> user;
            if (FAILED(users_->GetAt(i,&user))) continue;
            PWSTR rawSid=nullptr;
            if (FAILED(user->GetSid(&rawSid)) || !rawSid) continue;
            std::wstring sid;
            try { sid=rawSid; } catch (...) { CoTaskMemFree(rawSid); throw; }
            CoTaskMemFree(rawSid);
            try {
                auto profile=swa::loadProfile(sid);
                ComPtr<Credential> credential;
                credential.Attach(new Credential(std::move(profile),events_.Get(),context_,users_.Get(),scenario_));
                credentials_.push_back(std::move(credential));
                trace("ProfileLoaded");
            } catch (...) { trace("ProfileUnavailable"); /* No credential for a missing/damaged profile. */ }
        }
    }
public:
    Provider() { ++liveObjects; trace("ProviderCreated"); }
    ~Provider() { credentials_.clear(); --liveObjects; }
    IFACEMETHODIMP QueryInterface(REFIID iid,void** out) override {
        if (!out) return E_POINTER;
        *out=nullptr;
        if (iid==IID_IUnknown || iid==IID_ICredentialProvider) *out=static_cast<ICredentialProvider*>(this);
        else if (iid==IID_ICredentialProviderSetUserArray) *out=static_cast<ICredentialProviderSetUserArray*>(this);
        else return E_NOINTERFACE;
        AddRef(); return S_OK;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++references_; }
    IFACEMETHODIMP_(ULONG) Release() override { auto n=--references_; if (!n) delete this; return n; }
    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario,DWORD) override {
        trace("SetUsageScenario",scenario,GetSystemMetrics(SM_REMOTESESSION));
        for (auto& credential:credentials_) credential->SetDeselected();
        credentials_.clear(); enumerated_=false;
        supported_=(scenario==CPUS_LOGON || scenario==CPUS_UNLOCK_WORKSTATION) && !GetSystemMetrics(SM_REMOTESESSION);
        scenario_=scenario;
        return supported_ ? S_OK : E_NOTIMPL;
    }
    IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*) override { return E_NOTIMPL; }
    IFACEMETHODIMP Advise(ICredentialProviderEvents* events,UINT_PTR context) override {
        trace("Advise");
        if (!events) return E_POINTER;
        events_=events; context_=context;
        for (auto& credential:credentials_) credential->setProviderEvents(events,context);
        return S_OK;
    }
    IFACEMETHODIMP UnAdvise() override {
        trace("ProviderUnAdvise");
        for (auto& credential:credentials_) credential->SetDeselected();
        credentials_.clear(); events_.Reset(); enumerated_=false; return S_OK;
    }
    IFACEMETHODIMP SetUserArray(ICredentialProviderUserArray* users) override {
        trace("SetUserArray");
        if (!users) return E_POINTER;
        for (auto& credential:credentials_) credential->SetDeselected();
        credentials_.clear(); users_=users; enumerated_=false; return S_OK;
    }
    IFACEMETHODIMP GetFieldDescriptorCount(DWORD* count) override {
        if (!count) return E_POINTER;
        *count=FieldCount; return S_OK;
    }
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD index,CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** descriptor) override {
        if (!descriptor) return E_POINTER;
        *descriptor=nullptr;
        if (index>=FieldCount) return E_INVALIDARG;
        auto result=static_cast<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*>(CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR)));
        if (!result) return E_OUTOFMEMORY;
        *result={}; result->dwFieldID=index; result->cpft=Types[index];
        if (index==Logo) result->guidFieldType=CPFG_CREDENTIAL_PROVIDER_LOGO;
        if (index==ProviderLabel) result->guidFieldType=CPFG_CREDENTIAL_PROVIDER_LABEL;
        HRESULT hr=SHStrDupW(Labels[index],&result->pszLabel);
        if (FAILED(hr)) { CoTaskMemFree(result); return hr; }
        *descriptor=result; return S_OK;
    }
    IFACEMETHODIMP GetCredentialCount(DWORD* count,DWORD* selected,BOOL* automatic) override {
        if (!count || !selected || !automatic) return E_POINTER;
        *count=0; *selected=CREDENTIAL_PROVIDER_NO_DEFAULT; *automatic=FALSE;
        try {
            enumerate();
            *count=static_cast<DWORD>(credentials_.size());
            if (*count==1) *selected=0;
            for (DWORD i=0;i<*count;++i) if (credentials_[i]->ready()) { *selected=i; *automatic=TRUE; break; }
            trace("GetCredentialCount",*count,*automatic);
            return S_OK;
        } catch (...) { return E_FAIL; }
    }
    IFACEMETHODIMP GetCredentialAt(DWORD index,ICredentialProviderCredential** credential) override {
        if (!credential) return E_POINTER;
        *credential=nullptr;
        if (index>=credentials_.size()) return E_INVALIDARG;
        return credentials_[index]->QueryInterface(IID_PPV_ARGS(credential));
    }
};
class Factory final : public IClassFactory {
    std::atomic<ULONG> references_{1};
public:
    Factory() { ++liveObjects; }
    ~Factory() { --liveObjects; }
    IFACEMETHODIMP QueryInterface(REFIID iid,void** out) override {
        if (!out) return E_POINTER;
        *out=nullptr;
        if (iid!=IID_IUnknown && iid!=IID_IClassFactory) return E_NOINTERFACE;
        *out=static_cast<IClassFactory*>(this); AddRef(); return S_OK;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++references_; }
    IFACEMETHODIMP_(ULONG) Release() override { auto n=--references_; if (!n) delete this; return n; }
    IFACEMETHODIMP CreateInstance(IUnknown* outer,REFIID iid,void** out) override {
        if (!out) return E_POINTER;
        *out=nullptr;
        if (outer) return CLASS_E_NOAGGREGATION;
        try { auto provider=new Provider(); auto hr=provider->QueryInterface(iid,out); provider->Release(); return hr; }
        catch (...) { return E_OUTOFMEMORY; }
    }
    IFACEMETHODIMP LockServer(BOOL lock) override { if (lock) ++serverLocks; else --serverLocks; return S_OK; }
};
FARPROC WINAPI delayLoad(unsigned notification,PDelayLoadInfo info) {
    if (notification!=dliNotePreLoadLibrary || strcmp(info->szDll,"fido2.dll")!=0) return nullptr;
    wchar_t path[32768]{};
    DWORD length=GetModuleFileNameW(moduleHandle,path,static_cast<DWORD>(std::size(path)));
    if (!length || length>=std::size(path)) throw std::runtime_error("Cannot locate provider module");
    auto slash=wcsrchr(path,L'\\');
    if (!slash) throw std::runtime_error("Provider module path is not absolute");
    if (wcscpy_s(slash+1,std::size(path)-static_cast<size_t>(slash+1-path),L"fido2.dll")!=0)
        throw std::runtime_error("FIDO library path is too long");
    auto library=LoadLibraryExW(path,nullptr,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!library) throw std::runtime_error("Cannot load the FIDO library from the provider directory");
    return reinterpret_cast<FARPROC>(library);
}
}
extern "C" const PfnDliHook __pfnDliNotifyHook2=delayLoad;
extern "C" HRESULT __stdcall DllGetClassObject(REFCLSID clsid,REFIID iid,void** out) {
    trace("DllGetClassObject");
    if (!out) return E_POINTER;
    *out=nullptr;
    if (clsid!=CLSID_SovereignAuth) return CLASS_E_CLASSNOTAVAILABLE;
    try { auto factory=new Factory(); auto hr=factory->QueryInterface(iid,out); factory->Release(); return hr; }
    catch (...) { return E_OUTOFMEMORY; }
}
extern "C" HRESULT __stdcall DllCanUnloadNow() { return liveObjects==0 && serverLocks==0 ? S_OK : S_FALSE; }
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,LPVOID) {
    if (reason==DLL_PROCESS_ATTACH) { moduleHandle=instance; DisableThreadLibraryCalls(instance); }
    return TRUE;
}
