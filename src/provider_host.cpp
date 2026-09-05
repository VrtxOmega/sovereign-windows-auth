#include "core.h"
#include "windows_auth.h"
#include "current_user.h"
#include "provider_id.h"
#include <credentialprovider.h>
#include <shlwapi.h>
#include <shlguid.h>
#include <wincred.h>
#include <wrl/client.h>
#include <atomic>
#include <iostream>

using Microsoft::WRL::ComPtr;
namespace {
void check(bool condition,const char* message) {
    if (!condition) throw std::runtime_error(message);
    std::cout << "PASS " << message << std::endl;
}
class User final : public ICredentialProviderUser {
    std::atomic<ULONG> references_{1};
    std::wstring sid_;
public:
    explicit User(std::wstring sid):sid_(std::move(sid)) {}
    IFACEMETHODIMP QueryInterface(REFIID iid,void** out) override {
        if (!out) return E_POINTER; *out=nullptr;
        if (iid!=IID_IUnknown && iid!=IID_ICredentialProviderUser) return E_NOINTERFACE;
        *out=static_cast<ICredentialProviderUser*>(this); AddRef(); return S_OK;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++references_; }
    IFACEMETHODIMP_(ULONG) Release() override { auto n=--references_; if (!n) delete this; return n; }
    IFACEMETHODIMP GetSid(PWSTR* sid) override { return SHStrDupW(sid_.c_str(),sid); }
    IFACEMETHODIMP GetProviderID(GUID* provider) override { if (!provider) return E_POINTER; *provider={}; return S_OK; }
    IFACEMETHODIMP GetStringValue(REFPROPERTYKEY,PWSTR* value) override { if (value) *value=nullptr; return E_NOTIMPL; }
    IFACEMETHODIMP GetValue(REFPROPERTYKEY,PROPVARIANT*) override { return E_NOTIMPL; }
};
class Users final : public ICredentialProviderUserArray {
    std::atomic<ULONG> references_{1};
    ComPtr<ICredentialProviderUser> user_;
public:
    explicit Users(std::wstring sid) { user_.Attach(new User(std::move(sid))); }
    IFACEMETHODIMP QueryInterface(REFIID iid,void** out) override {
        if (!out) return E_POINTER; *out=nullptr;
        if (iid!=IID_IUnknown && iid!=IID_ICredentialProviderUserArray) return E_NOINTERFACE;
        *out=static_cast<ICredentialProviderUserArray*>(this); AddRef(); return S_OK;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++references_; }
    IFACEMETHODIMP_(ULONG) Release() override { auto n=--references_; if (!n) delete this; return n; }
    IFACEMETHODIMP SetProviderFilter(REFGUID) override { return S_OK; }
    IFACEMETHODIMP GetAccountOptions(CREDENTIAL_PROVIDER_ACCOUNT_OPTIONS* options) override {
        if (!options) return E_POINTER; *options=CPAO_NONE; return S_OK;
    }
    IFACEMETHODIMP GetCount(DWORD* count) override { if (!count) return E_POINTER; *count=1; return S_OK; }
    IFACEMETHODIMP GetAt(DWORD index,ICredentialProviderUser** user) override {
        if (!user) return E_POINTER; *user=nullptr;
        if (index!=0) return E_INVALIDARG;
        return user_.CopyTo(user);
    }
};
class Events final : public ICredentialProviderEvents {
    std::atomic<ULONG> references_{1};
    ComPtr<IUnknown> marshaler_;
public:
    HANDLE changed=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    Events() {
        if (!changed || FAILED(CoCreateFreeThreadedMarshaler(this,&marshaler_))) throw std::runtime_error("Cannot create test event receiver");
    }
    ~Events() { CloseHandle(changed); }
    IFACEMETHODIMP QueryInterface(REFIID iid,void** out) override {
        if (!out) return E_POINTER; *out=nullptr;
        if (iid==IID_IMarshal) return marshaler_->QueryInterface(iid,out);
        if (iid!=IID_IUnknown && iid!=IID_ICredentialProviderEvents) return E_NOINTERFACE;
        *out=static_cast<ICredentialProviderEvents*>(this); AddRef(); return S_OK;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++references_; }
    IFACEMETHODIMP_(ULONG) Release() override { auto n=--references_; if (!n) delete this; return n; }
    IFACEMETHODIMP CredentialsChanged(UINT_PTR context) override {
        if (context!=42) return E_INVALIDARG;
        SetEvent(changed); return S_OK;
    }
};
class CredentialEvents final : public ICredentialProviderCredentialEvents {
    std::atomic<ULONG> refs_{1};
public:
    IFACEMETHODIMP QueryInterface(REFIID iid,void** out) override {
        if (!out) return E_POINTER; *out=nullptr;
        if (iid!=IID_IUnknown && iid!=IID_ICredentialProviderCredentialEvents) return E_NOINTERFACE;
        *out=static_cast<ICredentialProviderCredentialEvents*>(this); AddRef(); return S_OK;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++refs_; }
    IFACEMETHODIMP_(ULONG) Release() override { auto n=--refs_; if (!n) delete this; return n; }
    IFACEMETHODIMP SetFieldState(ICredentialProviderCredential*,DWORD,CREDENTIAL_PROVIDER_FIELD_STATE) override { return S_OK; }
    IFACEMETHODIMP SetFieldInteractiveState(ICredentialProviderCredential*,DWORD,CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE) override { return S_OK; }
    IFACEMETHODIMP SetFieldString(ICredentialProviderCredential*,DWORD,PCWSTR) override { return S_OK; }
    IFACEMETHODIMP SetFieldCheckbox(ICredentialProviderCredential*,DWORD,BOOL,PCWSTR) override { return S_OK; }
    IFACEMETHODIMP SetFieldBitmap(ICredentialProviderCredential*,DWORD,HBITMAP) override { return S_OK; }
    IFACEMETHODIMP SetFieldComboBoxSelectedItem(ICredentialProviderCredential*,DWORD,DWORD) override { return S_OK; }
    IFACEMETHODIMP DeleteFieldComboBoxItem(ICredentialProviderCredential*,DWORD,DWORD) override { return S_OK; }
    IFACEMETHODIMP AppendFieldComboBoxItem(ICredentialProviderCredential*,DWORD,PCWSTR) override { return S_OK; }
    IFACEMETHODIMP SetFieldSubmitButton(ICredentialProviderCredential*,DWORD,DWORD) override { return S_OK; }
    IFACEMETHODIMP OnCreatingWindow(HWND* owner) override { if (!owner) return E_POINTER; *owner=nullptr; return S_OK; }
};
using GetFactory=HRESULT (__stdcall*)(REFCLSID,REFIID,void**);
using CanUnload=HRESULT (__stdcall*)();
void test(const wchar_t* dll,bool authenticate,bool cancel,bool inspect,const wchar_t* inspectSid,bool registered,const wchar_t* localAccount,bool cancelReady) {
    const auto path=std::filesystem::absolute(dll);
    ComPtr<IClassFactory> cf;
    if (registered) check(SUCCEEDED(CoGetClassObject(CLSID_SovereignAuth,CLSCTX_INPROC_SERVER,nullptr,IID_PPV_ARGS(&cf))),"Windows COM registration activates the provider");
    HMODULE module=LoadLibraryExW(path.c_str(),nullptr,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);
    check(module!=nullptr,"provider loads without Windows registration");
    const auto factory=reinterpret_cast<GetFactory>(GetProcAddress(module,"DllGetClassObject"));
    const auto unload=reinterpret_cast<CanUnload>(GetProcAddress(module,"DllCanUnloadNow"));
    check(factory && unload,"COM entry points exported");
    check(unload()==(registered ? S_FALSE : S_OK),"module lifetime matches the active factory state");
    if (!registered) check(SUCCEEDED(factory(CLSID_SovereignAuth,IID_PPV_ARGS(&cf))),"class factory created");
    check(unload()==S_FALSE,"live COM objects prevent module unload");
    ComPtr<ICredentialProvider> provider;
    check(SUCCEEDED(cf->CreateInstance(nullptr,IID_PPV_ARGS(&provider))),"provider created");
    void* unexpected=nullptr;
    check(cf->CreateInstance(cf.Get(),IID_ICredentialProvider,&unexpected)==CLASS_E_NOAGGREGATION && !unexpected,"COM aggregation rejected");
    check(provider->SetUsageScenario(CPUS_CREDUI,0)==E_NOTIMPL,"UAC scenario not inadvertently intercepted");
    check(provider->SetUsageScenario(CPUS_CHANGE_PASSWORD,0)==E_NOTIMPL,"password changes not intercepted");
    check(SUCCEEDED(provider->SetUsageScenario(CPUS_LOGON,0)),"interactive logon supported");
    DWORD fields=0;
    check(SUCCEEDED(provider->GetFieldDescriptorCount(&fields)) && fields==5,"sign-in fields include a Windows provider logo and label");
    DWORD logo=MAXDWORD,label=MAXDWORD;
    for (DWORD i=0;i<fields;++i) {
        CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* field=nullptr;
        check(SUCCEEDED(provider->GetFieldDescriptorAt(i,&field)) && field && field->cpft!=CPFT_PASSWORD_TEXT,"no daily password input field");
        if (field->guidFieldType==CPFG_CREDENTIAL_PROVIDER_LOGO && field->cpft==CPFT_TILE_IMAGE) logo=field->dwFieldID;
        if (field->guidFieldType==CPFG_CREDENTIAL_PROVIDER_LABEL && field->cpft==CPFT_SMALL_TEXT) label=field->dwFieldID;
        CoTaskMemFree(field->pszLabel); CoTaskMemFree(field);
    }
    check(logo!=MAXDWORD && label!=MAXDWORD && logo!=label,"Windows sign-in option icon and label are explicitly identified");
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* invalid=nullptr;
    check(provider->GetFieldDescriptorAt(fields,&invalid)==E_INVALIDARG && !invalid,"invalid field index rejected");
    DWORD count=99,selected=0;
    BOOL automatic=TRUE;
    check(SUCCEEDED(provider->GetCredentialCount(&count,&selected,&automatic)) && count==0 && !automatic,"no sign-in before user enumeration");
    ComPtr<Events> events; events.Attach(new Events());
    ComPtr<ICredentialProviderSetUserArray> setUsers;
    check(SUCCEEDED(provider.As(&setUsers)),"V2 user-array interface exposed");
    ComPtr<ICredentialProviderUserArray> users;
    if (localAccount) users=swa::userArrayForLocalAccount(localAccount);
    else if (inspectSid) users.Attach(new Users(inspectSid));
    else if (authenticate || cancel || inspect || cancelReady) users=swa::currentUserArray();
    else users.Attach(new Users(L"S-1-5-21-1-2-3-1999999999"));
    ComPtr<ICredentialProviderUser> targetUser;
    PWSTR rawTargetSid=nullptr;
    check(SUCCEEDED(users->GetAt(0,&targetUser)) && SUCCEEDED(targetUser->GetSid(&rawTargetSid)) && rawTargetSid,"test target has an explicit SID");
    const std::wstring expectedSid(rawTargetSid); CoTaskMemFree(rawTargetSid); targetUser.Reset();
    check(SUCCEEDED(setUsers->SetUserArray(users.Get())),"test user array supplied");
    check(SUCCEEDED(provider->GetCredentialCount(&count,&selected,&automatic)) && !automatic &&
        count==((authenticate || cancel || inspect || cancelReady) ? 1u : 0u),"credential enumeration does not depend on callback registration order");
    check(SUCCEEDED(provider->Advise(events.Get(),42)),"event callback connected after enumeration");
    check(SUCCEEDED(provider->GetCredentialCount(&count,&selected,&automatic)) && !automatic,"no automatic sign-in without fresh key proof");
    if (!authenticate && !cancel && !inspect && !cancelReady) {
        check(count==0,"unenrolled user has no credential tile");
    } else {
        check(count==1,"enrolled user has exactly one key tile");
        ComPtr<ICredentialProviderCredential> credential;
        check(SUCCEEDED(provider->GetCredentialAt(0,&credential)),"enrolled credential retrieved");
        ComPtr<CredentialEvents> credentialEvents; credentialEvents.Attach(new CredentialEvents());
        check(SUCCEEDED(credential->Advise(credentialEvents.Get())),"credential UI callbacks attached");
        BOOL selectAutomatically=TRUE;
        check(SUCCEEDED(credential->SetSelected(&selectAutomatically)) && !selectAutomatically,"selecting the tile without a key proof cannot sign in");
        HBITMAP bitmap=nullptr;
        check(SUCCEEDED(credential->GetBitmapValue(logo,&bitmap)) && bitmap,"provider supplies its sign-in option bitmap");
        BITMAP details{};
        const bool validBitmap=GetObjectW(bitmap,sizeof(details),&details)==sizeof(details) && details.bmWidth==64 && details.bmHeight==64 && details.bmBitsPixel==32;
        DeleteObject(bitmap);
        check(validBitmap,"sign-in option bitmap is valid 64x64 BGRA");
        PWSTR providerLabel=nullptr;
        const auto labelStatus=credential->GetStringValue(label,&providerLabel);
        const bool validLabel=SUCCEEDED(labelStatus) && providerLabel && wcscmp(providerLabel,L"Sovereign key")==0;
        CoTaskMemFree(providerLabel);
        check(validLabel,"sign-in option is labeled Sovereign key");
        if (authenticate || cancel || cancelReady) {
        CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE response{};
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION serialized{};
        PWSTR message=nullptr;
        CREDENTIAL_PROVIDER_STATUS_ICON icon{};
        const auto started=GetTickCount64();
        std::cout << (cancel ? "Testing cancellation; do not touch the key." : "Touch the key to test our provider. No password or PIN entry.") << std::endl;
        check(SUCCEEDED(credential->GetSerialization(&response,&serialized,&message,&icon)),"authentication request accepted");
        CoTaskMemFree(message); message=nullptr;
        check(GetTickCount64()-started<1000 && response==CPGSR_NO_CREDENTIAL_NOT_FINISHED && serialized.rgbSerialization==nullptr,"authentication starts asynchronously with no early credential release");
        if (cancel) credential->SetDeselected();
        check(WaitForSingleObject(events->changed,22000)==WAIT_OBJECT_0,"background authentication returns a completion event");
        // This is the exact refresh order observed in the real LogonUI trace:
        // UnAdvise -> GetCredentialCount -> Advise -> SetSelected -> serialization.
        check(SUCCEEDED(credential->UnAdvise()),"Windows refresh detaches credential UI callbacks");
        provider->GetCredentialCount(&count,&selected,&automatic);
        check(SUCCEEDED(credential->Advise(credentialEvents.Get())),"Windows refresh reattaches credential UI callbacks");
        if (cancel) {
            check(!automatic,"canceled authentication cannot trigger sign-in");
            check(SUCCEEDED(credential->SetSelected(&selectAutomatically)) && !selectAutomatically,"reselecting after cancellation cannot revive the proof");
        } else if (cancelReady) {
            check(automatic && selected==0,"completed proof survives a display-only refresh before cancellation");
            check(SUCCEEDED(credential->SetDeselected()),"user cancellation invalidates a completed proof");
            credential->UnAdvise();
            provider->GetCredentialCount(&count,&selected,&automatic);
            credential->Advise(credentialEvents.Get());
            check(!automatic && SUCCEEDED(credential->SetSelected(&selectAutomatically)) && !selectAutomatically,"a canceled completed proof cannot be revived by display refresh or reselection");
            std::cout << "No Windows credential submitted during cancellation check." << std::endl;
        } else {
            check(automatic && selected==0,"fresh proof selects the authenticated tile");
            check(SUCCEEDED(credential->SetSelected(&selectAutomatically)) && selectAutomatically,"Windows tile selection continues the completed key authentication");
            check(SUCCEEDED(credential->GetSerialization(&response,&serialized,&message,&icon)) && response==CPGSR_RETURN_CREDENTIAL_FINISHED,"provider serializes credential only after verified touch");
            CoTaskMemFree(message); message=nullptr;
            check(serialized.clsidCredentialProvider==CLSID_SovereignAuth && serialized.rgbSerialization && serialized.cbSerialization>0,"Windows authentication package receives our provider's credential");
            std::wstring sid;
            try {
                sid=swa::authenticateWindowsBuffer(serialized.ulAuthenticationPackage,{serialized.rgbSerialization,serialized.cbSerialization});
            } catch (...) {
                SecureZeroMemory(serialized.rgbSerialization,serialized.cbSerialization); CoTaskMemFree(serialized.rgbSerialization); serialized={};
                throw;
            }
            SecureZeroMemory(serialized.rgbSerialization,serialized.cbSerialization); CoTaskMemFree(serialized.rgbSerialization); serialized={};
            check(!sid.empty(),"Windows accepts the exact serialized credential emitted by our provider");
            check(sid==expectedSid,"Windows authenticates the intended user");
            provider->GetCredentialCount(&count,&selected,&automatic);
            check(!automatic,"completed proof cannot be reused for another automatic sign-in");
            check(SUCCEEDED(credential->SetSelected(&selectAutomatically)) && !selectAutomatically,"reselecting a consumed proof cannot sign in again");
        }
        credential->SetDeselected();
        }
    }
    provider->UnAdvise(); setUsers.Reset(); provider.Reset(); cf.Reset(); users.Reset(); events.Reset();
    const auto until=GetTickCount64()+2000;
    while (unload()!=S_OK && GetTickCount64()<until) Sleep(10);
    check(unload()==S_OK,"provider releases COM objects and background worker");
    FreeLibrary(module);
}
}
int wmain(int argc,wchar_t** argv) {
    const HRESULT com=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
    if (FAILED(com)) return 1;
    int result=0;
    try {
        if (argc<2 || argc>4) throw std::runtime_error("Usage: swa_provider_host provider.dll [--authenticate|--cancel|--inspect|--inspect-sid SID|--registered-sid SID]");
        const bool systemAuth=argc==4 && std::wstring_view(argv[2])==L"--authenticate-system-user";
        if (systemAuth && swa::currentSid()!=L"S-1-5-18") throw std::runtime_error("SYSTEM authentication check requires the SYSTEM account");
        const bool authenticate=systemAuth || (argc==3 && std::wstring_view(argv[2])==L"--authenticate");
        const bool cancel=argc==3 && std::wstring_view(argv[2])==L"--cancel";
        const bool cancelReady=argc==3 && std::wstring_view(argv[2])==L"--cancel-ready";
        const bool registered=argc==4 && std::wstring_view(argv[2])==L"--registered-sid";
        const wchar_t* sid=argc==4 && (registered || std::wstring_view(argv[2])==L"--inspect-sid") ? argv[3] : nullptr;
        const bool inspect=sid || (argc==3 && std::wstring_view(argv[2])==L"--inspect");
        if (argc>=3 && !authenticate && !cancel && !inspect && !cancelReady) throw std::runtime_error("Unknown test mode");
        test(argv[1],authenticate,cancel,inspect,sid,registered,systemAuth ? argv[3] : nullptr,cancelReady);
    } catch (const std::exception& error) { std::cerr << "FAILED: " << error.what() << std::endl; result=1; }
    CoUninitialize(); return result;
}
