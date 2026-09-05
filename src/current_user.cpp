#include "current_user.h"
#include "core.h"
#include <lm.h>
#include <propkey.h>
#include <propvarutil.h>
#include <shlwapi.h>
#include <sddl.h>
#include <atomic>
using Microsoft::WRL::ComPtr;
namespace {
class User final : public ICredentialProviderUser {
    std::atomic<ULONG> refs_{1};
    std::wstring sid_,username_,qualified_,display_;
    GUID identity_{};
public:
    explicit User(const wchar_t* name) {
        if (!name || !name[0] || wcsnlen_s(name,UNLEN+1)>UNLEN) throw std::runtime_error("Invalid local account name");
        USER_INFO_23* local=nullptr;
        if (NetUserGetInfo(nullptr,name,23,reinterpret_cast<LPBYTE*>(&local))!=NERR_Success || !local)
            throw std::runtime_error("Cannot identify the local account SID");
        PWSTR sid=nullptr;
        const bool converted=ConvertSidToStringSidW(local->usri23_user_sid,&sid)!=FALSE;
        NetApiBufferFree(local);
        if (!converted || !sid) throw std::runtime_error("Cannot format the local account SID");
        try { sid_=sid; } catch (...) { LocalFree(sid); throw; }
        LocalFree(sid);
        USER_INFO_24* internet=nullptr;
        if (NetUserGetInfo(nullptr,name,24,reinterpret_cast<LPBYTE*>(&internet))!=NERR_Success || !internet)
            throw std::runtime_error("Cannot identify account provider");
        // MicrosoftAccount's registered IdentityStore provider on this PC.
        // USER_INFO_24 provides the provider name, not a provider GUID.
        if (!internet->usri24_internet_identity || !internet->usri24_internet_provider_name ||
            wcscmp(internet->usri24_internet_provider_name,L"MicrosoftAccount")!=0) {
            NetApiBufferFree(internet); throw std::runtime_error("Inspection requires the linked Microsoft account");
        }
        if (FAILED(CLSIDFromString(L"{D7F9888F-E3FC-49b0-9EA6-A85B5F392A4F}",&identity_))) {
            NetApiBufferFree(internet); throw std::runtime_error("Cannot identify Microsoft-account provider");
        }
        username_=internet->usri24_internet_principal_name ? internet->usri24_internet_principal_name : name;
        qualified_=internet->usri24_internet_identity ? L"MicrosoftAccount\\"+username_ : username_;
        NetApiBufferFree(internet);
        USER_INFO_10* details=nullptr;
        if (NetUserGetInfo(nullptr,name,10,reinterpret_cast<LPBYTE*>(&details))==NERR_Success && details) {
            display_=details->usri10_full_name ? details->usri10_full_name : name;
            NetApiBufferFree(details);
        }
    }
    IFACEMETHODIMP QueryInterface(REFIID iid,void** out) override {
        if (!out) return E_POINTER; *out=nullptr;
        if (iid!=IID_IUnknown && iid!=IID_ICredentialProviderUser) return E_NOINTERFACE;
        *out=static_cast<ICredentialProviderUser*>(this); AddRef(); return S_OK;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++refs_; }
    IFACEMETHODIMP_(ULONG) Release() override { const auto n=--refs_; if (!n) delete this; return n; }
    IFACEMETHODIMP GetSid(PWSTR* sid) override { return SHStrDupW(sid_.c_str(),sid); }
    IFACEMETHODIMP GetProviderID(GUID* provider) override {
        if (!provider) return E_POINTER; *provider=identity_; return S_OK;
    }
    IFACEMETHODIMP GetStringValue(REFPROPERTYKEY key,PWSTR* value) override {
        if (!value) return E_POINTER; *value=nullptr;
        if (key==PKEY_Identity_QualifiedUserName) return SHStrDupW(qualified_.c_str(),value);
        if (key==PKEY_Identity_UserName) return SHStrDupW(username_.c_str(),value);
        if (key==PKEY_Identity_DisplayName) return SHStrDupW(display_.c_str(),value);
        if (key==PKEY_Identity_PrimarySid) return SHStrDupW(sid_.c_str(),value);
        if (key==PKEY_Identity_LogonStatusString) return SHStrDupW(L"",value);
        return E_NOTIMPL;
    }
    IFACEMETHODIMP GetValue(REFPROPERTYKEY key,PROPVARIANT* value) override {
        if (!value) return E_POINTER; PropVariantInit(value);
        if (key==PKEY_Identity_ProviderID) return InitPropVariantFromCLSID(identity_,value);
        PWSTR text=nullptr; const auto status=GetStringValue(key,&text);
        if (FAILED(status)) return status;
        const auto initialized=InitPropVariantFromString(text,value); CoTaskMemFree(text); return initialized;
    }
};
class Users final : public ICredentialProviderUserArray {
    std::atomic<ULONG> refs_{1};
    ComPtr<ICredentialProviderUser> user_;
public:
    explicit Users(const wchar_t* name) { user_.Attach(new User(name)); }
    IFACEMETHODIMP QueryInterface(REFIID iid,void** out) override {
        if (!out) return E_POINTER; *out=nullptr;
        if (iid!=IID_IUnknown && iid!=IID_ICredentialProviderUserArray) return E_NOINTERFACE;
        *out=static_cast<ICredentialProviderUserArray*>(this); AddRef(); return S_OK;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++refs_; }
    IFACEMETHODIMP_(ULONG) Release() override { const auto n=--refs_; if (!n) delete this; return n; }
    IFACEMETHODIMP SetProviderFilter(REFGUID) override { return S_OK; }
    IFACEMETHODIMP GetAccountOptions(CREDENTIAL_PROVIDER_ACCOUNT_OPTIONS* options) override {
        if (!options) return E_POINTER; *options=CPAO_NONE; return S_OK;
    }
    IFACEMETHODIMP GetCount(DWORD* count) override { if (!count) return E_POINTER; *count=1; return S_OK; }
    IFACEMETHODIMP GetAt(DWORD index,ICredentialProviderUser** user) override {
        if (!user) return E_POINTER; *user=nullptr; if (index) return E_INVALIDARG;
        return user_.CopyTo(user);
    }
};

}
namespace swa {
ComPtr<ICredentialProviderUserArray> currentUserArray() {
    wchar_t name[UNLEN+1]{}; DWORD size=UNLEN+1;
    if (!GetUserNameW(name,&size)) throw std::runtime_error("Cannot identify current user");
    return userArrayForLocalAccount(name);
}
ComPtr<ICredentialProviderUserArray> userArrayForLocalAccount(const wchar_t* name) {
    ComPtr<ICredentialProviderUserArray> users;
    users.Attach(new Users(name));
    return users;
}
}
