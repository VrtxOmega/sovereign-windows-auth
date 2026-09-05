#include "windows_pin.h"
#include "windows_pin_interfaces.h"
#include <wrl/client.h>
#include <optional>
#include <atomic>
using Microsoft::WRL::ComPtr;
namespace {
void requireHr(HRESULT status,const char* stage) {
    if (FAILED(status)) throw std::runtime_error(std::string(stage)+" (HRESULT "+std::to_string(static_cast<ULONG>(status))+")");
}
struct PinPrompt { swa::Secret pin{514}; };
class Events final : public swa::PinEvents5,public ICredentialProviderEvents {
    std::atomic<ULONG> refs_{1};
public:
    IFACEMETHODIMP QueryInterface(REFIID iid,void** out) override {
        if (!out) return E_POINTER; *out=nullptr;
        if (iid==IID_IUnknown || iid==IID_ICredentialProviderCredentialEvents || iid==IID_ICredentialProviderCredentialEvents2 ||
            iid==__uuidof(swa::PinEvents3) || iid==__uuidof(swa::PinEvents4) || iid==__uuidof(swa::PinEvents5))
            *out=static_cast<swa::PinEvents5*>(this);
        else if (iid==IID_ICredentialProviderEvents) *out=static_cast<ICredentialProviderEvents*>(this);
        else return E_NOINTERFACE;
        AddRef(); return S_OK;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++refs_; }
    IFACEMETHODIMP_(ULONG) Release() override { const auto n=--refs_; if (!n) delete this; return n; }
    IFACEMETHODIMP CredentialsChanged(UINT_PTR) override { return S_OK; }
    IFACEMETHODIMP BeginFieldUpdates() override { return S_OK; }
    IFACEMETHODIMP EndFieldUpdates() override { return S_OK; }
    IFACEMETHODIMP SetFieldOptions(ICredentialProviderCredential*,DWORD,CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS) override { return S_OK; }
    IFACEMETHODIMP SetFieldBitmapBuffer(ICredentialProviderCredential*,DWORD,DWORD,const BYTE*) override { return S_OK; }
    IFACEMETHODIMP RequestSerialization() override { return S_OK; }
    IFACEMETHODIMP RequestSelection() override { return S_OK; }
    IFACEMETHODIMP SetTextFieldMaxLength(ICredentialProviderCredential*,DWORD,DWORD) override { return S_OK; }
    IFACEMETHODIMP SetAccessibilityTextForField(ICredentialProviderCredential*,DWORD,PCWSTR) override { return S_OK; }
    IFACEMETHODIMP SetRawAccessibilityViewForField(ICredentialProviderCredential*,DWORD,BOOL) override { return S_OK; }
    IFACEMETHODIMP RequestWebDialogVisibilityChange(ICredentialProviderCredential*,BOOL visible) override { return visible ? E_NOTIMPL : S_OK; }
    IFACEMETHODIMP SetFieldState(ICredentialProviderCredential*,DWORD,CREDENTIAL_PROVIDER_FIELD_STATE) override { return S_OK; }
    IFACEMETHODIMP SetFieldInteractiveState(ICredentialProviderCredential*,DWORD,CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE) override { return S_OK; }
    IFACEMETHODIMP SetFieldString(ICredentialProviderCredential*,DWORD,PCWSTR) override { return S_OK; }
    IFACEMETHODIMP SetFieldCheckbox(ICredentialProviderCredential*,DWORD,BOOL,PCWSTR) override { return S_OK; }
    IFACEMETHODIMP SetFieldBitmap(ICredentialProviderCredential*,DWORD,HBITMAP) override { return S_OK; }
    IFACEMETHODIMP SetFieldComboBoxSelectedItem(ICredentialProviderCredential*,DWORD,DWORD) override { return S_OK; }
    IFACEMETHODIMP DeleteFieldComboBoxItem(ICredentialProviderCredential*,DWORD,DWORD) override { return S_OK; }
    IFACEMETHODIMP AppendFieldComboBoxItem(ICredentialProviderCredential*,DWORD,PCWSTR) override { return S_OK; }
    IFACEMETHODIMP SetFieldSubmitButton(ICredentialProviderCredential*,DWORD,DWORD) override { return S_OK; }
    IFACEMETHODIMP OnCreatingWindow(HWND* owner) override { if (!owner) return E_POINTER; *owner=GetConsoleWindow(); return S_OK; }
};
INT_PTR CALLBACK pinDialog(HWND window,UINT message,WPARAM wparam,LPARAM lparam) {
    auto prompt=reinterpret_cast<PinPrompt*>(GetWindowLongPtrW(window,DWLP_USER));
    if (message==WM_INITDIALOG) {
        SetWindowLongPtrW(window,DWLP_USER,lparam);
        SendDlgItemMessageW(window,1002,EM_SETLIMITTEXT,256,0);
        SetFocus(GetDlgItem(window,1002)); return FALSE;
    }
    if (message==WM_COMMAND && LOWORD(wparam)==IDOK && prompt) {
        const int count=GetWindowTextLengthW(GetDlgItem(window,1002));
        if (count<1 || count>256) return TRUE;
        if (GetDlgItemTextW(window,1002,reinterpret_cast<PWSTR>(prompt->pin.data()),257)!=static_cast<UINT>(count)) return TRUE;
        SetDlgItemTextW(window,1002,L""); EndDialog(window,IDOK); return TRUE;
    }
    if (message==WM_CLOSE || (message==WM_COMMAND && LOWORD(wparam)==IDCANCEL)) {
        SetDlgItemTextW(window,1002,L""); EndDialog(window,IDCANCEL); return TRUE;
    }
    return FALSE;
}

}

namespace swa {
struct WindowsPin::Impl {
    ComPtr<ICredentialProvider> provider;
    ComPtr<ICredentialProviderCredential> credential;
    ComPtr<Events> events;
    DWORD pinField=0;
    bool hasPinField=false;
    bool used=false;
    ~Impl() {
        if (credential) {
            if (hasPinField) credential->SetStringValue(pinField,L"");
            credential->SetDeselected(); credential->UnAdvise();
        }
        if (provider) provider->UnAdvise();
    }
    void initialize(ICredentialProviderUserArray* users,const std::wstring& expectedSid,CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario) {
        if (!users || (scenario!=CPUS_LOGON && scenario!=CPUS_UNLOCK_WORKSTATION))
            throw std::invalid_argument("Invalid Windows PIN scenario or user array");
        CLSID clsid{};
        requireHr(CLSIDFromString(L"{D6886603-9D2F-4EB2-B667-1971041FA96B}",&clsid),"Identify Windows PIN provider");
        requireHr(CoCreateInstance(clsid,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&provider)),"Open Windows PIN provider");
        requireHr(provider->SetUsageScenario(scenario,0),"Set Windows PIN scenario");
        events.Attach(new Events());
        requireHr(provider->Advise(static_cast<ICredentialProviderEvents*>(events.Get()),0),"Connect Windows PIN provider events");
        ComPtr<ICredentialProviderSetUserArray> setUsers;
        requireHr(provider.As(&setUsers),"Query Windows PIN user interface");
        requireHr(setUsers->SetUserArray(users),"Set Windows PIN user identity");
        DWORD count=0,selected=0; BOOL automatic=FALSE;
        requireHr(provider->GetCredentialCount(&count,&selected,&automatic),"Enumerate Windows PIN credentials");
        if (count>256 || automatic) throw std::runtime_error("Unexpected Windows PIN enumeration state");
        for (DWORD i=0;i<count;++i) {
            ComPtr<ICredentialProviderCredential> candidate;
            if (FAILED(provider->GetCredentialAt(i,&candidate))) continue;
            ComPtr<ICredentialProviderCredential2> v2;
            if (FAILED(candidate.As(&v2))) continue;
            PWSTR sid=nullptr;
            const auto status=v2->GetUserSid(&sid);
            const bool match=SUCCEEDED(status) && sid && expectedSid==sid;
            CoTaskMemFree(sid);
            if (match) {
                if (credential) throw std::runtime_error("Ambiguous Windows PIN identity");
                credential=candidate;
            }
        }
        if (!credential) throw std::runtime_error("No Windows PIN credential for the enrolled user");
        requireHr(credential->Advise(static_cast<ICredentialProviderCredentialEvents*>(events.Get())),"Connect Windows PIN credential events");
        BOOL autoSelected=FALSE;
        requireHr(credential->SetSelected(&autoSelected),"Select Windows PIN credential");
        if (autoSelected) throw std::runtime_error("Unexpected automatic Windows PIN submission");
        DWORD fields=0;
        requireHr(provider->GetFieldDescriptorCount(&fields),"Enumerate Windows PIN fields");
        if (fields>128) throw std::runtime_error("Too many Windows PIN fields");
        std::optional<DWORD> input;
        for (DWORD i=0;i<fields;++i) {
            CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* field=nullptr;
            if (FAILED(provider->GetFieldDescriptorAt(i,&field)) || !field) continue;
            const auto id=field->dwFieldID; const auto type=field->cpft;
            CoTaskMemFree(field->pszLabel); CoTaskMemFree(field);
            if (type!=CPFT_PASSWORD_TEXT) continue;
            CREDENTIAL_PROVIDER_FIELD_STATE state{};
            CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE interactive{};
            if (SUCCEEDED(credential->GetFieldState(id,&state,&interactive)) &&
                (state==CPFS_DISPLAY_IN_SELECTED_TILE || state==CPFS_DISPLAY_IN_BOTH) && interactive==CPFIS_FOCUSED) {
                if (input) throw std::runtime_error("Ambiguous Windows PIN input");
                input=id;
            }
        }
        if (!input) throw std::runtime_error("Windows PIN input unavailable");
        pinField=*input;
        hasPinField=true;
    }
};
WindowsPin::WindowsPin(ICredentialProviderUserArray* users,const std::wstring& sid,CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario)
    : impl_(std::make_unique<Impl>()) { impl_->initialize(users,sid,scenario); }
WindowsPin::~WindowsPin()=default;
WindowsCredentialBuffer WindowsPin::serialize(const wchar_t* pin) {
    if (!pin || !pin[0] || wcsnlen_s(pin,257)>256 || impl_->used)
        throw std::invalid_argument("Invalid or repeated Windows PIN request");
    impl_->used=true;
    requireHr(impl_->credential->SetStringValue(impl_->pinField,pin),"Supply Windows PIN");
    struct Serialization {
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION value{};
        ~Serialization() {
            if (value.rgbSerialization) { SecureZeroMemory(value.rgbSerialization,value.cbSerialization); CoTaskMemFree(value.rgbSerialization); }
        }
    } serialized;
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE response{};
    PWSTR message=nullptr; CREDENTIAL_PROVIDER_STATUS_ICON icon{};
    const auto status=impl_->credential->GetSerialization(&response,&serialized.value,&message,&icon);
    CoTaskMemFree(message);
    impl_->credential->SetStringValue(impl_->pinField,L"");
    requireHr(status,"Windows PIN serialization");
    if (response!=CPGSR_RETURN_CREDENTIAL_FINISHED || !serialized.value.rgbSerialization ||
        serialized.value.cbSerialization==0 || serialized.value.cbSerialization>65536)
        throw std::runtime_error("Windows PIN did not produce a credential; no automatic retry");
    Secret buffer(serialized.value.cbSerialization);
    memcpy(buffer.data(),serialized.value.rgbSerialization,buffer.size());
    return {serialized.value.ulAuthenticationPackage,std::move(buffer)};
}
Secret promptWindowsPin() {
    PinPrompt prompt;
    if (DialogBoxParamW(GetModuleHandleW(nullptr),MAKEINTRESOURCEW(101),nullptr,pinDialog,reinterpret_cast<LPARAM>(&prompt))!=IDOK)
        throw std::runtime_error("Windows PIN entry canceled");
    return std::move(prompt.pin);
}
}
