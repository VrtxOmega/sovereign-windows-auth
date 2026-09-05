#include "core.h"
#include "current_user.h"
#include <credentialprovider.h>
#include <lm.h>
#include <ncrypt.h>
#include <propkey.h>
#include <propvarutil.h>
#include <shlwapi.h>
#include <wrl/client.h>
#include <atomic>
#include <iostream>

// Read-only, in-process inspection. Never select a tile, submit a credential,
// request a private-key operation, change enrollment, or print key identifiers.
using Microsoft::WRL::ComPtr;
namespace {
void result(const char* name,HRESULT status) {
    std::cout << name << "=0x" << std::hex << static_cast<unsigned long>(status) << std::dec << std::endl;
}
void inspectProvider(const wchar_t* id,CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario) {
    CLSID clsid{}; if (FAILED(CLSIDFromString(id,&clsid))) throw std::runtime_error("Invalid provider ID");
    ComPtr<IUnknown> instance;
    auto status=CoCreateInstance(clsid,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&instance));
    result("create",status); if (FAILED(status)) return;
    ComPtr<ICredentialProvider> provider;
    status=instance.As(&provider); result("provider_interface",status); if (FAILED(status)) return;
    status=provider->SetUsageScenario(scenario,0); result("scenario",status); if (FAILED(status)) return;
    ComPtr<ICredentialProviderSetUserArray> setUsers;
    status=provider.As(&setUsers); result("user_array_interface",status);
    auto users=swa::currentUserArray();
    if (SUCCEEDED(status)) result("set_users",setUsers->SetUserArray(users.Get()));
    DWORD fields=0;
    status=provider->GetFieldDescriptorCount(&fields); result("fields",status);
    if (SUCCEEDED(status) && fields<128) {
        std::cout << "field_count=" << fields << std::endl;
        for (DWORD i=0;i<fields;++i) {
            CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* descriptor=nullptr;
            status=provider->GetFieldDescriptorAt(i,&descriptor);
            if (SUCCEEDED(status) && descriptor) {
                std::cout << "field_index=" << i << " id=" << descriptor->dwFieldID
                    << " type=" << descriptor->cpft << std::endl;
                if (descriptor->pszLabel) std::wcout << L"label=" << descriptor->pszLabel << std::endl;
                CoTaskMemFree(descriptor->pszLabel); CoTaskMemFree(descriptor);
            }
        }
    }
    DWORD count=0,selected=CREDENTIAL_PROVIDER_NO_DEFAULT; BOOL automatic=FALSE;
    status=provider->GetCredentialCount(&count,&selected,&automatic); result("credentials",status);
    if (SUCCEEDED(status)) std::cout << "credential_count=" << count << " automatic=" << automatic << std::endl;
    if (SUCCEEDED(status) && count>0 && count<16) {
        ComPtr<ICredentialProviderCredential> credential;
        result("get_first_credential",provider->GetCredentialAt(0,&credential));
        if (credential) {
            ComPtr<ICredentialProviderCredential2> v2;
            result("credential_v2",credential.As(&v2));
            if (v2) {
                PWSTR credentialSid=nullptr;
                const auto sidStatus=v2->GetUserSid(&credentialSid);
                result("credential_sid",sidStatus);
                if (SUCCEEDED(sidStatus) && credentialSid)
                    std::cout << "matches_current_user=" << (swa::currentSid()==credentialSid) << std::endl;
                CoTaskMemFree(credentialSid);
            }
            for (DWORD i=0;i<fields && i<128;++i) {
                CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* descriptor=nullptr;
                if (SUCCEEDED(provider->GetFieldDescriptorAt(i,&descriptor)) && descriptor) {
                    CREDENTIAL_PROVIDER_FIELD_STATE visible{};
                    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE interactive{};
                    const auto fieldStatus=credential->GetFieldState(descriptor->dwFieldID,&visible,&interactive);
                    if (SUCCEEDED(fieldStatus)) std::cout << "field_id=" << descriptor->dwFieldID << " visibility=" << visible << " interactive=" << interactive << std::endl;
                    if (descriptor->cpft==CPFT_SUBMIT_BUTTON) {
                        DWORD adjacent=0;
                        const auto adjacentStatus=credential->GetSubmitButtonValue(descriptor->dwFieldID,&adjacent);
                        if (SUCCEEDED(adjacentStatus)) std::cout << "submit_adjacent_to=" << adjacent << std::endl;
                    }
                    CoTaskMemFree(descriptor->pszLabel); CoTaskMemFree(descriptor);
                }
            }
        }
    }
}
void inspectPassport() {
    NCRYPT_PROV_HANDLE provider=0;
    auto status=NCryptOpenStorageProvider(&provider,L"Microsoft Passport Key Storage Provider",0);
    result("passport_provider",status); if (status!=ERROR_SUCCESS) return;
    void* enumeration=nullptr; DWORD count=0;
    for (;count<256;) {
        NCryptKeyName* key=nullptr;
        status=NCryptEnumKeys(provider,nullptr,&key,&enumeration,NCRYPT_SILENT_FLAG);
        if (status!=ERROR_SUCCESS) break;
        ++count; NCryptFreeBuffer(key);
    }
    if (enumeration) NCryptFreeBuffer(enumeration);
    NCryptFreeObject(provider);
    result("passport_enumeration",status);
    std::cout << "passport_key_count=" << count << std::endl;
}
}
int wmain(int argc,wchar_t** argv) {
    if (FAILED(CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED))) return 1;
    int exitCode=0;
    try {
        if (argc==2 && std::wstring_view(argv[1])==L"passport") inspectPassport();
        else if (argc==3) {
            const std::wstring_view name(argv[1]),scenarioName(argv[2]);
            const wchar_t* id=name==L"hello" ? L"{D6886603-9D2F-4EB2-B667-1971041FA96B}" :
                name==L"fido" ? L"{F8A1793B-7873-4046-B2A7-1F318747F427}" :
                name==L"password" ? L"{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}" : nullptr;
            if (!id) throw std::runtime_error("Unknown provider");
            const auto scenario=scenarioName==L"logon" ? CPUS_LOGON : scenarioName==L"unlock" ? CPUS_UNLOCK_WORKSTATION : CPUS_INVALID;
            if (scenario==CPUS_INVALID) throw std::runtime_error("Unknown scenario");
            inspectProvider(id,scenario);
        } else throw std::runtime_error("Usage: swa_signin_inspect passport | hello|fido|password logon|unlock");
    } catch (const std::exception& error) { std::cerr << error.what() << std::endl; exitCode=1; }
    CoUninitialize(); return exitCode;
}
