#include "provider_id.h"
#include <windows.h>
#include <credentialprovider.h>
#include <wrl/client.h>
#include <iostream>
#include <stdexcept>

using Microsoft::WRL::ComPtr;
namespace {
void check(bool condition,const char* message) {
    if(!condition)throw std::runtime_error(message);
    std::cout<<"PASS "<<message<<'\n';
}
}
int wmain(int argc,wchar_t** argv) {
    HMODULE library=nullptr;
    try {
        if(argc!=2)throw std::runtime_error("Supply the lab PIN bridge DLL path");
        library=LoadLibraryExW(argv[1],nullptr,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);
        check(library!=nullptr,"lab DLL loads without registration or enrollment");
        const auto getClass=reinterpret_cast<HRESULT(__stdcall*)(REFCLSID,REFIID,void**)>(GetProcAddress(library,"DllGetClassObject"));
        const auto canUnload=reinterpret_cast<HRESULT(__stdcall*)()>(GetProcAddress(library,"DllCanUnloadNow"));
        check(getClass&&canUnload,"COM exports exist");
        check(canUnload()==S_OK,"unused module can unload");
        void* output=reinterpret_cast<void*>(1);
        check(getClass(GUID_NULL,IID_IUnknown,&output)==CLASS_E_CLASSNOTAVAILABLE&&!output,"other classes rejected");
        {
            ComPtr<IClassFactory> factory;
            check(SUCCEEDED(getClass(CLSID_SovereignAuth,IID_PPV_ARGS(&factory))),"factory available");
            check(canUnload()==S_FALSE,"factory holds module");
            check(factory->LockServer(FALSE)==E_UNEXPECTED,"unbalanced unlock rejected");
            check(factory->CreateInstance(factory.Get(),IID_IUnknown,&output)==CLASS_E_NOAGGREGATION&&!output,"aggregation rejected");
            ComPtr<ICredentialProvider> provider;
            check(SUCCEEDED(factory->CreateInstance(nullptr,IID_PPV_ARGS(&provider))),"provider available");
            ComPtr<ICredentialProviderSetUserArray> users;
            check(SUCCEEDED(provider.As(&users)),"user array interface available");
            check(users->SetUserArray(nullptr)==E_POINTER,"null user array rejected");
            for(const auto scenario:{CPUS_LOGON,CPUS_UNLOCK_WORKSTATION,CPUS_CREDUI,CPUS_CHANGE_PASSWORD,CPUS_PLAP})
                check(provider->SetUsageScenario(scenario,0)==E_NOTIMPL,"unarmed host cannot activate lab sign-in");
            DWORD count=9,selected=9;BOOL automatic=TRUE;
            check(provider->GetCredentialCount(&count,&selected,&automatic)==S_OK&&count==0&&
                selected==CREDENTIAL_PROVIDER_NO_DEFAULT&&!automatic,"unarmed host has no credential or automatic sign-in");
            ComPtr<ICredentialProviderCredential> credential;
            check(provider->GetCredentialAt(0,&credential)==E_INVALIDARG&&!credential,"no credential escapes guard");
            DWORD fields=0;
            check(provider->GetFieldDescriptorCount(&fields)==S_OK&&fields==4,"lab has four explicit fields");
            CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* descriptor=nullptr;
            check(provider->GetFieldDescriptorAt(2,&descriptor)==S_OK&&descriptor&&descriptor->cpft==CPFT_PASSWORD_TEXT,
                "lab PIN field masks input");
            CoTaskMemFree(descriptor->pszLabel);CoTaskMemFree(descriptor);
            check(provider->SetSerialization(nullptr)==E_NOTIMPL,"serialized credentials cannot bypass guard");
        }
        check(canUnload()==S_OK,"released objects permit unload");
        FreeLibrary(library);return 0;
    }catch(const std::exception& error){
        if(library)FreeLibrary(library);
        std::cerr<<error.what()<<'\n';return 1;
    }
}
