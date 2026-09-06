#include "filter_lab.h"
#include "filter_id.h"
#include <wrl/client.h>
#include <iostream>
#include <stdexcept>

using Microsoft::WRL::ComPtr;
namespace {
void check(bool condition, const char* text) {
    if (!condition) throw std::runtime_error(text);
    std::cout << "PASS " << text << '\n';
}
}
int wmain(int argc, wchar_t** argv) {
    HMODULE library = nullptr;
    try {
        if (argc != 2) throw std::runtime_error("Supply the VM filter DLL path");
        library = LoadLibraryExW(argv[1], nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
        check(library != nullptr, "VM filter loads without FIDO, enrollment or registration");
        const auto getClass = reinterpret_cast<HRESULT(__stdcall*)(REFCLSID,REFIID,void**)>(GetProcAddress(library, "DllGetClassObject"));
        const auto canUnload = reinterpret_cast<HRESULT(__stdcall*)()>(GetProcAddress(library, "DllCanUnloadNow"));
        check(getClass && canUnload, "COM exports exist");
        check(canUnload() == S_OK, "unused module can unload");
        void* output = reinterpret_cast<void*>(1);
        check(getClass(CLSID_SovereignAuth, IID_IUnknown, &output) == CLASS_E_CLASSNOTAVAILABLE && !output,
              "a different class cannot be instantiated");
        check(getClass(CLSID_SovereignFilter, IID_IUnknown, nullptr) == E_POINTER, "null factory output rejected");
        {
            ComPtr<IClassFactory> factory;
            check(SUCCEEDED(getClass(CLSID_SovereignFilter, IID_PPV_ARGS(&factory))), "filter class factory loads");
            check(canUnload() == S_FALSE, "live factory holds module");
            check(factory->LockServer(FALSE) == E_UNEXPECTED, "unbalanced server unlock rejected");
            check(factory->LockServer(TRUE) == S_OK, "server lock accepted");
            ComPtr<IUnknown> identity;
            check(SUCCEEDED(factory.As(&identity)), "factory identity available");
            check(factory->CreateInstance(identity.Get(), IID_IUnknown, &output) == CLASS_E_NOAGGREGATION && !output,
                  "aggregation rejected");
            ComPtr<ICredentialProviderFilter> filter;
            check(SUCCEEDED(factory->CreateInstance(nullptr, IID_PPV_ARGS(&filter))), "filter interface instantiates");
            std::array<GUID, 3> ids{CLSID_SovereignAuth, swa::lab::convenienceProviders[0].id, GUID_NULL};
            std::array<BOOL, 3> allow{TRUE, TRUE, FALSE};
            check(filter->Filter(CPUS_LOGON, 0, ids.data(), allow.data(), static_cast<DWORD>(ids.size())) == S_OK,
                  "desktop filter contract succeeds");
            check(allow[0] == TRUE && allow[1] == TRUE && allow[2] == FALSE,
                  "unconfigured or physical host remains passive and preserves other exclusions");
            CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION remote{};
            remote.cbSerialization = 12;
            check(filter->UpdateRemoteCredential(nullptr, &remote) == E_NOTIMPL && remote.cbSerialization == 0,
                  "remote serialization is not forwarded");
            check(factory->LockServer(FALSE) == S_OK, "balanced server unlock succeeds");
        }
        check(canUnload() == S_OK, "all released objects permit unloading");
        FreeLibrary(library);
        return 0;
    } catch (const std::exception& error) {
        if (library) FreeLibrary(library);
        std::cerr << error.what() << '\n';
        return 1;
    }
}
