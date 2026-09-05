#define _SEC_WINNT_AUTH_TYPES
#include "windows_auth.h"
#include <winternl.h>
#include <sspi.h>
#include <wincred.h>
#include <iostream>

namespace {
void check(bool value,const char* message) {
    if (!value) throw std::runtime_error(message);
    std::cout << "PASS " << message << std::endl;
}
struct Identity {
    PSEC_WINNT_AUTH_IDENTITY_OPAQUE value=nullptr;
    ~Identity() { SspiFreeAuthIdentity(value); }
};
struct SspiLibrary {
    HMODULE module=LoadLibraryExW(L"sspicli.dll",nullptr,LOAD_LIBRARY_SEARCH_SYSTEM32);
    ~SspiLibrary() { if (module) FreeLibrary(module); }
};
bool stringAt(std::span<const unsigned char> data,size_t offset,size_t length,std::wstring_view expected) {
    return offset<=data.size() && length<=data.size()-offset && length==expected.size()*sizeof(wchar_t) &&
        memcmp(data.data()+offset,expected.data(),length)==0;
}
}
int wmain() {
    try {
        // Reserved .invalid domain; this test never attempts to authenticate it.
        const std::wstring account=L"MicrosoftAccount\\fixture@example.invalid";
        const wchar_t* dummy=L"Fixture \u00e9 \u03a9 \u4e2d ! password";
        auto packed=swa::packWindowsCredential(account,dummy);
        check(packed.size()>=sizeof(SEC_WINNT_AUTH_IDENTITY_EX2),"online-identity header present");
        SEC_WINNT_AUTH_IDENTITY_EX2 header{};
        memcpy(&header,packed.data(),sizeof(header));
        check(header.Version==SEC_WINNT_AUTH_IDENTITY_VERSION_2,"online identity uses EX2, not a legacy interactive logon buffer");
        check((header.Flags&SEC_WINNT_AUTH_IDENTITY_FLAGS_ID_PROVIDER)!=0,"online identity provider flag preserved");
        check((header.Flags&(SEC_WINNT_AUTH_IDENTITY_FLAGS_USER_PROTECTED|SEC_WINNT_AUTH_IDENTITY_FLAGS_SYSTEM_PROTECTED))!=0,
            "Windows protects the packed credential for the current logon session");
        wchar_t username[1024]{},domain[1024]{};
        swa::Secret password(8192);
        DWORD userSize=1024,domainSize=1024,passwordSize=4096;
        check(CredUnPackAuthenticationBufferW(CRED_PACK_PROTECTED_CREDENTIALS,packed.data(),static_cast<DWORD>(packed.size()),
            username,&userSize,domain,&domainSize,reinterpret_cast<PWSTR>(password.data()),&passwordSize)!=FALSE,
            "Windows can unpack its protected online-identity format");
        // EX2 unpacking returns marshaled strings, not a plaintext password.
        // The old host's UnPack -> LogonUser conversion lost that distinction.
        check(wcscmp(reinterpret_cast<const wchar_t*>(password.data()),dummy)!=0,
            "unpacked online-identity strings cannot be treated as plaintext passwords");
        Identity identity;
        check(SspiUnmarshalAuthIdentity(static_cast<ULONG>(packed.size()),reinterpret_cast<char*>(packed.data()),&identity.value)==SEC_E_OK,
            "Windows validates and decodes its complete identity buffer");
        SspiLibrary library;
        check(library.module!=nullptr,"system SSPI library loaded");
        const auto decrypt=reinterpret_cast<decltype(&SspiDecryptAuthIdentityEx)>(GetProcAddress(library.module,"SspiDecryptAuthIdentityEx"));
        check(decrypt!=nullptr,"documented SSPI decryption entry point available");
        check(decrypt(SEC_WINNT_AUTH_IDENTITY_ENCRYPT_SAME_LOGON,identity.value)==SEC_E_OK,
            "Windows decrypts the test identity in the correct logon session");
        const auto clear=reinterpret_cast<const SEC_WINNT_AUTH_IDENTITY_EX2*>(identity.value);
        const std::span<const unsigned char> clearBytes{reinterpret_cast<const unsigned char*>(clear),clear->cbStructureLength};
        check(clearBytes.size()<=packed.size() && clearBytes.size()>=sizeof(*clear),"decoded identity size is bounded");
        check(stringAt(clearBytes,clear->UserOffset,clear->UserLength,L"fixture@example.invalid") &&
            stringAt(clearBytes,clear->DomainOffset,clear->DomainLength,L"MicrosoftAccount"),"Microsoft identity is preserved exactly");
        check(clear->PackedCredentialsOffset<=clearBytes.size() && clear->PackedCredentialsLength<=clearBytes.size()-clear->PackedCredentialsOffset &&
            clear->PackedCredentialsLength>=sizeof(SEC_WINNT_AUTH_PACKED_CREDENTIALS),"password credential header is bounded");
        const auto credentials=clearBytes.subspan(clear->PackedCredentialsOffset,clear->PackedCredentialsLength);
        SEC_WINNT_AUTH_PACKED_CREDENTIALS credential{};
        memcpy(&credential,credentials.data(),sizeof(credential));
        check(credential.AuthData.CredType==SEC_WINNT_AUTH_DATA_TYPE_PASSWORD,"credential type remains password");
        check(stringAt(credentials,credential.AuthData.CredData.ByteArrayOffset,credential.AuthData.CredData.ByteArrayLength,dummy),
            "Unicode and punctuation in the password survive unchanged");
        bool rejected=false;
        try { auto invalid=swa::packWindowsCredential(L"example.invalid",dummy); } catch (const std::invalid_argument&) { rejected=true; }
        check(rejected,"unqualified identities are rejected before any logon attempt");
        std::cout << "No account authentication or enrollment was attempted." << std::endl;
        return 0;
    } catch (const std::exception& error) { std::cerr << "FAILED: " << error.what() << std::endl; return 1; }
}
