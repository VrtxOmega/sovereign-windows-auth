#include "windows_auth.h"
#include <ntsecapi.h>
#include <wincred.h>
#include <iomanip>
#include <sstream>

namespace swa {
namespace {
std::string statusText(NTSTATUS status) {
    std::ostringstream text;
    text << "0x" << std::hex << std::setw(8) << std::setfill('0') << static_cast<ULONG>(status);
    return text.str();
}
class Lsa final {
public:
    LSA_HANDLE handle=nullptr;
    Lsa() {
        const auto status=LsaConnectUntrusted(&handle);
        if (status<0) throw std::runtime_error("Windows authentication connection failed: "+statusText(status));
    }
    ~Lsa() { if (handle) LsaDeregisterLogonProcess(handle); }
    Lsa(const Lsa&)=delete;
    Lsa& operator=(const Lsa&)=delete;
};
struct LogonResult {
    HANDLE token=nullptr;
    void* profile=nullptr;
    ULONG profileSize=0;
    ~LogonResult() {
        if (token) CloseHandle(token);
        if (profile) { SecureZeroMemory(profile,profileSize); LsaFreeReturnBuffer(profile); }
    }
};
}
ULONG windowsAuthenticationPackage() {
    Lsa lsa;
    char name[]="Negotiate";
    LSA_STRING identity{static_cast<USHORT>(sizeof(name)-1),static_cast<USHORT>(sizeof(name)),name};
    ULONG package=0;
    const auto status=LsaLookupAuthenticationPackage(lsa.handle,&identity,&package);
    if (status<0) throw std::runtime_error("Windows authentication package lookup failed: "+statusText(status));
    return package;
}
Secret packWindowsCredential(const std::wstring& account,const wchar_t* password) {
    if (!account.starts_with(L"MicrosoftAccount\\") || account.size()<=17 || account.size()>1024 || !password)
        throw std::invalid_argument("Invalid Microsoft-account credential input");
    constexpr DWORD flags=CRED_PACK_PROTECTED_CREDENTIALS|CRED_PACK_ID_PROVIDER_CREDENTIALS;
    DWORD size=0;
    const auto user=const_cast<PWSTR>(account.c_str());
    const auto clear=const_cast<PWSTR>(password);
    if (CredPackAuthenticationBufferW(flags,user,clear,nullptr,&size) || GetLastError()!=ERROR_INSUFFICIENT_BUFFER || size==0 || size>65536)
        throw std::runtime_error("Windows online-identity sizing failed");
    Secret buffer(size);
    if (!CredPackAuthenticationBufferW(flags,user,clear,buffer.data(),&size))
        throw std::runtime_error("Windows online-identity packing failed (Win32 "+std::to_string(GetLastError())+")");
    if (size!=buffer.size()) throw std::runtime_error("Windows online-identity size changed");
    return buffer;
}
std::wstring authenticateWindowsBuffer(ULONG package,std::span<const unsigned char> buffer) {
    if (buffer.empty() || buffer.size()>65536) throw std::invalid_argument("Invalid Windows authentication buffer size");
    Lsa lsa;
    char originText[]="SovereignAuth";
    LSA_STRING origin{static_cast<USHORT>(sizeof(originText)-1),static_cast<USHORT>(sizeof(originText)),originText};
    TOKEN_SOURCE source{};
    memcpy(source.SourceName,"SWAAuth",7);
    if (!AllocateLocallyUniqueId(&source.SourceIdentifier)) throw std::runtime_error("Cannot identify authentication request");
    LogonResult result;
    LUID id{}; QUOTA_LIMITS quotas{}; NTSTATUS substatus=0;
    const auto status=LsaLogonUser(lsa.handle,&origin,Interactive,package,
        const_cast<unsigned char*>(buffer.data()),static_cast<ULONG>(buffer.size()),nullptr,&source,
        &result.profile,&result.profileSize,&id,&result.token,&quotas,&substatus);
    if (status<0) throw std::runtime_error("Windows online-identity authentication failed (status "+statusText(status)+
        ", substatus "+statusText(substatus)+", Win32 "+std::to_string(LsaNtStatusToWinError(status))+"). No retry or profile change.");
    if (!result.token) throw std::runtime_error("Windows returned success without an authenticated user token");
    return tokenSid(result.token);
}
void validateWindowsCredential(const std::wstring& account,const wchar_t* password,const std::wstring& expectedSid) {
    auto buffer=packWindowsCredential(account,password);
    const auto authenticated=authenticateWindowsBuffer(windowsAuthenticationPackage(),buffer.view());
    if (authenticated!=expectedSid) throw std::runtime_error("Windows authenticated a different user; enrollment rejected");
}
}
