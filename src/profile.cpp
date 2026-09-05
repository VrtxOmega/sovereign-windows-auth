#include "core.h"
#include <wincrypt.h>
#include <sddl.h>
#include <shlobj.h>
#include <aclapi.h>
#include <algorithm>
#include <limits>

namespace swa {
namespace {
void need(bool ok, const char* message) { if (!ok) throw std::runtime_error(message); }
void put32(Bytes& out, size_t number) {
    need(number <= 65536,"Length exceeds profile limit");
    for (unsigned i=0;i<4;++i) out.push_back(static_cast<unsigned char>((number >> (8*i)) & 0xff));
}
void putBytes(Bytes& out, std::span<const unsigned char> bytes) {
    out.insert(out.end(),bytes.begin(),bytes.end());
}
void putString(Bytes& out, const std::wstring& value) {
    need(!value.empty() && value.size()<=512 && value.find(L'\0')==std::wstring::npos,"Invalid identity string");
    put32(out,value.size());
    putBytes(out,{reinterpret_cast<const unsigned char*>(value.data()),value.size()*sizeof(wchar_t)});
}
struct Reader {
    std::span<const unsigned char> data;
    size_t position=0;
    std::span<const unsigned char> take(size_t n) {
        need(position<=data.size() && n<=data.size()-position,"Truncated account profile");
        auto result=data.subspan(position,n); position+=n; return result;
    }
    uint32_t number() {
        auto bytes=take(4); uint32_t result=0;
        for (unsigned i=0;i<4;++i) result |= static_cast<uint32_t>(bytes[i]) << (8*i);
        return result;
    }
    std::wstring string() {
        auto n=number(); need(n>0 && n<=512,"Invalid identity length");
        auto bytes=take(static_cast<size_t>(n)*2);
        std::wstring result(n,L'\0'); memcpy(result.data(),bytes.data(),bytes.size());
        need(result.find(L'\0')==std::wstring::npos,"Embedded identity terminator");
        return result;
    }
};
void validateSid(const std::wstring& sid) {
    PSID value=nullptr;
    need(ConvertStringSidToSidW(sid.c_str(),&value)!=FALSE,"Invalid account SID");
    const bool valid=IsValidSid(value)!=FALSE;
    LPWSTR canonical=nullptr;
    const bool converted=ConvertSidToStringSidW(value,&canonical)!=FALSE;
    const bool exact=converted && sid==canonical;
    LocalFree(value); if (canonical) LocalFree(canonical);
    need(valid && exact,"Noncanonical SID");
}
struct LocalBlob {
    DATA_BLOB value{};
    ~LocalBlob() { if (value.pbData) { SecureZeroMemory(value.pbData,value.cbData); LocalFree(value.pbData); } }
};
struct Handle {
    HANDLE value=INVALID_HANDLE_VALUE;
    explicit Handle(HANDLE v) : value(v) {}
    ~Handle() { if (value!=INVALID_HANDLE_VALUE && value) CloseHandle(value); }
};
void trustedPath(const std::filesystem::path& path) {
    const DWORD attributes=GetFileAttributesW(path.c_str());
    need(attributes!=INVALID_FILE_ATTRIBUTES && !(attributes&FILE_ATTRIBUTE_REPARSE_POINT),"Missing or redirected protected path");
    PSID owner=nullptr; PACL acl=nullptr; PSECURITY_DESCRIPTOR descriptor=nullptr;
    need(GetNamedSecurityInfoW(path.c_str(),SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,
        &owner,nullptr,&acl,nullptr,&descriptor)==ERROR_SUCCESS,"Cannot inspect protected path permissions");
    bool trusted=owner && (IsWellKnownSid(owner,WinBuiltinAdministratorsSid) || IsWellKnownSid(owner,WinLocalSystemSid));
    SECURITY_DESCRIPTOR_CONTROL control=0; DWORD revision=0;
    trusted=trusted && GetSecurityDescriptorControl(descriptor,&control,&revision) && (control&SE_DACL_PROTECTED) && acl;
    if (trusted) {
        for (DWORD i=0;i<acl->AceCount;++i) {
            void* raw=nullptr;
            if (!GetAce(acl,i,&raw) || static_cast<ACE_HEADER*>(raw)->AceType!=ACCESS_ALLOWED_ACE_TYPE) { trusted=false; break; }
            auto ace=static_cast<ACCESS_ALLOWED_ACE*>(raw);
            PSID principal=&ace->SidStart;
            if (!IsWellKnownSid(principal,WinBuiltinAdministratorsSid) && !IsWellKnownSid(principal,WinLocalSystemSid)) { trusted=false; break; }
        }
    }
    LocalFree(descriptor);
    need(trusted,"Protected path must be owned by SYSTEM/Administrators with access restricted to those identities");
}
}
Bytes profileBinding(const AccountProfile& profile) {
    validateSid(profile.sid);
    need(profile.account.rfind(L"MicrosoftAccount\\",0)==0,"This prototype supports Microsoft accounts only");
    need(profile.key.credential.size()>=16 && profile.key.credential.size()<=2048,"Invalid credential length");
    need(profile.kind==CredentialKind::MicrosoftPassword || profile.kind==CredentialKind::WindowsPin,"Unknown credential kind");
    Bytes out{'S','W','A',static_cast<unsigned char>(profile.kind)};
    putString(out,profile.sid); putString(out,profile.account);
    put32(out,profile.key.credential.size()); putBytes(out,profile.key.credential);
    putBytes(out,profile.key.publicKey); putBytes(out,profile.key.salt);
    return out;
}
Bytes encodeProfile(const AccountProfile& profile) {
    if (!profile.additional.empty()) {
        need(profile.additional.size()<8,"Too many enrolled keys");
        Bytes out{'S','W','M',2};
        put32(out,profile.additional.size()+1);
        std::vector<Bytes> identities;
        for (size_t i=0;i<=profile.additional.size();++i) {
            auto record=profileForKey(profile,i);
            for (const auto& id:identities) need(!equal(id,record.key.credential),"Duplicate enrolled key credential");
            identities.push_back(record.key.credential);
            auto encoded=encodeProfile(record);
            put32(out,encoded.size()); putBytes(out,encoded);
        }
        need(out.size()<=60000,"Multi-key profile exceeds size limit");
        return out;
    }
    auto binding=profileBinding(profile);
    need(!profile.password.ciphertext.empty() && profile.password.ciphertext.size()<=8192,"Invalid encrypted credential size");
    Bytes out;
    put32(out,binding.size()); putBytes(out,binding);
    putBytes(out,profile.password.nonce); putBytes(out,profile.password.tag);
    put32(out,profile.password.ciphertext.size()); putBytes(out,profile.password.ciphertext);
    return out;
}
AccountProfile decodeProfile(std::span<const unsigned char> bytes) {
    if (bytes.size()>=4 && equal(bytes.first(4),Bytes{'S','W','M',2})) {
        need(bytes.size()<=60000,"Multi-key profile exceeds size limit");
        Reader outer{bytes}; outer.take(4);
        const auto count=outer.number(); need(count>=2 && count<=8,"Invalid enrolled key count");
        AccountProfile result;
        for (uint32_t i=0;i<count;++i) {
            const auto length=outer.number(); need(length>4 && length<=16384,"Invalid key record length");
            auto recordBytes=outer.take(length);
            need(!equal(recordBytes.first(4),Bytes{'S','W','M',2}),"Nested multi-key profiles are not allowed");
            auto record=decodeProfile(recordBytes);
            if (i==0) result=std::move(record);
            else {
                need(record.sid==result.sid && record.account==result.account && record.kind==result.kind,"Multi-key profile crosses identities or credential kinds");
                result.additional.push_back({std::move(record.key),std::move(record.password)});
            }
        }
        need(outer.position==bytes.size(),"Trailing multi-key profile data");
        need(equal(encodeProfile(result),bytes),"Noncanonical multi-key profile");
        return result;
    }
    need(bytes.size()<=16384,"Account profile exceeds size limit");
    Reader outer{bytes}; auto bindingSize=outer.number();
    need(bindingSize<=8192,"Account binding exceeds size limit");
    Reader binding{outer.take(bindingSize)};
    const auto magic=binding.take(4);
    need(equal(magic.first(3),Bytes{'S','W','A'}) && (magic[3]==1 || magic[3]==2),"Unknown account profile version");
    AccountProfile profile;
    profile.kind=static_cast<CredentialKind>(magic[3]);
    profile.sid=binding.string(); profile.account=binding.string();
    auto credSize=binding.number(); need(credSize>=16 && credSize<=2048,"Invalid credential size");
    auto credential=binding.take(credSize); profile.key.credential.assign(credential.begin(),credential.end());
    auto publicKey=binding.take(64); std::copy(publicKey.begin(),publicKey.end(),profile.key.publicKey.begin());
    auto salt=binding.take(32); std::copy(salt.begin(),salt.end(),profile.key.salt.begin());
    need(binding.position==binding.data.size(),"Trailing account binding data");
    need(equal(profileBinding(profile),binding.data),"Noncanonical account binding");
    auto nonce=outer.take(12); std::copy(nonce.begin(),nonce.end(),profile.password.nonce.begin());
    auto tag=outer.take(16); std::copy(tag.begin(),tag.end(),profile.password.tag.begin());
    auto cipherSize=outer.number(); need(cipherSize>0 && cipherSize<=8192,"Invalid encrypted password length");
    auto ciphertext=outer.take(cipherSize); profile.password.ciphertext.assign(ciphertext.begin(),ciphertext.end());
    need(outer.position==bytes.size(),"Trailing encrypted profile data");
    return profile;
}
AccountProfile profileForKey(const AccountProfile& profile,size_t index) {
    need(index<=profile.additional.size(),"Invalid enrolled key index");
    AccountProfile result;
    result.sid=profile.sid; result.account=profile.account; result.kind=profile.kind;
    result.key=index==0 ? profile.key : profile.additional[index-1].key;
    result.password=index==0 ? profile.password : profile.additional[index-1].password;
    return result;
}
Secret unlockAccount(const AccountProfile& profile,int timeoutMs) {
    std::vector<KeyProfile> keys{profile.key};
    for (const auto& record:profile.additional) keys.push_back(record.key);
    auto proof=touchAnyKey(keys,timeoutMs);
    auto record=profileForKey(profile,proof.index);
    return unseal(proof.secret.view(),record.password,profileBinding(record));
}
std::wstring tokenSid(HANDLE token) {
    DWORD bytes=0;
    GetTokenInformation(token,TokenUser,nullptr,0,&bytes);
    need(bytes>0 && bytes<=65536,"Cannot query token identity");
    Bytes buffer(bytes);
    need(GetTokenInformation(token,TokenUser,buffer.data(),bytes,&bytes)!=FALSE,"Cannot read token identity");
    auto info=reinterpret_cast<TOKEN_USER*>(buffer.data());
    LPWSTR text=nullptr;
    need(ConvertSidToStringSidW(info->User.Sid,&text)!=FALSE,"Cannot format token SID");
    std::wstring result(text); LocalFree(text); return result;
}
std::wstring currentSid() {
    HANDLE raw=nullptr;
    need(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&raw)!=FALSE,"Cannot open current token");
    Handle token(raw); return tokenSid(token.value);
}
std::filesystem::path profilePath(const std::wstring& sid) {
    validateSid(sid);
    PWSTR path=nullptr;
    need(SUCCEEDED(SHGetKnownFolderPath(FOLDERID_ProgramData,KF_FLAG_DEFAULT,nullptr,&path)),"Cannot locate ProgramData");
    std::filesystem::path result(path); CoTaskMemFree(path);
    return result / L"SovereignWindowsAuth" / (sid+L".swa");
}
void saveProfile(const AccountProfile& profile) {
    auto path=profilePath(profile.sid);
    PSECURITY_DESCRIPTOR descriptor=nullptr;
    need(ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",SDDL_REVISION_1,&descriptor,nullptr)!=FALSE,"Cannot create restricted ACL");
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES),descriptor,FALSE};
    bool created=CreateDirectoryW(path.parent_path().c_str(),&attributes)!=FALSE;
    auto error=GetLastError();
    if (!created && error!=ERROR_ALREADY_EXISTS) { LocalFree(descriptor); throw std::runtime_error("Cannot create profile directory"); }
    try { trustedPath(path.parent_path()); } catch (...) { LocalFree(descriptor); throw; }
    auto plain=encodeProfile(profile);
    DATA_BLOB input{static_cast<DWORD>(plain.size()),plain.data()};
    LocalBlob protectedData;
    if (!CryptProtectData(&input,L"Sovereign Windows authentication profile",nullptr,nullptr,nullptr,
        CRYPTPROTECT_LOCAL_MACHINE|CRYPTPROTECT_UI_FORBIDDEN,&protectedData.value)) {
        LocalFree(descriptor); throw std::runtime_error("Cannot bind encrypted profile to this Windows installation");
    }
    GUID nonce{};
    if (FAILED(CoCreateGuid(&nonce))) { LocalFree(descriptor); throw std::runtime_error("Cannot generate temporary file name"); }
    wchar_t suffix[40]{}; StringFromGUID2(nonce,suffix,40);
    auto temporary=path; temporary+=L".new-"+std::wstring(suffix);
    bool ownsTemporary=false;
    try {
        {
            Handle file(CreateFileW(temporary.c_str(),GENERIC_WRITE,0,&attributes,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr));
            LocalFree(descriptor); descriptor=nullptr;
            need(file.value!=INVALID_HANDLE_VALUE,"Cannot create restricted temporary profile");
            ownsTemporary=true;
            DWORD written=0;
            need(WriteFile(file.value,protectedData.value.pbData,protectedData.value.cbData,&written,nullptr)!=FALSE && written==protectedData.value.cbData,"Cannot write full profile");
            need(FlushFileBuffers(file.value)!=FALSE,"Cannot flush profile");
        }
        trustedPath(temporary);
        need(MoveFileExW(temporary.c_str(),path.c_str(),MOVEFILE_WRITE_THROUGH)!=FALSE,"Profile already exists or cannot be installed; no overwrite performed");
    } catch (...) {
        if (descriptor) LocalFree(descriptor);
        if (ownsTemporary) DeleteFileW(temporary.c_str());
        throw;
    }
}
AccountProfile loadProfile(const std::wstring& sid) {
    auto path=profilePath(sid);
    trustedPath(path.parent_path()); trustedPath(path);
    auto encrypted=readFile(path);
    DATA_BLOB input{static_cast<DWORD>(encrypted.size()),encrypted.data()};
    LocalBlob clear;
    need(CryptUnprotectData(&input,nullptr,nullptr,nullptr,nullptr,CRYPTPROTECT_UI_FORBIDDEN,&clear.value)!=FALSE,"Profile belongs to another Windows installation or is damaged");
    auto result=decodeProfile({clear.value.pbData,clear.value.cbData});
    need(result.sid==sid,"Profile belongs to a different Windows user");
    return result;
}
}
