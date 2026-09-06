#include "recovery_usb.h"
#include <bcrypt.h>
#include <sddl.h>
#include <shlobj.h>
#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace swa::recovery {
namespace {
constexpr std::array<BYTE,8> Magic{'S','W','A','U','S','B',1,0};
constexpr size_t KeySize = 56;
struct Material {
    std::array<BYTE, KeySize> data{};
    ~Material() { SecureZeroMemory(data.data(), data.size()); }
};
struct Handle {
    HANDLE value = INVALID_HANDLE_VALUE;
    ~Handle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
struct Key {
    HKEY value = nullptr;
    ~Key() { if (value) RegCloseKey(value); }
};
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
std::wstring usbPath(const wchar_t* path, bool directory) {
    const std::wstring input(path ? path : L"");
    require(input.size() >= 3 && input[1] == L':' && input[2] == L'\\' &&
        ((input[0] >= L'A' && input[0] <= L'Z') || (input[0] >= L'a' && input[0] <= L'z')) &&
        input.find(L':', 2) == std::wstring::npos, "Supply a local USB drive path.");
    wchar_t full[32768]{};
    const DWORD count = GetFullPathNameW(input.c_str(), static_cast<DWORD>(std::size(full)), full, nullptr);
    require(count && count < std::size(full), "Invalid USB path.");
    std::wstring result(full);
    while (result.size() > 3 && result.back() == L'\\') result.pop_back();
    const auto root = result.substr(0,3);
    require(GetDriveTypeW(root.c_str()) == DRIVE_REMOVABLE, "The recovery credential must be on a removable USB drive.");
    for (size_t end=3; end<=result.size(); ++end) {
        if (end != result.size() && result[end] != L'\\') continue;
        if (!directory && end == result.size()) break;
        const auto attributes=GetFileAttributesW(result.substr(0,end).c_str());
        require(attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) &&
            !(attributes & FILE_ATTRIBUTE_REPARSE_POINT), "USB path is missing or traverses a reparse point.");
    }
    return result;
}
void readKey(const wchar_t* path, Material& material) {
    const auto full=usbPath(path,false);
    Handle file;
    file.value=CreateFileW(full.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    require(file.value != INVALID_HANDLE_VALUE, "Insert the paired recovery USB. Its private credential was not found.");
    BY_HANDLE_FILE_INFORMATION information{};
    require(GetFileInformationByHandle(file.value,&information) && !information.nFileSizeHigh &&
        information.nFileSizeLow == KeySize && !(information.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY)),
        "The recovery credential is not a valid regular file.");
    DWORD read=0;
    require(ReadFile(file.value,material.data.data(),static_cast<DWORD>(material.data.size()),&read,nullptr) && read==KeySize,
        "The recovery credential could not be read completely.");
}
Digest expected(HKEY software) {
    std::array<BYTE,40> record{};
    DWORD size=static_cast<DWORD>(record.size());
    require(RegGetValueW(software,PairingPath,L"Pairing",RRF_RT_REG_BINARY,nullptr,record.data(),&size)==ERROR_SUCCESS &&
        size==record.size() && std::equal(Magic.begin(),Magic.end(),record.begin()),
        "Recovery pairing is missing or damaged. No sign-in settings were changed.");
    Digest digest{};
    std::copy_n(record.begin()+8,digest.size(),digest.begin());
    return digest;
}
}
Digest keyDigest(std::span<const BYTE> key) {
    require(key.size()==KeySize && std::equal(Magic.begin(),Magic.end(),key.begin()), "Invalid recovery credential format.");
    BCRYPT_ALG_HANDLE algorithm=nullptr;
    require(BCryptOpenAlgorithmProvider(&algorithm,BCRYPT_SHA256_ALGORITHM,nullptr,0)>=0,"Cannot open recovery hashing algorithm.");
    Digest result{};
    const auto status=BCryptHash(algorithm,nullptr,0,const_cast<PUCHAR>(key.data()),static_cast<ULONG>(key.size()),result.data(),static_cast<ULONG>(result.size()));
    BCryptCloseAlgorithmProvider(algorithm,0);
    require(status>=0,"Cannot verify recovery credential.");
    return result;
}
bool digestEqual(const Digest& left, const Digest& right) noexcept {
    volatile BYTE difference=0;
    for (size_t i=0;i<left.size();++i) difference=static_cast<BYTE>(difference | (left[i]^right[i]));
    return difference==0;
}
bool paired(HKEY software) {
    Key key;
    const auto result=RegOpenKeyExW(software,PairingPath,0,KEY_READ,&key.value);
    if (result==ERROR_FILE_NOT_FOUND || result==ERROR_PATH_NOT_FOUND) return false;
    require(result==ERROR_SUCCESS,"Cannot inspect recovery pairing.");
    return true;
}
void authorize(HKEY software, const wchar_t* keyFile) {
    const auto verifier=expected(software);
    require(keyFile && keyFile[0],"This Windows installation requires its paired recovery USB.");
    Material material;
    readKey(keyFile,material);
    require(digestEqual(keyDigest(material.data),verifier),"This is not the recovery USB paired with this Windows installation.");
}
void pairUsb(const wchar_t* directory) {
    require(IsUserAnAdmin()!=FALSE,"Pairing a recovery USB requires administrator access.");
    Key pe;
    require(RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Control\\MiniNT",0,KEY_READ,&pe.value)==ERROR_FILE_NOT_FOUND,
        "Pair the USB from the working Windows desktop, not a recovery environment.");
    Key software;
    // We create a child key; never request permission to set values on SOFTWARE.
    // Windows can reject that broader access even for an elevated administrator.
    const auto opened=RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE",0,KEY_READ|KEY_CREATE_SUB_KEY,&software.value);
    if(opened!=ERROR_SUCCESS) throw std::runtime_error("Cannot open Windows pairing configuration (Windows error "+std::to_string(opened)+").");
    require(!paired(software.value),"A recovery USB is already paired. It was not replaced.");
    const auto target=usbPath(directory,true)+L"\\recovery.key";
    Material material;
    require(BCryptGenRandom(nullptr,material.data.data(),static_cast<ULONG>(material.data.size()),BCRYPT_USE_SYSTEM_PREFERRED_RNG)>=0,
        "Cannot generate recovery credential.");
    std::copy(Magic.begin(),Magic.end(),material.data.begin());
    const auto digest=keyDigest(material.data);
    {
        Handle file;
        file.value=CreateFileW(target.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH,nullptr);
        require(file.value!=INVALID_HANDLE_VALUE,"Cannot create the new USB credential. Existing files were not overwritten.");
        DWORD written=0;
        require(WriteFile(file.value,material.data.data(),static_cast<DWORD>(material.data.size()),&written,nullptr) && written==KeySize &&
            FlushFileBuffers(file.value),"USB credential write failed. Windows pairing was not changed.");
    }
    Material checked;
    readKey(target.c_str(),checked);
    require(digestEqual(keyDigest(checked.data),digest),"USB read-back verification failed. Windows pairing was not changed.");
    PSECURITY_DESCRIPTOR descriptor=nullptr;
    require(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)",SDDL_REVISION_1,&descriptor,nullptr),
        "Cannot protect recovery pairing configuration.");
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES),descriptor,FALSE};
    Key pairing;
    DWORD disposition=0;
    const auto created=RegCreateKeyExW(software.value,PairingPath,0,nullptr,0,KEY_READ|KEY_WRITE,&attributes,&pairing.value,&disposition);
    LocalFree(descriptor);
    require(created==ERROR_SUCCESS && disposition==REG_CREATED_NEW_KEY,"Recovery pairing already exists or could not be created.");
    std::array<BYTE,40> record{};
    std::copy(Magic.begin(),Magic.end(),record.begin());
    std::copy(digest.begin(),digest.end(),record.begin()+8);
    require(RegSetValueExW(pairing.value,L"Pairing",0,REG_BINARY,record.data(),static_cast<DWORD>(record.size()))==ERROR_SUCCESS &&
        RegFlushKey(pairing.value)==ERROR_SUCCESS,"Pairing record could not be saved. Keep the USB credential and diagnose before retrying.");
    authorize(software.value,target.c_str());
    std::cout<<"Recovery USB paired and read-back verified. Only its verifier was stored on the PC.\n"
        <<"No PIN, key enrollment, sign-in filter or encryption setting was changed.\n";
}
void checkLiveUsb(const wchar_t* keyFile) {
    Key software;
    require(RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE",0,KEY_READ,&software.value)==ERROR_SUCCESS,"Cannot inspect Windows pairing.");
    authorize(software.value,keyFile);
    std::cout<<"The recovery USB matches this Windows installation. No settings were changed.\n";
}
void selfTestUsb() {
    Material first;
    std::copy(Magic.begin(),Magic.end(),first.data.begin());
    require(BCryptGenRandom(nullptr,first.data.data()+8,static_cast<ULONG>(first.data.size()-8),BCRYPT_USE_SYSTEM_PREFERRED_RNG)>=0,"Fixture generation failed.");
    const auto expectedDigest=keyDigest(first.data);
    require(digestEqual(expectedDigest,keyDigest(first.data)),"Matching credential rejected.");
    first.data.back()^=1;
    require(!digestEqual(expectedDigest,keyDigest(first.data)),"Modified credential accepted.");
    for (size_t length : {size_t{0},size_t{8},size_t{55}}) {
        bool rejected=false;
        try { (void)keyDigest(std::span<const BYTE>(first.data.data(),length)); } catch (const std::runtime_error&) { rejected=true; }
        require(rejected,"Truncated credential accepted.");
    }
    first.data.front()^=1;
    bool rejected=false;
    try { (void)keyDigest(first.data); } catch (const std::runtime_error&) { rejected=true; }
    require(rejected,"Unknown credential version accepted.");
    std::cout<<"PASS matching, modified, truncated and unknown-format USB credentials\n";
}
}
