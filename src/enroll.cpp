#include "core.h"
#include "windows_auth.h"
#include "windows_pin.h"
#include "current_user.h"
#include <lm.h>
#include <wincred.h>
#include <iostream>
#include <optional>

namespace {
std::wstring microsoftIdentity() {
    wchar_t username[UNLEN+1]{};
    DWORD count=UNLEN+1;
    if (!GetUserNameW(username,&count)) throw std::runtime_error("Cannot identify current Windows user");
    USER_INFO_24* info=nullptr;
    auto status=NetUserGetInfo(nullptr,username,24,reinterpret_cast<LPBYTE*>(&info));
    if (status!=NERR_Success || !info) throw std::runtime_error("Cannot query the linked Microsoft identity");
    std::wstring result;
    if (info->usri24_internet_identity && info->usri24_internet_principal_name)
        result=L"MicrosoftAccount\\"+std::wstring(info->usri24_internet_principal_name);
    NetApiBufferFree(info);
    if (result.empty()) throw std::runtime_error("Current user is not linked to a Microsoft identity");
    return result;
}
swa::Secret enrollKey(const swa::KeyProfile& key) {
    for (;;) {
        std::cout << "Waiting for the expected YubiKey. Touch it when it blinks." << std::endl;
        try { return swa::touchSecret(key); }
        catch (const std::exception& error) {
            std::cout << "Key request stopped: " << error.what() << std::endl;
            std::cout << "Reconnect this key and press Enter to retry it, or type q and Enter to cancel. No PIN re-entry is needed." << std::endl;
            std::wstring retry;
            if (!std::getline(std::wcin,retry) || !retry.empty()) throw std::runtime_error("Key enrollment canceled");
        }
    }
}
void enroll(const wchar_t* publicProfile,const wchar_t* secondPublicProfile,bool usePin) {
    swa::AccountProfile profile;
    profile.kind=usePin ? swa::CredentialKind::WindowsPin : swa::CredentialKind::MicrosoftPassword;
    profile.key=swa::parseTestProfile(swa::readFile(publicProfile,4096));
    profile.sid=swa::currentSid();
    profile.account=microsoftIdentity();
    std::optional<swa::KeyProfile> secondKey;
    if (secondPublicProfile) {
        secondKey=swa::parseTestProfile(swa::readFile(secondPublicProfile,4096));
        if (swa::equal(profile.key.credential,secondKey->credential)) throw std::runtime_error("The second key duplicates the first credential");
    }
    if (std::filesystem::exists(swa::profilePath(profile.sid)))
        throw std::runtime_error("A profile already exists. This enrollment tool will not overwrite it.");
    wchar_t username[CREDUI_MAX_USERNAME_LENGTH+1]{};
    if (wcscpy_s(username,profile.account.c_str())!=0) throw std::runtime_error("Account name is too long");
    swa::Secret password((CREDUI_MAX_PASSWORD_LENGTH+1)*sizeof(wchar_t));
    if (usePin) {
        auto users=swa::currentUserArray();
        swa::WindowsPin windows(users.Get(),profile.sid);
        password=swa::promptWindowsPin();
        auto serialized=windows.serialize(reinterpret_cast<PCWSTR>(password.data()));
        if (swa::authenticateWindowsBuffer(serialized.package,serialized.buffer.view())!=profile.sid)
            throw std::runtime_error("Windows PIN authenticated another user");
    } else {
    CREDUI_INFOW ui{};
    ui.cbSize=sizeof(ui);
    ui.pszCaptionText=L"Sovereign Windows sign-in - one-time enrollment";
    ui.pszMessageText=L"Enter your Microsoft account password once to bind Windows sign-in to your key. Daily sign-in will use touch. This is not your YubiKey PIN.";
    BOOL save=FALSE;
    auto status=CredUIPromptForCredentialsW(&ui,L"SovereignWindowsAuth",nullptr,0,
        username,static_cast<ULONG>(std::size(username)),reinterpret_cast<PWSTR>(password.data()),
        CREDUI_MAX_PASSWORD_LENGTH+1,&save,CREDUI_FLAGS_GENERIC_CREDENTIALS|CREDUI_FLAGS_DO_NOT_PERSIST|
        CREDUI_FLAGS_ALWAYS_SHOW_UI|CREDUI_FLAGS_KEEP_USERNAME|CREDUI_FLAGS_EXCLUDE_CERTIFICATES);
    if (status!=NO_ERROR) throw std::runtime_error("Enrollment dialog canceled or unavailable");
    if (profile.account!=username) throw std::runtime_error("Enrollment identity was changed");
    }
    const auto clear=reinterpret_cast<const wchar_t*>(password.data());
    const auto capacity=password.size()/sizeof(wchar_t);
    const size_t length=wcsnlen_s(clear,capacity);
    if (length==0 || length>=capacity) throw std::runtime_error("Empty or invalid Windows credential");
    if (!usePin) swa::validateWindowsCredential(profile.account,clear,profile.sid);
    std::cout << "Windows accepted your credential. Connect the FIRST YubiKey, then press Enter." << std::endl;
    std::wstring confirmation;
    if (!std::getline(std::wcin,confirmation)) throw std::runtime_error("Enrollment canceled");
    std::cout << "Touch the first key to encrypt the profile." << std::endl;
    auto secret=enrollKey(profile.key);
    auto binding=swa::profileBinding(profile);
    const std::span<const unsigned char> passwordBytes{password.data(),(length+1)*sizeof(wchar_t)};
    profile.password=swa::seal(secret.view(),passwordBytes,binding);
    auto check=swa::unseal(secret.view(),profile.password,binding);
    if (!swa::equal(check.view(),passwordBytes)) throw std::runtime_error("Encrypted profile verification failed");
    check.clear(); secret.clear();
    if (secondKey) {
        std::cout << "Disconnect the first key. Connect the SECOND YubiKey, then press Enter." << std::endl;
        if (!std::getline(std::wcin,confirmation)) throw std::runtime_error("Second-key enrollment canceled");
        std::cout << "Touch the second key to give it independent access." << std::endl;
        auto secondSecret=enrollKey(*secondKey);
        swa::AccountProfile secondRecord;
        secondRecord.sid=profile.sid; secondRecord.account=profile.account; secondRecord.key=*secondKey; secondRecord.kind=profile.kind;
        secondRecord.password=swa::seal(secondSecret.view(),passwordBytes,swa::profileBinding(secondRecord));
        auto secondCheck=swa::unseal(secondSecret.view(),secondRecord.password,swa::profileBinding(secondRecord));
        if (!swa::equal(secondCheck.view(),passwordBytes)) throw std::runtime_error("Second key profile verification failed");
        profile.additional.push_back({secondRecord.key,secondRecord.password});
    }
    password.clear();
    swa::saveProfile(profile);
    auto reloaded=swa::loadProfile(profile.sid);
    if (!swa::equal(swa::encodeProfile(profile),swa::encodeProfile(reloaded))) throw std::runtime_error("Saved profile verification failed");
    std::cout << "Encrypted, machine-bound profile saved with SYSTEM/Administrators access. Sign-in provider is not installed by this tool." << std::endl;
}
void verifySaved() {
    auto profile=swa::loadProfile(swa::currentSid());
    std::cout << "Touch the key to verify the saved profile against Windows. No password entry." << std::endl;
    auto password=swa::unlockAccount(profile);
    if (password.size()<4 || password.size()%2 || reinterpret_cast<const wchar_t*>(password.data())[password.size()/2-1]!=0)
        throw std::runtime_error("Invalid decrypted Windows credential encoding");
    if (profile.kind==swa::CredentialKind::WindowsPin) {
        auto users=swa::currentUserArray();
        swa::WindowsPin windows(users.Get(),profile.sid);
        auto serialized=windows.serialize(reinterpret_cast<PCWSTR>(password.data()));
        if (swa::authenticateWindowsBuffer(serialized.package,serialized.buffer.view())!=profile.sid)
            throw std::runtime_error("Windows PIN authenticated another user");
    } else swa::validateWindowsCredential(profile.account,reinterpret_cast<const wchar_t*>(password.data()),profile.sid);
    std::cout << "PASS: touch alone decrypted the profile and Windows authenticated the expected user. Desktop unlock remains a separate test." << std::endl;
}
}
int wmain(int argc,wchar_t** argv) {
    const HRESULT initialized=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
    if (FAILED(initialized)) return 1;
    struct Apartment { ~Apartment() { CoUninitialize(); } } apartment;
    try {
        if (argc==2 && std::wstring_view(argv[1])==L"--identity") {
            std::wcout << microsoftIdentity() << L'\n'; return 0;
        }
        if ((argc==3 || argc==4) && (std::wstring_view(argv[1])==L"--enroll" || std::wstring_view(argv[1])==L"--enroll-pin")) {
            enroll(argv[2],argc==4 ? argv[3] : nullptr,std::wstring_view(argv[1])==L"--enroll-pin"); return 0;
        }
        if (argc==2 && std::wstring_view(argv[1])==L"--verify") { verifySaved(); return 0; }
        std::cerr << "Usage: swa_enroll --identity | --enroll-pin first.swt second.swt | --enroll first.swt [second.swt] | --verify\n";
        return 2;
    } catch (const std::exception& error) {
        std::cerr << "FAILED: " << error.what() << '\n'; return 1;
    }
}
