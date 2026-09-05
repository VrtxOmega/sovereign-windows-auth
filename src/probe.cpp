#include "core.h"
#include <iostream>
#include <functional>
#include <fstream>

namespace {
void check(bool ok, const char* label) {
    if (!ok) throw std::runtime_error(label);
    std::cout << "PASS " << label << '\n';
}
void rejected(const char* label, const std::function<void()>& operation) {
    bool failed = false;
    try { operation(); } catch (const std::exception&) { failed = true; }
    check(failed,label);
}
void cryptoTests(std::span<const unsigned char> first, std::span<const unsigned char> second) {
    const swa::Bytes data = {'t','e','s','t',' ','d','a','t','a'};
    const swa::Bytes aad = {'S','W','A',1,'t','e','s','t'};
    auto encrypted = swa::seal(first,data,aad);
    auto decrypted = swa::unseal(second,encrypted,aad);
    check(swa::equal(decrypted.view(),data), "AES-GCM round trip with authenticated binding");
    rejected("wrong encryption key rejected", [&] { auto unused = swa::unseal(swa::randomBytes(32),encrypted,aad); });
    auto bad = encrypted;
    bad.tag[0] ^= 1;
    rejected("modified tag rejected", [&] { auto unused = swa::unseal(second,bad,aad); });
    bad = encrypted;
    bad.ciphertext[0] ^= 1;
    rejected("modified ciphertext rejected", [&] { auto unused = swa::unseal(second,bad,aad); });
    bad = encrypted;
    bad.nonce[0] ^= 1;
    rejected("modified nonce rejected", [&] { auto unused = swa::unseal(second,bad,aad); });
    auto otherBinding = aad;
    otherBinding[0] ^= 1;
    rejected("modified profile binding rejected", [&] { auto unused = swa::unseal(second,encrypted,otherBinding); });
    rejected("short encryption key rejected", [&] { auto unused = swa::unseal(second.first(16),encrypted,aad); });
}
void selfTest() {
    auto key = swa::randomBytes(32);
    cryptoTests(key,key);
    swa::Bytes valid{'S','W','T',1,16,0,0,0};
    valid.resize(8+16+64+32,0x42);
    check(swa::parseTestProfile(valid).credential.size()==16,"bounded profile parses");
    for (size_t i=0; i<valid.size(); ++i) {
        bool failed = false;
        try { auto unused = swa::parseTestProfile({valid.data(),i}); } catch (const std::exception&) { failed=true; }
        if (!failed) throw std::runtime_error("Truncated profile accepted");
    }
    check(true,"all truncated profile lengths rejected");
    valid.push_back(0);
    rejected("trailing profile data rejected", [&] { auto unused = swa::parseTestProfile(valid); });
    valid[4]=0xff; valid[5]=0xff; valid[6]=0xff; valid[7]=0xff;
    rejected("oversized credential rejected", [&] { auto unused = swa::parseTestProfile(valid); });
    swa::AccountProfile account;
    account.sid=L"S-1-5-21-1-2-3-1001";
    account.account=L"MicrosoftAccount\\fixture@example.invalid";
    account.key.credential=swa::Bytes(32,0x32);
    const swa::Bytes dummyPassword{'d',0,'u',0,'m',0,'m',0,'y',0,0,0};
    account.password=swa::seal(key,dummyPassword,swa::profileBinding(account));
    auto encoded=swa::encodeProfile(account);
    auto decoded=swa::decodeProfile(encoded);
    check(swa::equal(encoded,swa::encodeProfile(decoded)),"account profile round trip");
    auto recovered=swa::unseal(key,decoded.password,swa::profileBinding(decoded));
    check(swa::equal(recovered.view(),dummyPassword),"account profile decrypts with matching binding");
    for (size_t i=0;i<encoded.size();++i) {
        bool failed=false;
        try { auto unused=swa::decodeProfile({encoded.data(),i}); } catch (const std::exception&) { failed=true; }
        if (!failed) throw std::runtime_error("Truncated account profile accepted");
    }
    check(true,"all truncated account profile lengths rejected");
    auto other=decoded;
    other.sid=L"S-1-5-21-1-2-3-1002";
    rejected("cross-user credential substitution rejected",[&] { auto unused=swa::unseal(key,other.password,swa::profileBinding(other)); });
    other=decoded; other.account=L"MicrosoftAccount\\other@example.invalid";
    rejected("cross-account credential substitution rejected",[&] { auto unused=swa::unseal(key,other.password,swa::profileBinding(other)); });
    other=decoded; other.key.credential[0]^=1;
    rejected("credential handle substitution rejected",[&] { auto unused=swa::unseal(key,other.password,swa::profileBinding(other)); });
    other=decoded; other.key.publicKey[0]^=1;
    rejected("public key substitution rejected",[&] { auto unused=swa::unseal(key,other.password,swa::profileBinding(other)); });
    other=decoded; other.key.salt[0]^=1;
    rejected("hardware salt substitution rejected",[&] { auto unused=swa::unseal(key,other.password,swa::profileBinding(other)); });
    other=decoded; other.sid=L"..\\fixture";
    rejected("profile path traversal rejected",[&] { auto unused=swa::profileBinding(other); });
    auto trailing=encoded; trailing.push_back(0);
    rejected("account trailing data rejected",[&] { auto unused=swa::decodeProfile(trailing); });
    auto oversized=encoded; oversized[0]=0xff; oversized[1]=0xff;
    rejected("oversized binding rejected",[&] { auto unused=swa::decodeProfile(oversized); });
    auto secondRecord=account;
    secondRecord.key.credential[0]^=1;
    secondRecord.key.publicKey[0]^=1;
    auto secondKey=swa::randomBytes(32);
    secondRecord.password=swa::seal(secondKey,dummyPassword,swa::profileBinding(secondRecord));
    account.additional.push_back({secondRecord.key,secondRecord.password});
    auto multiBytes=swa::encodeProfile(account);
    auto multi=swa::decodeProfile(multiBytes);
    check(multi.additional.size()==1 && swa::equal(swa::encodeProfile(multi),multiBytes),"two-key profile round trip");
    auto firstRecord=swa::profileForKey(multi,0);
    auto backupRecord=swa::profileForKey(multi,1);
    check(swa::equal(swa::unseal(key,firstRecord.password,swa::profileBinding(firstRecord)).view(),dummyPassword),"first key independently unlocks the profile");
    check(swa::equal(swa::unseal(secondKey,backupRecord.password,swa::profileBinding(backupRecord)).view(),dummyPassword),"second key independently unlocks the profile");
    rejected("first secret cannot decrypt second key wrapping",[&] { auto unused=swa::unseal(key,backupRecord.password,swa::profileBinding(backupRecord)); });
    for (size_t i=0;i<multiBytes.size();++i) {
        bool failed=false;
        try { auto unused=swa::decodeProfile({multiBytes.data(),i}); } catch (const std::exception&) { failed=true; }
        if (!failed) throw std::runtime_error("Truncated two-key profile accepted");
    }
    check(true,"all truncated two-key profile lengths rejected");
    auto duplicate=account; duplicate.additional[0].key=account.key;
    rejected("duplicate key record rejected",[&] { auto unused=swa::encodeProfile(duplicate); });
    auto tooMany=multiBytes; tooMany[4]=9;
    rejected("excessive key count rejected",[&] { auto unused=swa::decodeProfile(tooMany); });
    const swa::Bytes dummyPin{'1',0,'2',0,'3',0,'4',0,0,0};
    auto pin=firstRecord;
    pin.kind=swa::CredentialKind::WindowsPin;
    pin.password=swa::seal(key,dummyPin,swa::profileBinding(pin));
    auto pinBackup=backupRecord;
    pinBackup.kind=swa::CredentialKind::WindowsPin;
    pinBackup.password=swa::seal(secondKey,dummyPin,swa::profileBinding(pinBackup));
    pin.additional.push_back({pinBackup.key,pinBackup.password});
    auto pinBytes=swa::encodeProfile(pin);
    auto pinDecoded=swa::decodeProfile(pinBytes);
    check(pinDecoded.kind==swa::CredentialKind::WindowsPin && pinDecoded.additional.size()==1 &&
        swa::equal(swa::encodeProfile(pinDecoded),pinBytes),"two-key Windows PIN profile round trip");
    auto pinFirst=swa::profileForKey(pinDecoded,0);
    auto pinSecond=swa::profileForKey(pinDecoded,1);
    check(swa::equal(swa::unseal(key,pinFirst.password,swa::profileBinding(pinFirst)).view(),dummyPin),"first wrapping unlocks Windows PIN");
    check(swa::equal(swa::unseal(secondKey,pinSecond.password,swa::profileBinding(pinSecond)).view(),dummyPin),"second wrapping unlocks Windows PIN");
    pinFirst.kind=swa::CredentialKind::MicrosoftPassword;
    rejected("PIN cannot be substituted as an account password",[&] { auto unused=swa::unseal(key,pinFirst.password,swa::profileBinding(pinFirst)); });
    firstRecord.kind=swa::CredentialKind::WindowsPin;
    rejected("account password cannot be substituted as a PIN",[&] { auto unused=swa::unseal(key,firstRecord.password,swa::profileBinding(firstRecord)); });
    // Multi-key header (8), record length (4), binding length (4), then SWA kind at 19.
    auto mixed=pinBytes; mixed.at(19)=1;
    rejected("mixed credential kinds rejected before hardware access",[&] { auto unused=swa::decodeProfile(mixed); });
    auto unknown=swa::encodeProfile(pinSecond); unknown.at(7)=3;
    rejected("unknown credential kind rejected",[&] { auto unused=swa::decodeProfile(unknown); });
}
const swa::Bytes FixtureData={'s','o','v','e','r','e','i','g','n',' ','t','w','o',' ','k','e','y',' ','t','e','s','t'};
void connectKey(const char* message) {
    std::cout << message << " Press Enter when ready." << std::endl;
    std::wstring input;
    if (!std::getline(std::wcin,input)) throw std::runtime_error("Hardware test canceled");
}
void makeFixture(const wchar_t* first,const wchar_t* second,const wchar_t* output) {
    if (std::filesystem::exists(output)) throw std::runtime_error("Test fixture already exists; no overwrite performed");
    auto firstKey=swa::parseTestProfile(swa::readFile(first,4096));
    auto secondKey=swa::parseTestProfile(swa::readFile(second,4096));
    if (swa::equal(firstKey.credential,secondKey.credential)) throw std::runtime_error("Two distinct credentials are required");
    swa::AccountProfile profile;
    profile.sid=L"S-1-5-21-1-2-3-1999999999";
    profile.account=L"MicrosoftAccount\\hardware-fixture@example.invalid";
    profile.key=firstKey;
    connectKey("Connect ONLY the first YubiKey.");
    std::cout << "Touch the first key." << std::endl;
    auto secret=swa::touchSecret(firstKey);
    profile.password=swa::seal(secret.view(),FixtureData,swa::profileBinding(profile));
    secret.clear();
    connectKey("Disconnect the first key. Connect ONLY the second YubiKey.");
    std::cout << "Touch the second key." << std::endl;
    swa::AccountProfile secondRecord;
    secondRecord.sid=profile.sid; secondRecord.account=profile.account; secondRecord.key=secondKey;
    secret=swa::touchSecret(secondKey);
    secondRecord.password=swa::seal(secret.view(),FixtureData,swa::profileBinding(secondRecord));
    secret.clear();
    profile.additional.push_back({secondRecord.key,secondRecord.password});
    auto bytes=swa::encodeProfile(profile);
    std::ofstream file(std::filesystem::path(output),std::ios::binary);
    if (!file.write(reinterpret_cast<const char*>(bytes.data()),static_cast<std::streamsize>(bytes.size())))
        throw std::runtime_error("Cannot write encrypted test fixture");
    file.close();
    std::cout << "Created two-key fixture containing TEST DATA ONLY. No Windows credential or sign-in setting was used." << std::endl;
    std::cout << "Touch the second key again to test automatic key selection." << std::endl;
    auto secondRecovered=swa::unlockAccount(swa::decodeProfile(swa::readFile(output)));
    check(swa::equal(secondRecovered.view(),FixtureData),"second physical key alone unlocks the shared native fixture");
    secondRecovered.clear();
    connectKey("Disconnect the second key. Connect ONLY the first YubiKey.");
    std::cout << "Touch the first key to test automatic key selection." << std::endl;
    auto firstRecovered=swa::unlockAccount(swa::decodeProfile(swa::readFile(output)));
    check(swa::equal(firstRecovered.view(),FixtureData),"first physical key alone unlocks the shared native fixture");
}
}
int wmain(int argc, wchar_t** argv) {
    try {
        if (argc==2 && std::wstring_view(argv[1])==L"--self-test") {
            selfTest();
            return 0;
        }
        if (argc==3 && std::wstring_view(argv[1])==L"--hardware-test") {
            auto profile = swa::parseTestProfile(swa::readFile(argv[2],4096));
            std::cout << "Touch the key for native authentication 1. No PIN is requested." << std::endl;
            auto first = swa::touchSecret(profile);
            std::cout << "Touch the key for native authentication 2. No PIN is requested." << std::endl;
            auto second = swa::touchSecret(profile);
            check(swa::equal(first.view(),second.view()),"native FIDO secret matches across fresh assertions");
            cryptoTests(first.view(),second.view());
            std::cout << "Native hardware proof passed. Windows sign-in is not installed." << std::endl;
            return 0;
        }
        if (argc==5 && std::wstring_view(argv[1])==L"--two-key-fixture") {
            makeFixture(argv[2],argv[3],argv[4]); return 0;
        }
        std::cerr << "Usage: swa_probe --self-test | --hardware-test public-profile.swt\n";
        return 2;
    } catch (const std::exception& error) {
        std::cerr << "FAILED: " << error.what() << '\n';
        return 1;
    }
}
