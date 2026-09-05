#include "core.h"
#include <bcrypt.h>
#include <fido.h>
#include <fido/es256.h>
#include <algorithm>
#include <fstream>
#include <memory>
#include <mutex>
#include <utility>

namespace swa {
namespace {
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
void nt(NTSTATUS status) { require(status >= 0, "Windows cryptography operation failed"); }
void fido(int status) {
    if (status != FIDO_OK) throw std::runtime_error(fido_strerr(status));
}
struct Algorithm {
    BCRYPT_ALG_HANDLE handle = nullptr;
    Algorithm() {
        nt(BCryptOpenAlgorithmProvider(&handle, BCRYPT_AES_ALGORITHM, nullptr, 0));
        auto status = BCryptSetProperty(handle, BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
            sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
        if (status < 0) { BCryptCloseAlgorithmProvider(handle, 0); handle = nullptr; nt(status); }
    }
    ~Algorithm() { if (handle) BCryptCloseAlgorithmProvider(handle,0); }
};
struct AesKey {
    BCRYPT_KEY_HANDLE handle = nullptr;
    explicit AesKey(BCRYPT_ALG_HANDLE alg, std::span<const unsigned char> key) {
        require(key.size() == 32, "AES-256 requires a 32-byte key");
        nt(BCryptGenerateSymmetricKey(alg, &handle, nullptr, 0,
            const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0));
    }
    ~AesKey() { if (handle) BCryptDestroyKey(handle); }
};
struct Device {
    fido_dev_t* p = fido_dev_new();
    Device() { require(p != nullptr, "Cannot allocate authenticator"); }
    ~Device() { fido_dev_close(p); fido_dev_free(&p); }
};
struct Assertion {
    fido_assert_t* p = fido_assert_new();
    Assertion() { require(p != nullptr, "Cannot allocate assertion"); }
    ~Assertion() { fido_assert_free(&p); }
};
struct PublicKey {
    es256_pk_t* p = es256_pk_new();
    PublicKey() { require(p != nullptr, "Cannot allocate public key"); }
    ~PublicKey() { es256_pk_free(&p); }
};
struct Devices {
    static constexpr size_t Capacity = 64;
    fido_dev_info_t* p = fido_dev_info_new(Capacity);
    size_t count = 0;
    Devices() { require(p != nullptr, "Cannot allocate device list"); }
    ~Devices() { fido_dev_info_free(&p, Capacity); }
};
}

Secret::Secret(size_t size) : size_(size) {
    if (!size || size > 65536) throw std::invalid_argument("Invalid secret size");
    data_ = static_cast<unsigned char*>(VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!data_) throw std::bad_alloc();
    if (!VirtualLock(data_, size)) { clear(); throw std::runtime_error("Cannot lock secret memory"); }
}
Secret::~Secret() { clear(); }
Secret::Secret(Secret&& other) noexcept : data_(std::exchange(other.data_, nullptr)), size_(std::exchange(other.size_, 0)) {}
Secret& Secret::operator=(Secret&& other) noexcept {
    if (this != &other) { clear(); data_ = std::exchange(other.data_, nullptr); size_ = std::exchange(other.size_,0); }
    return *this;
}
void Secret::clear() noexcept {
    if (data_) { SecureZeroMemory(data_, size_); VirtualUnlock(data_, size_); VirtualFree(data_, 0, MEM_RELEASE); }
    data_ = nullptr; size_ = 0;
}
Bytes randomBytes(size_t count) {
    require(count > 0 && count <= 65536, "Invalid random data size");
    Bytes result(count);
    nt(BCryptGenRandom(nullptr, result.data(), static_cast<ULONG>(count), BCRYPT_USE_SYSTEM_PREFERRED_RNG));
    return result;
}
bool equal(std::span<const unsigned char> a, std::span<const unsigned char> b) noexcept {
    if (a.size() != b.size()) return false;
    volatile unsigned char difference = 0;
    for (size_t i=0; i<a.size(); ++i) difference = static_cast<unsigned char>(difference | (a[i] ^ b[i]));
    return difference == 0;
}
Bytes readFile(const std::filesystem::path& path, size_t maxSize) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    require(file.good(), "Cannot open profile");
    auto length = file.tellg();
    require(length > 0 && static_cast<uint64_t>(length) <= maxSize, "Invalid profile length");
    Bytes data(static_cast<size_t>(length));
    file.seekg(0);
    require(static_cast<bool>(file.read(reinterpret_cast<char*>(data.data()), length)), "Truncated profile");
    return data;
}
KeyProfile parseTestProfile(std::span<const unsigned char> bytes) {
    require(bytes.size() >= 8, "Truncated profile header");
    require(bytes[0]=='S' && bytes[1]=='W' && bytes[2]=='T' && bytes[3]==1, "Unknown profile format");
    uint32_t length = 0;
    for (unsigned i=0; i<4; ++i) length |= static_cast<uint32_t>(bytes[4+i]) << (8*i);
    require(length >= 16 && length <= 2048, "Invalid credential identifier length");
    require(bytes.size() == 8 + static_cast<size_t>(length) + 64 + 32, "Truncated or trailing profile data");
    KeyProfile result;
    result.credential.assign(bytes.begin()+8, bytes.begin()+8+length);
    std::copy_n(bytes.begin()+8+length,64,result.publicKey.begin());
    std::copy_n(bytes.begin()+8+length+64,32,result.salt.begin());
    return result;
}
Sealed seal(std::span<const unsigned char> key, std::span<const unsigned char> plaintext, std::span<const unsigned char> binding) {
    require(!plaintext.empty() && plaintext.size() <= 32768 && binding.size() <= 32768, "Invalid encryption input length");
    Algorithm algorithm;
    AesKey aes(algorithm.handle,key);
    Sealed box;
    auto nonce = randomBytes(box.nonce.size());
    std::copy(nonce.begin(), nonce.end(), box.nonce.begin());
    box.ciphertext.resize(plaintext.size());
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = box.nonce.data(); info.cbNonce = static_cast<ULONG>(box.nonce.size());
    info.pbTag = box.tag.data(); info.cbTag = static_cast<ULONG>(box.tag.size());
    info.pbAuthData = const_cast<PUCHAR>(binding.data()); info.cbAuthData = static_cast<ULONG>(binding.size());
    ULONG written = 0;
    nt(BCryptEncrypt(aes.handle,const_cast<PUCHAR>(plaintext.data()),static_cast<ULONG>(plaintext.size()),
        &info,nullptr,0,box.ciphertext.data(),static_cast<ULONG>(box.ciphertext.size()),&written,0));
    require(written == box.ciphertext.size(), "Unexpected encryption length");
    return box;
}
Secret unseal(std::span<const unsigned char> key, const Sealed& box, std::span<const unsigned char> binding) {
    require(!box.ciphertext.empty() && box.ciphertext.size() <= 32768 && binding.size() <= 32768, "Invalid decryption input length");
    Algorithm algorithm;
    AesKey aes(algorithm.handle,key);
    Secret result(box.ciphertext.size());
    auto nonce = box.nonce;
    auto tag = box.tag;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = nonce.data(); info.cbNonce = static_cast<ULONG>(nonce.size());
    info.pbTag = tag.data(); info.cbTag = static_cast<ULONG>(tag.size());
    info.pbAuthData = const_cast<PUCHAR>(binding.data()); info.cbAuthData = static_cast<ULONG>(binding.size());
    ULONG written = 0;
    nt(BCryptDecrypt(aes.handle,const_cast<PUCHAR>(box.ciphertext.data()),static_cast<ULONG>(box.ciphertext.size()),
        &info,nullptr,0,result.data(),static_cast<ULONG>(result.size()),&written,0));
    require(written == result.size(), "Unexpected decryption length");
    return result;
}
KeyProof touchAnyKey(std::span<const KeyProfile> profiles, int timeoutMs) {
    require(timeoutMs > 0 && timeoutMs <= 45000, "Invalid hardware timeout");
    require(!profiles.empty() && profiles.size()<=8,"Invalid enrolled key count");
    for (const auto& candidate:profiles)
        require(candidate.credential.size() >=16 && candidate.credential.size() <=2048, "Invalid credential");
    const auto deadline=GetTickCount64()+static_cast<ULONGLONG>(timeoutMs);
    static std::once_flag init;
    std::call_once(init, [] { fido_init(FIDO_DISABLE_U2F_FALLBACK); });
    Device device;
    size_t selected=profiles.size();
    // USB re-enumeration after a key swap is asynchronous. Discovery has no
    // presence request and releases no secret; wait within the same deadline.
    while (selected==profiles.size() && GetTickCount64()<deadline) {
    Devices devices;
    fido(fido_dev_info_manifest(devices.p, Devices::Capacity, &devices.count));
    for (size_t i=0; i<devices.count; ++i) {
        auto item = fido_dev_info_ptr(devices.p,i);
        if (fido_dev_info_vendor(item)!=0x1050) continue;
        const auto selectionNow=GetTickCount64();
        if (selectionNow>=deadline) break;
        fido(fido_dev_set_timeout(device.p,static_cast<int>(std::min<ULONGLONG>(1000,deadline-selectionNow))));
        const auto opened=fido_dev_open(device.p,fido_dev_info_path(item));
        if (opened!=FIDO_OK || !fido_dev_is_fido2(device.p)) { fido_dev_close(device.p); continue; }
        Assertion discovery;
        auto challenge=randomBytes(32);
        fido(fido_assert_set_clientdata_hash(discovery.p,challenge.data(),challenge.size()));
        fido(fido_assert_set_rp(discovery.p,RelyingParty));
        for (const auto& candidate:profiles)
            fido(fido_assert_allow_cred(discovery.p,candidate.credential.data(),candidate.credential.size()));
        fido(fido_assert_set_up(discovery.p,FIDO_OPT_FALSE));
        const auto discovered=fido_dev_get_assert(device.p,discovery.p,nullptr);
        if (discovered==FIDO_ERR_NO_CREDENTIALS) { fido_dev_close(device.p); continue; }
        fido(discovered);
        require(fido_assert_count(discovery.p)==1,"Unexpected credential discovery response");
        const std::span<const unsigned char> identifier{fido_assert_id_ptr(discovery.p,0),fido_assert_id_len(discovery.p,0)};
        for (size_t k=0;k<profiles.size();++k) if (equal(identifier,profiles[k].credential)) { selected=k; break; }
        if (selected!=profiles.size()) {
            // Discovery routes the request only. It grants no authentication and
            // releases no secret. The fresh signed UP assertion below is mandatory.
            break;
        }
        fido_dev_close(device.p);
    }
    const auto scanFinished=GetTickCount64();
    if (selected==profiles.size() && scanFinished<deadline)
        Sleep(static_cast<DWORD>(std::min<ULONGLONG>(250,deadline-scanFinished)));
    }
    require(selected!=profiles.size(),"The expected enrolled YubiKey did not become available before the timeout");
    const auto now=GetTickCount64();
    require(now<deadline,"Hardware selection timed out");
    fido(fido_dev_set_timeout(device.p,static_cast<int>(deadline-now)));
    const auto& profile=profiles[selected];
    Assertion assertion;
    auto challenge = randomBytes(32);
    fido(fido_assert_set_clientdata_hash(assertion.p,challenge.data(),challenge.size()));
    fido(fido_assert_set_rp(assertion.p,RelyingParty));
    fido(fido_assert_allow_cred(assertion.p,profile.credential.data(),profile.credential.size()));
    fido(fido_assert_set_up(assertion.p,FIDO_OPT_TRUE));
    // Leave UV omitted: this key rejects uv=false since it has no built-in UV.
    // No PIN is provided; reject any response reporting UV to keep the same secret domain.
    fido(fido_assert_set_extensions(assertion.p,FIDO_EXT_HMAC_SECRET));
    fido(fido_assert_set_hmac_salt(assertion.p,profile.salt.data(),profile.salt.size()));
    fido(fido_dev_get_assert(device.p,assertion.p,nullptr));
    require(fido_assert_count(assertion.p)==1, "Unexpected assertion count");
    require((fido_assert_flags(assertion.p,0) & 0x05)==0x01, "Touch-only signed flags required");
    require(equal({fido_assert_id_ptr(assertion.p,0),fido_assert_id_len(assertion.p,0)},profile.credential), "Wrong credential response");
    PublicKey publicKey;
    fido(es256_pk_from_ptr(publicKey.p,profile.publicKey.data(),profile.publicKey.size()));
    fido(fido_assert_verify(assertion.p,0,COSE_ES256,publicKey.p));
    require(fido_assert_hmac_secret_len(assertion.p,0)==32, "No 32-byte hardware secret");
    Secret result(32);
    std::copy_n(fido_assert_hmac_secret_ptr(assertion.p,0),32,result.data());
    return {selected,std::move(result)};
}
Secret touchSecret(const KeyProfile& profile, int timeoutMs) {
    return touchAnyKey({&profile,1},timeoutMs).secret;
}
}
