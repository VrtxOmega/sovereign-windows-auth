#pragma once
#include <windows.h>
#include <array>
#include <filesystem>
#include <span>
#include <stdexcept>
#include <vector>

namespace swa {
using Bytes = std::vector<unsigned char>;
inline constexpr char RelyingParty[] = "sovereign-windows-auth.local";

// Non-copyable, page-locked memory, wiped before release. Use for key material
// and plaintext. Library-owned temporary memory follows libfido2's lifecycle.
class Secret final {
    unsigned char* data_ = nullptr;
    size_t size_ = 0;
public:
    explicit Secret(size_t size);
    ~Secret();
    Secret(Secret&& other) noexcept;
    Secret& operator=(Secret&& other) noexcept;
    Secret(const Secret&) = delete;
    Secret& operator=(const Secret&) = delete;
    void clear() noexcept;
    unsigned char* data() noexcept { return data_; }
    const unsigned char* data() const noexcept { return data_; }
    size_t size() const noexcept { return size_; }
    std::span<const unsigned char> view() const { return {data_, size_}; }
};

struct KeyProfile {
    Bytes credential;
    std::array<unsigned char,64> publicKey{};
    std::array<unsigned char,32> salt{};
};
struct Sealed {
    std::array<unsigned char,12> nonce{};
    std::array<unsigned char,16> tag{};
    Bytes ciphertext;
};
Bytes randomBytes(size_t count);
bool equal(std::span<const unsigned char> a, std::span<const unsigned char> b) noexcept;
Bytes readFile(const std::filesystem::path& path, size_t maxSize = 65536);
KeyProfile parseTestProfile(std::span<const unsigned char> bytes);
Sealed seal(std::span<const unsigned char> key, std::span<const unsigned char> plaintext, std::span<const unsigned char> binding);
Secret unseal(std::span<const unsigned char> key, const Sealed& box, std::span<const unsigned char> binding);
Secret touchSecret(const KeyProfile& profile, int timeoutMs = 45000);
struct KeyProof {
    size_t index;
    Secret secret;
};
KeyProof touchAnyKey(std::span<const KeyProfile> profiles, int timeoutMs = 45000);
struct AdditionalKey {
    KeyProfile key;
    Sealed password;
};
enum class CredentialKind : unsigned char { MicrosoftPassword=1,WindowsPin=2 };
struct AccountProfile {
    CredentialKind kind=CredentialKind::MicrosoftPassword;
    KeyProfile key;
    std::wstring sid;
    std::wstring account;
    Sealed password;
    std::vector<AdditionalKey> additional;
};
AccountProfile profileForKey(const AccountProfile& profile,size_t index);
Secret unlockAccount(const AccountProfile& profile,int timeoutMs = 45000);
Bytes profileBinding(const AccountProfile& profile);
Bytes encodeProfile(const AccountProfile& profile);
AccountProfile decodeProfile(std::span<const unsigned char> bytes);
std::wstring tokenSid(HANDLE token);
std::wstring currentSid();
std::filesystem::path profilePath(const std::wstring& sid);
void saveProfile(const AccountProfile& profile);
AccountProfile loadProfile(const std::wstring& sid);
}
