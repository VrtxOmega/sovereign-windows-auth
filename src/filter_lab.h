#pragma once
#include <windows.h>
#include <credentialprovider.h>
#include <array>
#include <atomic>
#include "provider_id.h"

// This object is linked only into an isolated executable. It has no DLL exports,
// COM registration or configuration path into the installed sign-in provider.
namespace swa::lab {
enum class Mode { Disabled, Diagnostic, SimulateRestriction };
struct Preconditions {
    bool recoveryVerified = false;
    bool accountScopeVerified = false;
    bool inventoryReviewed = false;
};
struct KnownProvider {
    GUID id;
    const wchar_t* name;
};
// Explicitly identified convenience providers. Other providers must remain
// unchanged; registry membership alone does not make an identifier understood.
inline constexpr std::array<KnownProvider, 6> convenienceProviders{{
    {{0xd6886603,0x9d2f,0x4eb2,{0xb6,0x67,0x19,0x71,0x04,0x1f,0xa9,0x6b}}, L"Windows Hello PIN"},
    {{0x60b78e88,0xead8,0x445c,{0x9c,0xfd,0x0b,0x87,0xf7,0x4e,0xa6,0xcd}}, L"Password"},
    {{0x8af662bf,0x65a0,0x4d0a,{0xa5,0x40,0xa3,0x38,0xa9,0x99,0xd3,0x6f}}, L"Face"},
    {{0xbec09223,0xb018,0x416d,{0xa0,0xac,0x52,0x39,0x71,0xb6,0x39,0xf5}}, L"Fingerprint"},
    {{0x2135f72a,0x90b5,0x4ed3,{0xa7,0xf1,0x8b,0xb7,0x05,0xac,0x27,0x6a}}, L"Picture password"},
    {{0xcb82ea12,0x9f71,0x446d,{0x89,0xe1,0x8d,0x09,0x24,0xe1,0x25,0x6e}}, L"Legacy PIN"},
}};
inline const wchar_t* convenienceName(REFGUID id) noexcept {
    for (const auto& provider : convenienceProviders)
        if (id == provider.id) return provider.name;
    return nullptr;
}

class ProviderFilter final : public ICredentialProviderFilter {
    std::atomic<ULONG> references_{1};
    const Mode mode_;
    const Preconditions preconditions_;
public:
    explicit ProviderFilter(Mode mode = Mode::Disabled, Preconditions preconditions = {}) noexcept
        : mode_(mode), preconditions_(preconditions) {}
    IFACEMETHODIMP QueryInterface(REFIID iid, void** output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (iid != IID_IUnknown && iid != IID_ICredentialProviderFilter) return E_NOINTERFACE;
        *output = static_cast<ICredentialProviderFilter*>(this);
        AddRef();
        return S_OK;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++references_; }
    IFACEMETHODIMP_(ULONG) Release() override {
        const auto count = --references_;
        if (!count) delete this;
        return count;
    }
    IFACEMETHODIMP Filter(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, DWORD flags,
                         GUID* providers, BOOL* allow, DWORD count) override {
        // The SDK requires S_OK. Unsupported/malformed input and unproven
        // prerequisites are passive. This is safety gating, not automatic recovery.
        if (mode_ != Mode::SimulateRestriction || flags != 0 ||
            !preconditions_.recoveryVerified || !preconditions_.accountScopeVerified ||
            !preconditions_.inventoryReviewed || !providers || !allow ||
            (scenario != CPUS_LOGON && scenario != CPUS_UNLOCK_WORKSTATION)) return S_OK;
        bool sovereignAvailable = false;
        for (DWORD i = 0; i < count; ++i)
            if (providers[i] == CLSID_SovereignAuth && allow[i]) sovereignAvailable = true;
        if (!sovereignAvailable) return S_OK;
        for (DWORD i = 0; i < count; ++i)
            if (convenienceName(providers[i])) allow[i] = FALSE;
        return S_OK;
    }
    IFACEMETHODIMP UpdateRemoteCredential(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*,
                                         CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* output) override {
        if (output) *output = {};
        return E_NOTIMPL;
    }
};
} // namespace swa::lab
