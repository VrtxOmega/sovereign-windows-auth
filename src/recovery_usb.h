#pragma once
#include <windows.h>
#include <array>
#include <span>
#include <string>

namespace swa::recovery {
inline constexpr wchar_t PairingPath[] = L"SovereignWindowsAuth\\RecoveryUsb";
using Digest = std::array<BYTE, 32>;
// The credential is a bearer secret, not a USB serial-number authentication scheme.
Digest keyDigest(std::span<const BYTE> key);
bool digestEqual(const Digest& left, const Digest& right) noexcept;
bool paired(HKEY software);
void authorize(HKEY software, const wchar_t* keyFile);
void pairUsb(const wchar_t* directory);
void checkLiveUsb(const wchar_t* keyFile);
void selfTestUsb();
}
