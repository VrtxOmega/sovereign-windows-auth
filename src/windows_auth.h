#pragma once
#include "core.h"

namespace swa {
ULONG windowsAuthenticationPackage();
Secret packWindowsCredential(const std::wstring& account,const wchar_t* password);
// Authenticate the exact protected online-identity buffer that the provider emits.
// Returns only the authenticated SID; neither credentials nor tokens are logged.
std::wstring authenticateWindowsBuffer(ULONG package,std::span<const unsigned char> buffer);
void validateWindowsCredential(const std::wstring& account,const wchar_t* password,const std::wstring& expectedSid);
}
