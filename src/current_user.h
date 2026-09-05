#pragma once
#include <windows.h>
#include <credentialprovider.h>
#include <wrl/client.h>

namespace swa {
// Supplies the current user's public identity to an isolated native test host.
// At the real sign-in screen Windows supplies the user array itself.
Microsoft::WRL::ComPtr<ICredentialProviderUserArray> currentUserArray();
// Test hosts running as SYSTEM can request a local account's public metadata.
Microsoft::WRL::ComPtr<ICredentialProviderUserArray> userArrayForLocalAccount(const wchar_t* name);
}
