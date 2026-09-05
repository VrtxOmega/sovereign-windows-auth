#pragma once
#include "core.h"
#include <credentialprovider.h>
#include <memory>

namespace swa {
struct WindowsCredentialBuffer { ULONG package; Secret buffer; };
class WindowsPin final {
    struct Impl;
    std::unique_ptr<Impl> impl_;
public:
    WindowsPin(ICredentialProviderUserArray* users,const std::wstring& sid,
        CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario=CPUS_LOGON);
    ~WindowsPin();
    WindowsPin(const WindowsPin&)=delete;
    WindowsPin& operator=(const WindowsPin&)=delete;
    WindowsCredentialBuffer serialize(const wchar_t* pin);
};
// Available in interactive tools that embed hello_probe.rc, never in LogonUI.
Secret promptWindowsPin();
}
