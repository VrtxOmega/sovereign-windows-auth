#pragma once
#include "filter_lab.h"

namespace swa::desktop {
inline constexpr wchar_t Configuration[] = L"SOFTWARE\\SovereignWindowsAuth\\DesktopFilter";
enum class Mode : DWORD { Off=0, Observe=1, RequireKey=2 };
struct Decision { DWORD known=0, excluded=0, other=0; bool applicable=false; };
inline Decision apply(Mode mode,CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario,DWORD flags,
                      GUID* providers,BOOL* allow,DWORD count) noexcept {
    Decision result;
    if((mode!=Mode::Observe && mode!=Mode::RequireKey) || flags || !providers || !allow || count>256 ||
       (scenario!=CPUS_LOGON && scenario!=CPUS_UNLOCK_WORKSTATION))return result;
    result.applicable=true;
    for(DWORD i=0;i<count;++i){
        if(lab::convenienceName(providers[i])){
            ++result.known;
            // Once deliberately activated, a missing/broken Sovereign provider
            // must not silently restore ordinary PIN/password sign-in.
            if(mode==Mode::RequireKey)allow[i]=FALSE;
            if(!allow[i])++result.excluded;
        }else if(providers[i]!=CLSID_SovereignAuth)++result.other;
        // Unknown providers and exclusions made by other filters are preserved.
    }
    return result;
}
}
