#include "desktop_filter_policy.h"
#include <iostream>
#include <stdexcept>

namespace {
void check(bool condition,const char* message){
    if(!condition)throw std::runtime_error(message);
    std::cout<<"PASS "<<message<<'\n';
}
}
int main(){
    try{
        using swa::desktop::Mode;
        std::array<GUID,8> ids{};
        for(size_t i=0;i<6;++i)ids[i]=swa::lab::convenienceProviders[i].id;
        ids[6]=CLSID_SovereignAuth;ids[7]=GUID_NULL;
        std::array<BOOL,8> allow{};
        for(const auto mode:{Mode::Off,Mode::Observe,static_cast<Mode>(999)}){
            allow.fill(TRUE);allow[7]=FALSE;
            swa::desktop::apply(mode,CPUS_LOGON,0,ids.data(),allow.data(),8);
            check(allow[0]&&allow[5]&&allow[6]&&!allow[7],"inactive/observe/invalid modes preserve decisions");
        }
        for(const auto scenario:{CPUS_LOGON,CPUS_UNLOCK_WORKSTATION}){
            allow.fill(TRUE);
            auto decision=swa::desktop::apply(Mode::RequireKey,scenario,0,ids.data(),allow.data(),8);
            bool blocked=true;for(size_t i=0;i<6;++i)blocked=blocked&&!allow[i];
            check(blocked&&allow[6]&&allow[7]&&decision.excluded==6,"known alternatives excluded; Sovereign and unknown preserved");
            allow.fill(FALSE);
            swa::desktop::apply(Mode::RequireKey,scenario,0,ids.data(),allow.data(),8);
            check(!allow[6]&&!allow[7],"other filters' exclusions never reversed");
        }
        allow.fill(TRUE);
        swa::desktop::apply(Mode::RequireKey,CPUS_LOGON,0,ids.data(),allow.data(),6);
        check(!allow[0]&&!allow[5],"missing Sovereign never reopens PIN/password after activation");
        for(const auto scenario:{CPUS_CREDUI,CPUS_CHANGE_PASSWORD,CPUS_PLAP,CPUS_INVALID}){
            allow.fill(TRUE);
            const auto result=swa::desktop::apply(Mode::RequireKey,scenario,0,ids.data(),allow.data(),8);
            check(!result.applicable&&allow[0],"unsupported scenarios remain unchanged");
        }
        allow.fill(TRUE);
        check(!swa::desktop::apply(Mode::RequireKey,CPUS_LOGON,1,ids.data(),allow.data(),8).applicable&&allow[0],"nonzero flags preserved");
        check(!swa::desktop::apply(Mode::RequireKey,CPUS_LOGON,0,nullptr,allow.data(),8).applicable,"null provider input rejected");
        check(!swa::desktop::apply(Mode::RequireKey,CPUS_LOGON,0,ids.data(),nullptr,8).applicable,"null decision input rejected");
        check(!swa::desktop::apply(Mode::RequireKey,CPUS_LOGON,0,ids.data(),allow.data(),257).applicable,"oversized provider list rejected before access");
        return 0;
    }catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
}
