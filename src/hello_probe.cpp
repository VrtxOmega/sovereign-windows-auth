#include "core.h"
#include "current_user.h"
#include "windows_auth.h"
#include "windows_pin.h"
#include <iostream>
int wmain(int argc,wchar_t** argv) {
    if (FAILED(CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED))) return 1;
    int code=0;
    try {
        if (argc>2 || (argc==2 && std::wstring_view(argv[1])!=L"--preflight")) throw std::runtime_error("Unknown mode");
        auto users=swa::currentUserArray();
        swa::WindowsPin windows(users.Get(),swa::currentSid());
        std::cout << "PASS Windows PIN provider, identity, callbacks and active input" << std::endl;
        if (argc==1) {
            auto pin=swa::promptWindowsPin();
            auto serialized=windows.serialize(reinterpret_cast<PCWSTR>(pin.data()));
            pin.clear();
            if (swa::authenticateWindowsBuffer(serialized.package,serialized.buffer.view())!=swa::currentSid())
                throw std::runtime_error("Windows authenticated a different user");
            std::cout << "PASS Windows accepted the PIN credential and authenticated this user" << std::endl;
        } else std::cout << "Preflight complete. No PIN requested or authentication attempted." << std::endl;
        std::cout << "No profile saved or sign-in provider registered." << std::endl;
    } catch (const std::exception& error) { std::cerr << "FAILED: " << error.what() << std::endl; code=1; }
    CoUninitialize(); return code;
}
