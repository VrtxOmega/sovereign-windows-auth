#pragma once
#include <guiddef.h>

inline constexpr GUID CLSID_SovereignFilter =
    {0x51583b4d,0x1d80,0x4692,{0xb4,0xef,0x1c,0x38,0x5f,0xbc,0xf2,0x2d}};
inline constexpr wchar_t SovereignFilterId[] = L"{51583B4D-1D80-4692-B4EF-1C385FBCF22D}";
// Relative to a SOFTWARE hive, including an offline Windows SOFTWARE hive.
inline constexpr wchar_t SovereignFilterRegistration[] =
    L"Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Provider Filters\\{51583B4D-1D80-4692-B4EF-1C385FBCF22D}";
inline constexpr wchar_t SovereignFilterConfiguration[] = L"SOFTWARE\\SovereignWindowsAuth\\FilterVmLab";
