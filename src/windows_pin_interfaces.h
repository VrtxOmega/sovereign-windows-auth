#pragma once
#include <credentialprovider.h>

// Compatibility declarations for the Windows PIN provider's callback ABI.
// Events5 IID was observed directly in its Advise -> QueryInterface call on
// build 26200. Interfaces 3-5 are absent from SDK 26100's public header.
// ABI reference: rbmm's original interface research, sections Events3/4/5:
// https://medium.com/@_dm_sh_/list-of-credentials-provider-interfeces-begin-of-2025-67f6a966935e
// These declarations add no implementation to Windows or LSASS.
namespace swa {
MIDL_INTERFACE("2D8DEEB8-1322-4973-8DF9-B282F2468290")
PinEvents3 : public ICredentialProviderCredentialEvents2 {
    virtual HRESULT STDMETHODCALLTYPE SetFieldBitmapBuffer(ICredentialProviderCredential*,DWORD,DWORD,const BYTE*)=0;
};
MIDL_INTERFACE("DF50EA86-B7A9-4485-8F04-930A49686E5B")
PinEvents4 : public PinEvents3 {
    virtual HRESULT STDMETHODCALLTYPE RequestSerialization()=0;
    virtual HRESULT STDMETHODCALLTYPE RequestSelection()=0;
};
MIDL_INTERFACE("C4A56475-D6F5-43E3-80AE-1AA99833CC05")
PinEvents5 : public PinEvents4 {
    virtual HRESULT STDMETHODCALLTYPE SetTextFieldMaxLength(ICredentialProviderCredential*,DWORD,DWORD)=0;
    virtual HRESULT STDMETHODCALLTYPE SetAccessibilityTextForField(ICredentialProviderCredential*,DWORD,PCWSTR)=0;
    virtual HRESULT STDMETHODCALLTYPE SetRawAccessibilityViewForField(ICredentialProviderCredential*,DWORD,BOOL)=0;
    virtual HRESULT STDMETHODCALLTYPE RequestWebDialogVisibilityChange(ICredentialProviderCredential*,BOOL)=0;
};
}
