# Dependencies, attribution and references

Sovereign's source is GPL-3.0-only. Dependencies retain their upstream licenses;
the project license does not relicense Microsoft or Yubico code.

- **libfido2 1.17.0**: [Yubico source and license](https://github.com/Yubico/libfido2/tree/1.17.0),
  [official Windows SDK download](https://developers.yubico.com/libfido2/Releases/).
  The pinned Windows SDK supplies `fido2.dll`, `crypto-56.dll`, `cbor.dll` and
  `zlib1.dll`. Setup verifies the archive hash and Yubico Authenticode signatures.
  Downloaded headers, import libraries and binaries are excluded from Git.
- **python-fido2**: [Yubico source](https://github.com/Yubico/python-fido2).
  Used by enrollment/proof tools, not by the Windows sign-in DLL.
- **cryptography**: [PyCA source and licenses](https://github.com/pyca/cryptography).
  Used by the Python hardware proof tools.
- **Windows APIs, SDK and MSVC**: installed from Microsoft under Microsoft's
  terms. System libraries and SDK implementation files are not distributed here.

This source release contains no vendor binaries. A future binary release must
review licensing compatibility and include the applicable notices, licenses and
corresponding source obligations for the exact components it distributes.

## Implementation references

- [Microsoft credential-provider overview](https://learn.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows)
- [Microsoft V2 provider sample](https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/CredentialProvider)
- [Provider field descriptors](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/ns-credentialprovider-credential_provider_field_descriptor)
- [Credential UnAdvise contract](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/nf-credentialprovider-icredentialprovidercredential-unadvise)
- [Credential deselection contract](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/nf-credentialprovider-icredentialprovidercredential-setdeselected)
- [rbmm's original Windows credential-provider interface research](https://medium.com/@_dm_sh_/list-of-credentials-provider-interfeces-begin-of-2025-67f6a966935e):
  ABI reference for Events3–5 declarations in `src/windows_pin_interfaces.h`.
  The Events5 IID was also observed directly from the stock PIN provider on the
  test machine. This is interface interoperability work, not Microsoft support.
- [Yubico hmac-secret documentation](https://docs.yubico.com/yesdk/users-manual/application-fido2/hmac-secret.html)
- [libfido2 assertion verification](https://developers.yubico.com/libfido2/Manuals/fido_assert_verify.html)
- [Our Linux authentication project](https://github.com/VrtxOmega/yubikey-fido2-linux-auth)
