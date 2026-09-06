# Security model

## What the key authorizes

Sovereign delegates to Windows' existing PIN credential provider. It stores the
enrolled Windows PIN encrypted on the PC and supplies it to Windows after a fresh
signed YubiKey touch. It does not remove the Windows PIN or create a native
passwordless Microsoft-account authentication method.

Touch proves physical presence. Anyone with an enrolled key and access to this
PC can touch it. This is deliberately a possession-based alternative to entering
the PIN; it is not two-factor sign-in. Keep the recovery key separately.

The default installation keeps ordinary PIN sign-in available. The optional
[desktop restriction](DESKTOP_KEY_REQUIRED.md) hides identified ordinary
sign-in providers while preserving the PIN bridge. Both physical keys have
passed lock/unlock with that restriction on the tested PC. It is not enabled by
building the project or by the default provider installer.

The restriction applies to local sign-in tiles, not every Windows authentication
path. Unknown providers and remote/generic credential scenarios remain outside
its scope. Review provider and account coverage before activation.

## Trust boundaries

The design assumes the Windows installation, administrator/SYSTEM account,
enrollment process and installed runtime are trusted. It does not defend against
a compromised operating system, administrator malware or malicious code already
running inside LogonUI. Such code can observe a credential when it is legitimately
decrypted or alter the sign-in path. Disk encryption and physical device security
remain separate protections.

The profile receives two layers of protection:

1. Each key supplies a separate 32-byte FIDO2 `hmac-secret` for AES-256-GCM. The
   authenticated data binds credential kind, Windows SID, account identity,
   credential ID, public key and salt. Each key has its own encrypted wrap.
2. Machine-scope DPAPI binds the full encrypted profile to the Windows
   installation. File and directory ACLs allow SYSTEM and Administrators only.

Machine-scope DPAPI is not a substitute for the key or ACLs, and it is not a
per-user isolation boundary against an administrator. Public credential handles
and salts are not passwords, but enrollment files and diagnostic artifacts should
remain private. Do not upload the ProgramData directory or `artifacts/`.

## Authentication lifecycle

Discovery chooses an enrolled YubiKey without authorizing sign-in. A separate
fresh assertion must validate the challenge, relying party, enrolled credential,
ES256 signature and signed user-presence flag. No daily FIDO PIN is supplied.
Assertions reporting user verification are rejected to keep the intended
`hmac-secret` domain. Runtime discovery currently selects Yubico USB devices only.

The worker has a bounded key request; the provider uses a 15-second deadline.
A ready result is accepted for up to 30 seconds and is consumed once. Actual
tile deselection, provider teardown and account/scenario changes invalidate it.
Windows may detach UI callbacks during a display refresh: credential `UnAdvise`
therefore does not treat that refresh as user cancellation. Both the refresh and
real cancellation cases are covered by the native host.

Owned plaintext credentials and derived secrets use move-only, page-locked buffers
and are wiped on release. Windows and the FIDO library have their own internal
buffers. The Python enrollment/proof tools cannot guarantee erasure of immutable
Python objects and are not loaded into LogonUI.

## Compatibility and remaining work

The stock Windows PIN provider requires callback interfaces Events3–5 that are
absent from SDK 26100. Declarations are isolated in `src/windows_pin_interfaces.h`,
with their research attribution. They worked on build 26200; they are not a
Microsoft compatibility guarantee. The bridge rejects missing or ambiguous PIN
fields and does not fall back to requesting an account password.

Only local desktop use is implemented. RDP, UAC and password-change scenarios are
not supported. Local-only and managed enterprise account enrollment are not
implemented by the current enrollment tool. A FIPS-branded test key does not make
this whole project a FIPS-validated solution.

Changing the Windows PIN makes the existing encrypted enrollment stale. Safe PIN
rotation and individual-key revocation are not implemented yet. If a key is lost,
restore ordinary sign-in first if the desktop filter is active, then unregister
Sovereign and use native Windows sign-in. Follow [recovery](RECOVERY.md) in that
order; unregistering the provider alone does not remove the filter.
Do not rely on changing the Microsoft browser passkey to revoke this separate
credential. Unregistering Sovereign does not erase its protected profile.

The paired USB stores a random bearer credential; Windows holds its protected
verifier. This authorizes the recovery tool to remove the separate filter
registration. The file can be copied, and an unencrypted Windows volume remains
editable from another boot environment. Pairing is not hardware anti-cloning,
disk encryption or exclusive protection against offline bypass.

No independent security audit or broad deployment validation has been completed.
The public source release is intended to make those reviews and tests possible.
