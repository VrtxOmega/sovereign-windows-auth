# Sovereign Windows authentication

Unreleased Windows x64 prototype implementing touch-only daily sign-in for the
owner's personal Microsoft account. Source is controlled here; no Rohos login
component is used. Windows APIs and Yubico's protocol/cryptography libraries are
dependencies, as standard libraries were dependencies of the Linux PAM work.

**Status: touch-only Windows desktop unlock succeeded independently with both
physical YubiKeys on 2026-09-05, confirmed by the user and successful Windows
authentication results at 22:55:26.772Z and 22:56:21.408Z.** Daily unlock required
no PIN entry or facial scan. Both keys also passed individual FIDO hardware proofs.
The native DLL builds and all three automated suites pass: crypto/parser,
credential-provider contract, and Windows online-identity format.
Both keys independently unlocked the same native encrypted test fixture. Windows
PIN authentication succeeded against the correct Windows user on
2026-09-05T21:54:42Z. Both keys are now enrolled in a protected Windows PIN
profile. Each independently authenticated the correct user through the custom
provider's exact serialized output. All preinstallation checks passed at
2026-09-05T22:15:09Z. The installed refresh revision subsequently passed actual
desktop unlock with both physical keys.
The user confirmed that their existing YubiKey passkey signs into their Microsoft
account in a browser. Its PIN is not a Windows account password. After changing
their Microsoft-account password, the user explicitly requested further attempts.
The final attempt returned Win32 1326 on 2026-09-05T21:40:26Z. The user then
selected a different sign-in design. No more Microsoft-account password prompts
should be opened without a new user request.

## Current direction: Windows PIN protected by either YubiKey

The user confirmed that they unlock this PC with a numerical Windows PIN.
Read-only native inspection successfully opened the Windows NGC credential
provider, supplied this user's actual identity, obtained a V2 credential, and
verified its SID. Windows exposed one active, focused PIN input and a submit
button beside it. The Passport key provider enumerated one current-user key.
These live results take precedence over the earlier `dsregcmd` NgcSet:NO result;
that field alone was not sufficient to establish whether a PIN credential exists.

`swa_hello_probe` is an isolated test host with a clearly labeled Windows PIN
dialog. It asks for the PC's PIN once, forwards it privately to the stock PIN
provider, and submits the resulting original credential to LSA. It never registers
a provider, saves a profile, changes a PIN, or automatically retries. Actual PIN
authentication succeeded. The shared `WindowsPin` bridge now supplies the same
path to enrollment, saved-profile verification, and the custom sign-in provider.
The PIN is encrypted independently for each key and never written in plaintext.

The current Windows build requires the credential callback interface Events5,
which is absent from the public SDK. Its IID was observed directly, and the ABI
declarations are isolated in `windows_pin_interfaces.h`. This compatibility point
must be checked after Windows updates; the bridge rejects an unavailable or
ambiguous PIN input before requesting or submitting a PIN.

## Shared key protection and sign-in component

- A dedicated non-resident FIDO credential on each YubiKey, using the isolated RP
  `sovereign-windows-auth.local`. Existing passkeys, PINs, PIV certificates, OTP
  applications, and other credentials are preserved.
- FIDO2 `hmac-secret` supplies independent encryption material for each key.
  Daily requests supply no PIN; a fresh signed assertion must include presence
  and must not include user verification. Signature, RP, credential ID and
  challenge are checked before using the secret.
- A discovery request with presence disabled selects an enrolled key. Discovery
  never releases a secret or authorizes sign-in. A second, fresh request requires
  a signed touch. This allows either registered key to work independently.
- Each key encrypts the same one-time-enrolled Windows credential independently
  with AES-256-GCM. Associated data binds credential kind, SID, Microsoft identity, credential ID,
  public key and salt. The complete profile is additionally bound to this Windows
  installation with machine DPAPI and restricted to SYSTEM/Administrators.
- A native V2 credential provider displays title, status and submit controls;
  there is no daily password, PIN, OTP, or device-type dropdown.
- Authentication runs on a background worker. Deselecting the tile invalidates
  the pending result. Hardware requests are bounded; successful proof is consumed
  once, and an unused result expires after 30 seconds.
- Decrypted credentials and derived secrets use non-copyable, page-locked memory
  that is erased before release. The Python hardware probes are not the logon
  runtime and do not make the same memory-erasure guarantee.

For a PIN profile, the custom component gives the decrypted PIN to Windows' stock
NGC credential provider and forwards its original authentication package and
serialization. The test host authenticates that exact buffer through LSA and
checks the resulting SID. The paused password backend uses protected EX2 identity
serialization instead. This does not replace the LSA authentication package.
No password hash dumping, LSASS injection, signing bypass, or reduction
of LSA protection is part of the implementation. Changing the enrolled PIN requires
updating the encrypted enrollment. System sign-in providers remain available for
recovery, matching the separate recovery route retained in our Linux setup.

## Verified so far

- Key 1: Python and native FIDO proofs passed with touch-only authentication;
  independently derived secrets reproduced across fresh challenges/connections.
- Key 2: Python FIDO proof passed, including a check that it cannot use key 1's
  credential. Its credential and public metadata were exported for native use.
- Both physical keys independently unlocked one shared encrypted fixture through
  native C++ on 2026-09-05. This fixture contains dummy test data, not an account
  password. Neither key depended on the other being connected.
- Replay under a different challenge, wrong encryption keys, altered ciphertext,
  nonce, tag, identity binding, credential ID, public key and salt are rejected
  by the corresponding hardware/protocol or native tests.
- Native tests reject every truncated length of single-key and two-key profiles,
  trailing data, excessive lengths, invalid SIDs and duplicate key records.
- Windows PIN profiles round-trip with both independent wraps. Credential-kind
  substitution fails authentication, and mixed/unknown kinds are rejected.
- The PC's numerical Windows PIN authenticated the expected user through the
  stock NGC provider and LSA. Elevated enrollment repeated that success, but its
  second-key USB handoff failed before saving. Detection now rescans within a
  bounded deadline; enrollment offers a manual key retry without repeating PIN
  authentication. The revised enrollment completed successfully with both keys.
- Both physical keys independently produced a fresh authenticated credential
  through the custom provider, and Windows accepted each exact serialization for
  the expected user. The saved profile required no further PIN/password entry.
  Cancellation prevented automatic sign-in; a completed proof was not reusable;
  COM objects and the background worker were released.
- COM host verifies DLL loading without registration, correct interface lifetime,
  rejection of unsupported UAC/password-change scenarios, no password field,
  and no credential tile or automatic submission for an unenrolled user.
- The Windows identity-format test confirms EX2/online-provider flags, session
  protection, exact identity binding, and Unicode password preservation through
  native Windows APIs. It also proves that EX2 unpacking returns marshaled strings
  which must not be passed to `LogonUserW` as ordinary credentials. Enrollment and
  the provider host now test the original serialized buffer through `LsaLogonUser`.
  This corrected two validation-path flaws but did not resolve the account rejection.

Actual Windows lock/unlock is verified independently with both physical keys.
Reboot, offline and sleep tests remain pending. This is a locally validated
prototype; compatibility with future Windows updates is not established.

The installed runtime is under `C:\Program Files\SovereignWindowsAuth` and matches
the exact tested binary hashes. Its installed contract check passed. The ordinary
Windows PIN provider remains enabled. Recovery: run `Recover-Windows-Signin.cmd`
in that directory as administrator to unregister only Sovereign key sign-in.

The first actual lock-screen test did not show Sovereign in Sign-in options.
Inspection found that the original provider omitted the Windows provider logo
and label field GUIDs. The display repair adds both, supplies a 64x64 key icon,
and permits enrolled-user enumeration before `Advise`. The host now verifies
these behaviors. `--inspect` enumerates the real enrolled user without touching
a key or attempting authentication; `--registered-sid SID` additionally exercises
COM registration and can inspect an enrolled user's tile under SYSTEM.
The display revision was installed at 2026-09-05T22:34:02Z. Both the elevated
desktop inspection and the SYSTEM inspection passed, including original COM
activation, real encrypted-profile access, enumeration before event registration,
the icon bitmap, and the Sovereign label. The temporary SYSTEM task was removed.
That revision used `SovereignCredentialProvider-display.dll`; it and the original
DLL are retained. The subsequent lock-screen tests are described below.

The second lock-screen test showed the key option but returned to Windows PIN
after the touch request. The protected trace showed initial serialization and
credential re-enumeration, with no second serialization or Sovereign credential
submission. Inspection found `SetSelected` always returned false, even after a
fresh key proof. The handoff revision returns true only while an unconsumed,
unexpired proof exists; cancellation still clears it. Host checks now exercise
selection before proof, after proof, after consumption, and after cancellation.
Additional diagnostics distinguish successful, failed, and canceled key requests.

`tools/install-touch-handoff.ps1` stages a separate package and requires a real
touch-only authentication test under SYSTEM before switching registration. It
then pauses the face sign-in provider and prefers Sovereign for this user's tile,
preserving the Windows PIN provider and the original preferences for recovery.
The SYSTEM authentication passed at 2026-09-05T22:47:15Z, including exact LSA
serialization acceptance for the intended user, selection after touch, and proof
consumption. Cancellation and reselection checks passed too. The revision was
installed at 22:47:31Z under `touch-handoff\SovereignCredentialProvider.dll`.
Face sign-in is paused and Sovereign is preferred for this user; native PIN
recovery remains enabled. The subsequent desktop test exposed the refresh defect
described below.

The next real lock-screen trace identified the remaining refresh defect precisely:
at 22:48:53Z and 22:49:02Z, `KeyProofReady` was followed by credential `UnAdvise`,
which incorrectly called `SetDeselected` and erased the result before enumeration.
Credential `UnAdvise` now releases only UI callback state (none is retained by
this implementation). Real `SetDeselected`, provider teardown, expiry, and
consumption continue to erase the secret. The host reproduces the observed
`UnAdvise -> GetCredentialCount -> Advise -> SetSelected -> GetSerialization`
sequence and separately tests cancellation after a completed key proof. The
refresh revision is installed by `tools/update-provider-refresh.ps1`.
This revision passed the observed refresh sequence with real SYSTEM authentication
at 2026-09-05T22:54:18Z. A separate real-key test proved that canceling a completed
proof prevents sign-in even after another refresh and reselection. It was installed
at 22:54:26Z under `touch-refresh\SovereignCredentialProvider.dll`. Temporary test
tasks were removed. Actual desktop unlock then succeeded at 22:55:26.772Z and
22:56:21.408Z: each trace records a fresh key proof, successful credential
submission and Windows `ReportResult` with status and substatus both zero. The
user confirmed that both physical keys worked. The active provider SHA-256 is
`6837A531335116774093BF17DDDE8E49E43271CF2DB642E0E6BBDF53E1705F92`.

`tools/update-provider-display.ps1` preserves the original DLL, verifies the
display revision with the real enrollment, switches the registered DLL, and runs
a temporary inspection task as SYSTEM. The task is removed after the check;
the previous registration is restored on a failed check. Optional bounded tracing
records only lifecycle stage names, counts, and status codes in the protected
profile directory. It never records a PIN, password, or serialized credential.

## Build and test

Installed toolchain: MSVC v143, VS 2022 Build Tools, Windows SDK 10.0.26100.0.
Run `tools/build.ps1` from PowerShell. Binaries are in `build/Release`.
The project uses C++20, warning-as-error compilation, SDL checks, control-flow
guard, ASLR, DEP and CET compatibility flags.

libfido2 1.17.0 is downloaded from Yubico's official release site. Its runtime DLLs
have valid Yubico AB Authenticode signatures. The provider delay-loads FIDO from
its own directory using restricted DLL search flags, and pins its module for the
LogonUI process lifetime once a worker starts. `tools/install-provider.ps1` requires
a successful both-key receipt and the exact tested binary hashes. It copies the
runtime into Program Files, validates the copied files and DLL contract, and
registers only this provider with Apartment threading. It does not register a
credential filter or alter stock providers. `tools/unregister-provider.ps1` and
the installed recovery launcher remove only the two registration keys. Do not
register the workspace binary manually.

`swa_probe --self-test` runs non-hardware tests. `swa_provider_host <dll>` runs COM
contract checks without registration. Interactive scripts under `tools` perform
hardware tests. `artifacts/` contains private diagnostics and enrollment metadata
and is intentionally excluded from Git.

`tools/enroll-pin-and-verify.ps1` is the current interactive enrollment route. The
older `enroll-and-verify.ps1` uses the paused password design and should not be run
for this user's current workflow.

## References

- [Our Linux implementation](https://github.com/VrtxOmega/yubikey-fido2-linux-auth/tree/82d64f0922ee8f4c2f130f4fb83fa08711a4a1d4)
- [Microsoft credential provider interfaces](https://learn.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows)
- [Windows provider logo and label fields](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/ns-credentialprovider-credential_provider_field_descriptor)
- [Credential UI event detachment](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/nf-credentialprovider-icredentialprovidercredential-unadvise)
- [Deselection and secret cleanup](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/nf-credentialprovider-icredentialprovidercredential-setdeselected)
- [Official Microsoft V2 credential provider sample](https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/CredentialProvider)
- [Yubico hmac-secret behavior](https://docs.yubico.com/yesdk/users-manual/application-fido2/hmac-secret.html)
- [libfido2 assertion verification](https://developers.yubico.com/libfido2/Manuals/fido_assert_verify.html)
- [Windows protected LSA signing requirements](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
