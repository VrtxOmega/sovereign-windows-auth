# Requiring a key for desktop sign-in

Status: design only. Provider filtering and recovery codes are not implemented or
installed. The ordinary Windows PIN remains available in the current release.

## Intended behavior

An ordinary PIN tile allows someone who knows the PIN to sign in without a key.
The next mode should require either enrolled YubiKey for routine local desktop
sign-in and unlock. Exceptional recovery should require a deliberate, separately
authenticated procedure rather than another everyday sign-in option.

Do not delete the Windows Hello PIN. Sovereign decrypts the enrolled PIN after
key verification and supplies it to the stock PIN provider. Removing or changing
that credential breaks the bridge. Restricting its visible tile is a separate step.

## Candidate implementation

A separately registered `ICredentialProviderFilter` can control which known
providers LogonUI enumerates for `CPUS_LOGON` and `CPUS_UNLOCK_WORKSTATION`.
The first experiment must establish that hiding the stock PIN tile still allows
Sovereign to construct and use its provider internally. This is not yet tested.
Do not remove the stock provider's COM registration or alter PIN enrollment.
Default installation must leave filtering off. A diagnostic mode should report
decisions without changing them or collecting account secrets.

Microsoft prohibits excluding unknown provider identifiers and filtering generic
Credential UI prompts. Therefore activation needs an inventory of actual providers
and alternative account access, and cannot promise coverage of future providers.
The filter interface is scenario-based, not a per-account enrollment callback;
a single-user experiment must not be represented as safe for unenrolled users.
[Microsoft's filter contract](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/nf-credentialprovider-icredentialproviderfilter-filter).

## Recovery before activation

Two keys cover loss of one key. They do not cover a broken DLL, stale enrolled PIN,
damaged profile, or Windows update that changes the bridge's private interfaces.
The current uninstall script requires an accessible administrator desktop and is
not sufficient alone once ordinary sign-in choices are hidden.

Implement and rehearse recovery outside the affected LogonUI process on disposable
Windows first. It must remove only this filter's exact registration and restore
native sign-in choices while preserving enrollment and other providers. Keep any
system-volume encryption active and its recovery material separately accessible.
An already unlocked administrator session is not the only required recovery test.

A possible additional route is a high-entropy recovery code held separately from
the PC, with only its verifier stored locally. This needs its own attempt limits,
replay prevention, expiration and state-integrity design. A visible “use PIN”
button, a missing key or a key timeout must not silently enable recovery. Such a
code also cannot repair a filter that fails to load and cannot replace independent
recovery.

Microsoft recommends retaining a system provider when no other recovery route
exists and notes compatibility risks when wrapping stock providers. The recovery
experiment must address those exact failure modes.
[Credential providers and recovery](https://learn.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows).

## Required evidence

1. Isolated-host tests: known and unknown providers, supported and unsupported
   scenarios, absent or invalid configuration, diagnostics and independent removal.
2. Disposable Windows: hidden PIN tile with a working internal bridge; missing and
   wrong keys; timeout, cancellation, and ordinary alternative sign-in attempts.
3. Recovery with an unavailable Sovereign DLL and stale enrollment, restoring
   ordinary sign-in without needing a functioning Sovereign provider.
4. Both keys independently: lock, offline use, sleep, restart and first sign-in.
5. A bounded laptop trial only after recovery is proven, keeping the working
   runtime and enrollment intact.

## Scope

This concerns local interactive sign-in. Hiding tiles does not revoke passwords,
remove network logon rights, protect an unlocked session, require a key for UAC,
or unlock an encrypted disk before Windows boots. Each needs separate enforcement
and tests. Administrators and SYSTEM remain trusted under the existing
[security model](SECURITY_MODEL.md).
