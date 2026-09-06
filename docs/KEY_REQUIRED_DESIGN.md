# Requiring a key for desktop sign-in

Status: isolated filter and recovery experiments. The ordinary test executable is
joined by an optional QEMU-only filter DLL and an offline recovery executable.
No filter is installed on the working physical PC, and the VM DLL cannot be
enabled there through configuration. Recovery codes are not implemented. The
ordinary Windows PIN remains available in the current release.

## Intended behavior

An ordinary PIN tile allows someone who knows the PIN to sign in without a key.
The next mode should require either enrolled YubiKey for routine local desktop
sign-in and unlock. Exceptional recovery should require a deliberate, separately
authenticated procedure rather than another everyday sign-in option.

Do not delete the Windows Hello PIN. Sovereign decrypts the enrolled PIN after
key verification and supplies it to the stock PIN provider. Removing or changing
that credential breaks the bridge. Restricting its visible tile is a separate step.

## Candidate implementation

### Isolated experiment

Build with `tools/build.ps1`, then run:

```powershell
./build/Release/swa_filter_lab.exe --self-test
./build/Release/swa_filter_lab.exe --inspect
```

The lab implements `ICredentialProviderFilter` inside an ordinary executable.
Tests exercise simulated provider arrays; they do not invoke LogonUI or alter
registration. The read-only inventory prints registered provider identifiers and
identifies six convenience providers: current/legacy PIN, password, face,
fingerprint and picture password. It does not inspect account or key profiles.
Registration does not prove that a provider currently offers a usable tile.

Disabled, diagnostic, invalid and unsupported cases preserve all decisions.
Simulated restriction requires explicit recovery, account-scope and inventory
preconditions, plus an available Sovereign entry. These booleans are test inputs,
not evidence validators or a deployable activation mechanism. Recognized
convenience entries are excluded only for local logon/unlock with zero flags.
Unknown providers and exclusions made by other filters remain unchanged. Remote
credential handling returns `E_NOTIMPL` without forwarding credentials.

Local native compilation with warnings treated as errors and all six automated
suites passed on Windows build 26200, including the optional VM DLL and offline
recovery fixture. This establishes interface/decision behavior
in the lab, not hidden-PIN sign-in. An inventory on that machine also
found unreviewed provider registrations; the experiment cannot claim complete
key-only enforcement. The installed runtime hash remains unchanged.

The [offline recovery experiment](FILTER_RECOVERY.md) removes only the filter's
registration from an offline Windows hive. This passed in a disposable Windows
machine after a loadable but unusable provider left no sign-in tile: WinPE recovery
restored ordinary password sign-in while preserving the other registrations.
Physical recovery and hidden-PIN bridge validation are still pending.

### Physical implementation still pending

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
