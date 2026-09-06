# Opt-in local desktop restriction

This experimental filter hides the six identified ordinary sign-in providers
(current/legacy PIN, password, face, fingerprint, picture password) for local
console sign-in and unlock. It preserves the Windows PIN enrollment and provider
COM registration so Sovereign can use the existing PIN bridge internally.

The filter is a separate DLL. Building it does not install or activate it:

```powershell
./tools/build.ps1 -WithVmFilter -WithDesktopFilter
```

The live key provider and its encrypted enrollment files do not change. The
filter has no FIDO dependency and uses a statically linked C++ runtime. The
paired recovery program removes the same separate filter registration used by
the earlier VM experiment.

## Activation and recovery

`tools/enable-desktop-key-required.ps1` requires an elevated operator, explicit
validated artifact hashes, the reviewed provider inventory, and the paired
removable recovery credential. It checks the existing protected Windows PIN
profile for at least two enrolled keys without decrypting the PIN itself. It
rejects an existing filter installation, domain membership, inventory changes,
and additional enabled accounts unless they are explicitly reviewed, hidden,
nonadministrator background accounts. It never modifies those accounts' logon
rights or credentials. The restriction applies to their desktop tiles too.

The script stages the separate DLL in a protected directory, checks its hash,
creates protected configuration, and registers the filter last. It does not lock
or reboot Windows. An incomplete activation rolls back its own new filter
registration; runtime failures do not trigger an automatic fallback.

`HKLM\SOFTWARE\SovereignWindowsAuth\DesktopFilter` uses version 1 and three modes:
0/unconfigured is passive, 1 observes without altering decisions, and 2 requires
the key path for the identified local desktop alternatives. The configuration
is restricted to SYSTEM and administrators. Logs contain counts, scenarios and
process IDs, not account credentials or key material.

In mode 2, an absent or broken Sovereign provider does **not** make the ordinary
PIN/password tiles return. Use the [paired USB recovery screen](USB_RECOVERY.md)
to remove this filter registration and restore the normal Windows PIN screen.
Recovery preserves the filter's COM registration and configuration; reactivation
after a recovery needs an explicit reviewed procedure. Do not re-enable it
blindly while the original failure remains unresolved.

## Scope and limits

This controls local interactive credential tiles. Remote sessions, generic
credential prompts, UAC, network logon rights and already unlocked sessions are
outside this restriction. Unknown provider IDs and exclusions made by other
filters are preserved, following
[Microsoft's filter contract](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/nf-credentialprovider-icredentialproviderfilter-filter).
Review the actual installed alternatives and repeat that review after adding
authentication software or changing account configuration.

Filtering tiles does not protect an unencrypted offline Windows volume, revoke
the underlying account password, or make a copyable recovery USB credential
physically unique. Administrators/SYSTEM remain trusted. A missing or damaged
filter DLL itself can prevent its policy from running. These limits require
separate disk, boot and application protection work; do not describe this as
universal YubiKey enforcement or exclusive offline recovery.

## Validation record

Ten native suites passed on Windows build 26200, including COM lifetime checks,
known/unknown-provider decisions, unsupported scenarios, preservation of prior
exclusions, and continued exclusion when Sovereign is absent. The production
desktop filter also passed actual VM sign-in through the shared Windows PIN
bridge with five known alternatives excluded from 13 provider entries. Both
components recorded LogonUI PID 1140 and Windows reported successful sign-in.

The tested desktop filter SHA-256 is
`A50660B1AD9E2B344F7D9C843CA5B8E8BBA23318F941FCC147CD7F8BC64EE153`.
The lab uses a generated local-account PIN; it is not a physical YubiKey test.
See [the bridge experiment](PIN_BRIDGE_VM.md) for its earlier rejection/unlock
tests. Physical activation and hardware results will be recorded separately.

With the Sovereign COM path deliberately pointing to a missing DLL, the final
desktop filter received 12 entries without Sovereign, excluded five known
alternatives, and left no ordinary sign-in tile. Its recorded PID 1136 matched
LogonUI. This differs deliberately from the earlier VM experiment's
absent-provider safety gate, which had preserved password sign-in.

With that broken-provider state preserved, the independent WinPE recovery screen
refused recovery without a paired USB. Connecting the paired lab USB authorized
removal of the filter registration. After ejecting the recovery ISO and USB,
Windows presented its normal PIN screen and the existing PIN reached the full
desktop. The PIN, password, Sovereign and filter COM registrations were preserved;
only the filter registration was removed. This establishes recovery for this
tested missing-provider failure, not every possible Windows boot failure.

The same filter was then installed on the enrolled Windows 11 Pro build 26200
laptop after verifying its paired recovery USB and physically boot-tested recovery
image. The existing provider binary and both encrypted key enrollments remained
unchanged. The owner confirmed that both physical YubiKeys independently unlocked
the laptop without PIN entry and that ordinary PIN/password options were absent.
This physical result covers lock/unlock; reboot with the new filter and actual
offline restoration of the physical laptop's filter are not yet recorded.
The physical filter recorded mode 2, Sovereign present, and four identified
alternatives excluded from twelve entries. Its provider binary still matched
the pre-installation hash after the hardware tests.

[GitHub CI for the implementation commit](https://github.com/VrtxOmega/sovereign-windows-auth/actions/runs/34012695678)
passed its build, ten native suites and source checks on `bb50e8c`.
