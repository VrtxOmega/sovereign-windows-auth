# Key-required sign-in: design record

The optional [desktop restriction](DESKTOP_KEY_REQUIRED.md) is implemented and
has passed two-key physical lock/unlock on the test PC. This record explains the
decisions behind it. See [validation](VALIDATION.md) for the current evidence
and [recovery](RECOVERY.md) for operating instructions.

## Preserve the Windows credential

Sovereign's working provider decrypts an enrolled Windows Hello PIN after key
verification and supplies it to the stock PIN provider. Removing the PIN or its
provider's COM registration would break that bridge.

The separate filter controls whether identified ordinary tiles are offered in
local LogonUI. It does not delete the underlying credential.

## Separate the experiments from the desktop filter

| Component | Purpose | Missing Sovereign provider |
| --- | --- | --- |
| `swa_filter_lab` | Simulated provider decisions in an ordinary process | Preserves ordinary alternatives when preconditions fail |
| `SovereignCredentialFilterVm` | QEMU-only recovery experiment | Preserves alternatives when Sovereign is absent from the provider array |
| `SovereignCredentialFilter` | Explicitly activated local desktop restriction | Continues excluding identified alternatives in mode 2 |

The old VM filter's absent-provider guard was useful while exploring Windows'
behavior. It is not the policy of the active desktop filter. A present but
unusable provider can still leave no tile; independent recovery is required in
either case.

## Activation decisions

- Keep filtering off in the default provider installation.
- Require reviewed provider and account coverage before enabling a machine-wide
  desktop restriction.
- Validate the working provider, filter and recovery artifact hashes.
- Check that the protected PIN profile contains at least two enrolled keys.
- Verify the paired removable recovery credential before registering the filter.
- Stage the filter separately and register it as the final activation step.
- Preserve stock providers, existing PIN enrollment and other filters' exclusions.
- Refuse blind replacement of an existing filter configuration.

The activation script permits explicitly reviewed hidden, nonadministrator
background accounts without changing their rights. It does not establish
general multi-user enrollment support.

Mode 0 is passive; mode 1 observes decisions; mode 2 excludes identified ordinary
alternatives for local logon/unlock. Invalid configuration and unsupported
scenarios preserve decisions. Configuration is restricted to SYSTEM and
administrators, who remain trusted.

## Independent recovery

Two keys cover losing one key. They do not repair a broken DLL, stale PIN,
damaged profile or a changed Windows callback interface.

The paired recovery screen runs outside the affected LogonUI process. It checks
the USB credential again immediately before restoring normal sign-in and removes
only the filter registration. It preserves the PIN and Sovereign enrollment.
A missing key or failed touch must not silently enable ordinary PIN sign-in.

Recovery has reached the desktop in disposable Windows after a deliberately
unavailable provider. The physical recovery USB has passed boot, storage
discovery, pairing verification and return to Windows. Actual filter removal on
the physical laptop and encrypted-volume recovery remain separate unverified
cases.

## Evidence so far

- Native provider/filter contracts and recovery fixtures pass in the ten-suite CI.
- The shared production PIN bridge completed actual VM sign-in and unlock with
  the ordinary tiles hidden; a wrong generated lab PIN was rejected.
- The final desktop filter kept identified alternatives hidden when Sovereign's
  DLL was deliberately missing.
- The paired USB removed that final filter registration and the existing lab PIN
  reached the desktop after recovery media was removed.
- Both physical YubiKeys unlocked the enrolled personal Microsoft-account PC
  with ordinary PIN/password options absent.

Detailed records: [desktop filter](DESKTOP_KEY_REQUIRED.md),
[PIN bridge VM](PIN_BRIDGE_VM.md), [USB recovery](USB_RECOVERY.md).

## Scope

Microsoft's [filter contract](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/nf-credentialprovider-icredentialproviderfilter-filter)
requires preserving unknown provider identifiers and generic credential prompts.
Review provider coverage again after installing authentication software or
changing account configuration.

The restriction does not revoke passwords, remove network logon rights, protect
an already unlocked session, require a key for UAC, or unlock an encrypted disk.
A missing/damaged filter DLL can prevent its policy from running. Offline disk
protection, application authentication and boot policy require separate designs.
See [the security model](SECURITY_MODEL.md).
