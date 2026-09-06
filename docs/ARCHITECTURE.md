# Architecture

Sovereign consists of a Windows credential provider, enrollment tools and an
optional desktop filter with independent recovery. The installed provider is
native C++; Python is used only during enrollment and development.

## Enrollment and sign-in

1. Enrollment creates a separate non-resident FIDO2 credential for each YubiKey.
2. Windows checks the existing numerical Hello PIN before enrollment is saved.
3. Each key's `hmac-secret` independently encrypts that PIN with AES-256-GCM.
   Machine-scope DPAPI and SYSTEM/Administrator file permissions protect the profile.
4. On the secure sign-in desktop, Sovereign obtains and verifies a fresh assertion
   from an enrolled key, including the signed user-presence flag.
5. The matching key decrypts the PIN. Sovereign supplies it to the stock Windows
   PIN credential provider through the bridge in `windows_pin.cpp`.
6. Windows authenticates the account and reports the result.

The PIN is an existing Windows credential, not a newly created password. The
bridge retains the stock provider while Windows consumes its serialization.

## Authentication lifecycle

A background worker waits for the key with a bounded timeout. A completed proof
expires and can be consumed only once. Account/scenario changes, actual
deselection and teardown invalidate it. Windows callback detachment during UI
refresh is handled separately from user cancellation.

The distinction matters: real LogonUI detached callbacks after a successful key
touch during early testing. Preserving the proof across that refresh, while still
invalidating actual cancellation, made the two-key desktop path work.
See [validation](VALIDATION.md) for the observed sequence.

## Optional restriction and recovery

The separately registered desktop filter hides six identified provider types for
local logon/unlock: current and legacy PIN, password, face, fingerprint and
picture password. It preserves the stock PIN provider's COM registration so the
internal PIN bridge can still use it.

The default install does not register this filter. Its separate activation
script checks tested artifact hashes, enrollment, account/provider inventory and
paired recovery authorization. Once active, a missing Sovereign provider does
not automatically restore ordinary PIN/password tiles.

The recovery executable operates from Windows PE/RE. It checks the paired USB
credential, backs up the offline hive and removes only Sovereign's filter
registration. It preserves the PIN, key profiles and provider registrations.
The graphical recovery screen is a small front end to that executable.

[Desktop restriction](DESKTOP_KEY_REQUIRED.md) · [USB recovery](USB_RECOVERY.md) ·
[Security boundaries](SECURITY_MODEL.md)

## Source map

| Area | Source |
| --- | --- |
| Credential-provider tile and lifecycle | `src/provider.cpp`, `src/provider_id.h` |
| FIDO proof, protected buffers and profiles | `src/core.cpp`, `src/core.h`, `src/profile.cpp` |
| Windows PIN bridge and interface declarations | `src/windows_pin.cpp`, `src/windows_pin_interfaces.h` |
| Account identity and Windows authentication helpers | `src/current_user.cpp`, `src/windows_auth.cpp` |
| Native enrollment and preflight | `src/enroll.cpp`, `src/hello_probe.cpp` |
| Desktop filter | `src/desktop_filter.cpp`, `src/desktop_filter_policy.h` |
| Offline recovery and USB authorization | `src/filter_recovery.cpp`, `src/recovery_usb.cpp` |
| Recovery screen | `src/recovery_screen.cpp` |
| Build, setup and diagnostic scripts | `tools/` |
| Native test targets and opt-in fixtures | `CMakeLists.txt` |
| Windows CI | `.github/workflows/windows.yml` |

Default builds include six native suites. `-WithVmFilter` adds the QEMU filter
contract and PIN bridge guard suites; `-WithDesktopFilter` adds desktop decision
and COM contract suites. CI runs all ten. None of these build/test commands
enrolls a hardware credential or registers a sign-in component.
