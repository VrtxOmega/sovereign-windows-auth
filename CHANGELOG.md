# Changelog

## Unreleased

### Desktop restriction and recovery

- Add an opt-in local desktop filter that preserves the Windows PIN internally
  while hiding identified ordinary sign-in alternatives.
- Validate the existing provider, two-key enrollment, account/provider inventory
  and paired recovery credential before registering the separate filter.
- Confirm both physical YubiKeys unlock with ordinary PIN/password options absent.
- Prove the shared PIN bridge in actual VM LogonUI, including wrong-PIN rejection.
- Prove recovery after the final filter encounters a missing Sovereign DLL:
  the paired USB restores the existing PIN screen and sign-in reaches the desktop.

- Pair a removable recovery drive using a random credential and a protected
  local verifier; refuse silent replacement and malformed or mismatched keys.
- WinPE recovery screen checks the paired USB before offering to restore normal
  Windows sign-in options. The PIN and YubiKey enrollment are preserved.
- Inspect a temporary registry copy before permitting changes to paired offline
  installations. Keep the exact, non-recursive filter removal and protected backup.
- Build private bootable recovery media from a user-supplied Windows ISO.
- Keep filtering disabled in the default installation; pairing is not disk protection.
- Expand native CI from three to ten suites with optional filter/bridge fixtures.

### Repository and documentation

- Add project artwork, build/license/status badges and a documentation index.
- Add architecture, troubleshooting and roadmap guides.
- Reconcile setup, recovery, security and validation with the tested desktop filter.
- Add issue forms, a pull request template, formatting conventions and local
  documentation-link checks.

## 0.1.0-alpha.1 — 2026-09-05

First public source preview, licensed under GPL-3.0-only.

- Native Windows credential provider for YubiKey touch-based desktop unlock.
- Two independent FIDO2 `hmac-secret` wraps of an enrolled Windows Hello PIN.
- Actual two-key desktop, offline and sleep/resume unlock confirmed on Windows
  11 Pro x64 build 26200; native Windows PIN retained for recovery.
- Correct handling of Windows UI refresh after a completed key proof, with
  separate invalidation for cancellation, expiry and one-time consumption.
- Portable MSVC/CMake build, pinned and signed Yubico dependency verification,
  enrollment environment setup and three automated suites in Windows CI.
- Setup, recovery, security-model, validation and contribution documentation.

This preview distributes source only. Signed installers, individual-key revocation,
safe PIN rotation and broader Windows compatibility remain development work.
