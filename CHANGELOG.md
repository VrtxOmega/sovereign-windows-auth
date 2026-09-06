# Changelog

## Unreleased — recovery experiment

- Pair a removable recovery drive using a random credential and a protected
  local verifier; refuse silent replacement and malformed or mismatched keys.
- WinPE recovery screen checks the paired USB before offering to restore normal
  Windows sign-in options. The PIN and YubiKey enrollment are preserved.
- Inspect a temporary registry copy before permitting changes to paired offline
  installations. Keep the exact, non-recursive filter removal and protected backup.
- Build private bootable recovery media from a user-supplied Windows ISO.
- Keep filtering disabled on physical hardware; pairing is not disk protection.

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
