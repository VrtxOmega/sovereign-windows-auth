# Recovery

Before installation, confirm that you can unlock this account using the ordinary
Windows PIN option. Keep that option available while testing Sovereign. If
Sovereign fails, choose **Sign-in options → PIN** and use your existing Windows PIN.

From an administrator PowerShell window on the desktop, unregister Sovereign:

```powershell
& "$env:ProgramFiles\SovereignWindowsAuth\unregister-provider.ps1"
```

Alternatively, run `Recover-Windows-Signin.cmd` in that installed directory as
administrator. If script policy blocks the command, use a process-only exception:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$env:ProgramFiles\SovereignWindowsAuth\unregister-provider.ps1"
```

The script removes only Sovereign's credential-provider and COM registration. It
keeps the encrypted enrollment and installed files for diagnosis and requests no
restart. If a historical update saved sign-in preferences, the companion restore
script restores a value only when it still equals Sovereign's applied value.
Fresh installation does not disable the native PIN or face providers.

Changing your Windows PIN leaves the encrypted enrollment stale. If this happens,
use native Windows sign-in and unregister Sovereign. Enrollment deliberately
refuses to overwrite an existing profile; a safe PIN-update/revocation workflow
is still pending. Do not delete or replace profile files as a troubleshooting guess.

If you cannot reach the desktop through any normal provider, stop testing and use
your established Windows recovery procedure. Do not disable Secure Boot, LSA
protection or Windows signing checks. This project has not validated an offline
registry-repair procedure and does not promise recovery from arbitrary system
damage. Keep disk-encryption recovery material available through your normal
device-management process before conducting cold-boot tests.
