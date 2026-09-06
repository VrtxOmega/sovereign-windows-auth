# Recovery

Use the route that matches your installation. Recovery restores access through
your existing Windows credential; it does not reveal, reset or bypass your PIN.

| Installed setup | Recovery route |
| --- | --- |
| Default Sovereign provider | Select **Sign-in options → PIN** |
| Provider with desktop restriction | Boot the paired USB, restore PIN sign-in, then enter your existing PIN |

**If the desktop filter is active, restore ordinary sign-in before unregistering
Sovereign.** Unregistering the provider alone leaves the filter installed and can
leave no usable sign-in tile.

## With the default installation

The default installer preserves ordinary Windows sign-in. If Sovereign fails,
choose **Sign-in options → PIN** and use the numerical PIN you already use on
this PC. Before first installation, confirm that this route works.

Once on the desktop, you can [unregister Sovereign](#unregister-the-provider).
Keep existing enrollment files for diagnosis.

## With the desktop restriction

Keep the paired recovery USB separately and boot-test it before enabling the
restriction. Use your PC's boot menu to start its recovery image; boot-menu keys
vary by manufacturer.

1. Select the intended Windows installation if the screen lists more than one.
   Drive letters may differ from those in your normal Windows session.
2. Select **Check recovery USB**.
3. Keep the paired USB connected. Select **Restore PIN sign-in** and confirm.
4. Select **Restart**, remove the USB and sign in using your existing Windows PIN.

The tool checks USB authorization again before changing the offline registry,
keeps a protected backup and removes only Sovereign's filter registration. The
PIN, encrypted key enrollments and credential-provider registrations remain
intact. A missing or mismatched USB does not authorize restoration.

After recovery, diagnose the original failure before reactivating the filter.
The activation script refuses an existing configuration rather than blindly
overwriting it. [USB preparation and validation](USB_RECOVERY.md) ·
[Exact offline scope](FILTER_RECOVERY.md)

## Unregister the provider

First restore ordinary sign-in if the desktop restriction was enabled. The
unregister helper removes the provider, not the separate filter.

From an administrator PowerShell window on the desktop:

```powershell
& "$env:ProgramFiles\SovereignWindowsAuth\unregister-provider.ps1"
```

Alternatively, run `Recover-Windows-Signin.cmd` in that installed directory as
administrator. If script policy blocks execution, use a process-only exception:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$env:ProgramFiles\SovereignWindowsAuth\unregister-provider.ps1"
```

The script removes only Sovereign's credential-provider and COM registration.
It keeps encrypted enrollments and installed files, and requests no restart.
If a historical update saved sign-in preferences, the companion restore script
restores a value only when it still equals Sovereign's applied value.

## Changed PIN or lost key

Changing the Windows PIN leaves its encrypted enrollment stale. Use the recovery
route above and unregister Sovereign. Safe PIN updates and individual-key
revocation are [planned work](ROADMAP.md); do not delete or replace profile files
as a troubleshooting guess.

A browser passkey is separate from Sovereign's enrollment. Removing that browser
passkey does not revoke the key's ability to use Sovereign.

## Limits

Recovery of the exact active filter has passed in disposable Windows, including
a deliberately missing Sovereign DLL. The paired USB has also booted on the
physical test laptop and verified its offline installation. Actual removal of
an active filter on that physical laptop is not yet recorded.

The tool cannot repair arbitrary Windows damage or unlock BitLocker. Keep the
device's existing encryption recovery route available. Do not disable Secure
Boot, LSA protection or Windows signing checks to work around a failed test.

For symptoms and reporting guidance, see [troubleshooting](TROUBLESHOOTING.md).
