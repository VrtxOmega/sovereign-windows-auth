#!/usr/bin/env bash
# Build private recovery media from a Windows ISO the operator supplies.
# Microsoft binaries and device-specific credentials are never published.
set -euo pipefail
if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
  echo 'Usage: build_recovery_iso.sh WINDOWS.iso RELEASE_DIRECTORY NEW_OUTPUT_DIRECTORY [VMD_DRIVER_DIRECTORY]' >&2
  exit 2
fi
source_iso=$(realpath "$1")
release=$(realpath "$2")
output=$(realpath -m "$3")
seven=${SEVENZIP:-7z}
wim=${WIMLIB:-wimlib-imagex}
iso=${XORRISO:-xorriso}
test -f "$source_iso"
test -f "$release/swa_filter_recovery.exe"
test -f "$release/swa_recovery_screen.exe"
# No reuse, cleanup or recursive overwrite of an existing output tree.
test ! -e "$output"
mkdir "$output"
mkdir -p "$output/source" "$output/root/sources" "$output/payload/Sovereign" "$output/payload/Windows/System32"
"$seven" x -y "$source_iso" "-o$output/source" sources/boot.wim boot efi bootmgr bootmgr.efi >"$output/extract.log"
for name in boot efi bootmgr bootmgr.efi; do cp -a "$output/source/$name" "$output/root/"; done
# Windows PE image 1 has no Windows Setup shell. Export only that image.
"$wim" export "$output/source/sources/boot.wim" 1 "$output/root/sources/boot.wim" 'Sovereign Recovery' --boot --check >"$output/export.log"
cp "$release/swa_filter_recovery.exe" "$release/swa_recovery_screen.exe" "$output/payload/Sovereign/"
ini="$output/payload/Windows/System32/winpeshl.ini"
printf '[LaunchApps]\r\n%%SYSTEMROOT%%\\System32\\wpeinit.exe\r\n' >"$ini"
if [ "$#" -eq 4 ]; then
  driver=$(realpath "$4")
  test -f "$driver/iaStorVD.inf"
  test -f "$driver/iaStorVD.sys"
  mkdir -p "$output/payload/Sovereign/Drivers/VMD"
  cp -a "$driver/." "$output/payload/Sovereign/Drivers/VMD/"
  printf '%%SYSTEMROOT%%\\System32\\drvload.exe, %%SYSTEMDRIVE%%\\Sovereign\\Drivers\\VMD\\iaStorVD.inf\r\n' >>"$ini"
fi
printf '%%SYSTEMDRIVE%%\\Sovereign\\swa_recovery_screen.exe\r\n%%SYSTEMROOT%%\\System32\\wpeutil.exe, shutdown\r\n' >>"$ini"
# The command language supports quoted local paths. Refuse quote/newline paths.
case "$output" in *\"*|*$'\n'*) echo 'Unsupported quote/newline in output path' >&2; exit 2;; esac
printf 'add "%s" /\n' "$output/payload" | "$wim" update "$output/root/sources/boot.wim" 1 --check >"$output/update.log"
"$iso" -as mkisofs -iso-level 3 -J -joliet-long -V SWA_RECOVERY \
  -b boot/etfsboot.com -no-emul-boot -boot-load-size 8 \
  -eltorito-alt-boot -e efi/microsoft/boot/efisys_noprompt.bin -no-emul-boot \
  -o "$output/Sovereign-Recovery.iso" "$output/root" >"$output/iso.log" 2>&1
sha256sum "$output/Sovereign-Recovery.iso"
