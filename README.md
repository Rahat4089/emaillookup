# AI Network Security APK Patcher

Windows desktop tool (WinForms) to patch Android APKs so they always use a network security config.

## What it does

For each input package (`.apk`, `.xapk`, `.apkm`, `.apks`), the app:

1. Extracts base APK when needed.
2. Decompiles with apktool.
3. Writes `res/xml/network_security_config.xml` every time (hardcoded template).
4. Updates `AndroidManifest.xml`:
   - `android:networkSecurityConfig="@xml/network_security_config"`
   - `android:usesCleartextTraffic="true"`
   - If `<application>` is missing, it is created.
5. Rebuilds, aligns (if zipalign exists), signs, and outputs patched APK.
6. Handles errors with clear per-step logs.

## Tool requirements

At minimum:

- Java 17+
- apktool (`apktool.jar` or apktool executable)
- One signer option:
  - `apksigner`, or
  - `jarsigner`, or
  - `uber-apk-signer.jar`

Optional but recommended:

- `zipalign`

The app checks `./tools` first, then PATH.

## Quick setup (Windows PowerShell)

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install-requirements.ps1
```

This script:

- Attempts to install Java via winget (if missing).
- Downloads latest `apktool.jar`.
- Downloads latest `uber-apk-signer.jar`.
- Copies Android SDK `zipalign` / `apksigner` if found.

## Build EXE

### Prerequisite

- .NET SDK 8.0+

### Publish single-file Windows executable

```powershell
.\build-exe.ps1
```

Output:

- `bin\Release\net8.0-windows\win-x64\publish\AiNetworkSecurityApkPatcher.exe`

## Run

1. Start the EXE.
2. Drag and drop APK/APKS/XAPK/APKM files.
3. Click **PATCH NETWORK SECURITY (AI MODE)**.
4. Get output APKs in Desktop folder:
   - `APK_NETWORK_PATCHED`

## Template XML

Default template is in `network_security_config.xml`.
You can edit this file to customize behavior; app falls back to built-in template if the file is missing or invalid.

## Notes

- This tool modifies app security settings and re-signs APKs.
- Re-signed APKs are not signed with original developer keys.
- Use only where you are legally authorized to modify the APK.