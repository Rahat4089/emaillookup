param(
    [string]$ToolsDir = ".\tools"
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Download-LatestGitHubAsset {
    param(
        [Parameter(Mandatory = $true)][string]$Repo,
        [Parameter(Mandatory = $true)][string]$Pattern,
        [Parameter(Mandatory = $true)][string]$OutputPath
    )

    $api = "https://api.github.com/repos/$Repo/releases/latest"
    $release = Invoke-RestMethod -Uri $api -Headers @{ "User-Agent" = "apk-patcher-bootstrap" }
    $asset = $release.assets | Where-Object { $_.name -match $Pattern } | Select-Object -First 1
    if (-not $asset) {
        throw "No asset matching '$Pattern' found in $Repo latest release."
    }

    Write-Host "Downloading $($asset.name)..."
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $OutputPath
}

function Try-InstallJava {
    Write-Host "Checking Java runtime..."
    if (Get-Command java -ErrorAction SilentlyContinue) {
        Write-Host "Java already found in PATH."
        return
    }

    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Warning "winget not found. Install Java (JRE/JDK 17+) manually."
        return
    }

    Write-Host "Installing Java runtime with winget..."
    $javaIds = @(
        "EclipseAdoptium.Temurin.17.JRE",
        "EclipseAdoptium.Temurin.17.JDK",
        "Microsoft.OpenJDK.17"
    )

    foreach ($id in $javaIds) {
        try {
            winget install --id $id --silent --accept-source-agreements --accept-package-agreements
            Write-Host "Installed: $id"
            return
        }
        catch {
            Write-Warning "winget install failed for $id, trying next option..."
        }
    }

    Write-Warning "Java installation via winget failed. Install Java 17+ manually."
}

function Copy-AndroidBuildToolsIfAvailable {
    param([string]$Destination)

    $androidRoots = @()
    if ($env:ANDROID_HOME) { $androidRoots += $env:ANDROID_HOME }
    if ($env:ANDROID_SDK_ROOT) { $androidRoots += $env:ANDROID_SDK_ROOT }
    $androidRoots += "$env:LOCALAPPDATA\Android\Sdk"

    foreach ($root in $androidRoots | Select-Object -Unique) {
        if (-not (Test-Path $root)) { continue }
        $buildTools = Join-Path $root "build-tools"
        if (-not (Test-Path $buildTools)) { continue }

        $latest = Get-ChildItem $buildTools -Directory | Sort-Object Name -Descending | Select-Object -First 1
        if (-not $latest) { continue }

        $zipalign = Join-Path $latest.FullName "zipalign.exe"
        $apksignerBat = Join-Path $latest.FullName "apksigner.bat"

        if (Test-Path $zipalign) {
            Copy-Item $zipalign (Join-Path $Destination "zipalign.exe") -Force
            Write-Host "Copied zipalign.exe from Android SDK."
        }

        if (Test-Path $apksignerBat) {
            Copy-Item $apksignerBat (Join-Path $Destination "apksigner.bat") -Force
            Write-Host "Copied apksigner.bat from Android SDK."
        }

        if (Test-Path (Join-Path $latest.FullName "lib")) {
            Copy-Item (Join-Path $latest.FullName "lib") (Join-Path $Destination "lib") -Recurse -Force
            Write-Host "Copied apksigner support lib/ directory from Android SDK."
        }

        return
    }

    Write-Warning "Android SDK build-tools not found. zipalign/apksigner will remain optional."
}

Write-Host "Preparing tools folder..."
New-Item -ItemType Directory -Path $ToolsDir -Force | Out-Null

Try-InstallJava

$apktoolTarget = Join-Path $ToolsDir "apktool.jar"
$uberSignerTarget = Join-Path $ToolsDir "uber-apk-signer.jar"

Download-LatestGitHubAsset -Repo "iBotPeaches/Apktool" -Pattern "apktool_.*\.jar$" -OutputPath $apktoolTarget
Download-LatestGitHubAsset -Repo "patrickfav/uber-apk-signer" -Pattern "uber-apk-signer.*\.jar$" -OutputPath $uberSignerTarget

Copy-AndroidBuildToolsIfAvailable -Destination $ToolsDir

Write-Host ""
Write-Host "Bootstrap complete."
Write-Host "Tools installed under: $((Resolve-Path $ToolsDir).Path)"
Write-Host "Optional: place debug.keystore in tools\debug.keystore to skip key generation."
