param(
    [string]$Configuration = "Release",
    [string]$Runtime = "win-x64"
)

$ErrorActionPreference = "Stop"

Write-Host "Restoring packages..."
dotnet restore ".\APKPatcher.csproj"

Write-Host "Publishing single-file executable..."
dotnet publish ".\APKPatcher.csproj" `
  -c $Configuration `
  -r $Runtime `
  --self-contained true `
  /p:PublishSingleFile=true `
  /p:IncludeNativeLibrariesForSelfExtract=true `
  /p:PublishTrimmed=false

$publishDir = Join-Path $PSScriptRoot "bin\$Configuration\net8.0-windows\$Runtime\publish"
Write-Host ""
Write-Host "Done."
Write-Host "Publish folder: $publishDir"
