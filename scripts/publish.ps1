$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
dotnet publish "$repoRoot\CyberSensor\CyberSensor.csproj" -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=None -p:DebugSymbols=false -o "$repoRoot\publish\win-x64"
Write-Host "Готово: $repoRoot\publish\win-x64"
