$ErrorActionPreference = "Stop"
$exe = Join-Path (Split-Path -Parent $PSScriptRoot) "publish\win-x64\CyberSensor.exe"
if (-not (Test-Path $exe)) { throw "Не найден $exe. Сначала выполните publish.ps1." }
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw "Требуются права администратора." }
sc.exe create CyberSensor binPath= "`"$exe`"" start= auto DisplayName= "CyberSensor Network Sensor"
sc.exe description CyberSensor "Локальный сенсор обнаружения вторжений (NDR)"
Write-Host "Служба CyberSensor установлена."
