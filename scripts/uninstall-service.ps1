$ErrorActionPreference = "Stop"
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw "Требуются права администратора." }
sc.exe stop CyberSensor 2>$null
sc.exe delete CyberSensor
Write-Host "Служба CyberSensor удалена."
