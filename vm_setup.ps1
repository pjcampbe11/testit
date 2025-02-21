Write-Host "Starting Unified Commando & FLARE VM setup..." -ForegroundColor Yellow

# Check if running as administrator
function Test-Admin {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Host "This script must be run as an Administrator." -ForegroundColor Red
    exit 1
}

Write-Host "Disabling Windows Defender and Tamper Protection..." -ForegroundColor Yellow
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"
$registryName = "TamperProtection"
$value = 0

if (Test-Path $registryPath) {
    Set-ItemProperty -Path $registryPath -Name $registryName -Value $value -Force
    Write-Host "Tamper Protection disabled." -ForegroundColor Green
} else {
    Write-Host "Tamper Protection registry path not found." -ForegroundColor Red
}

Start-Sleep -Seconds 5

Write-Host "Disabling Real-Time Protection and Microsoft Defender via Group Policy..." -ForegroundColor Yellow
$policies = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
)

foreach ($path in $policies) {
    if (-not (Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 1 -Force

Write-Host "Applying Group Policy changes..." -ForegroundColor Yellow
Start-Process -FilePath "gpupdate.exe" -ArgumentList "/force" -Wait

Write-Host "Installing Commando & FLARE VM dependencies..." -ForegroundColor Yellow
Set-ExecutionPolicy Unrestricted -Scope CurrentUser -Force
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Host "Downloading Commando VM setup script..." -ForegroundColor Yellow
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/fireeye/commando-vm/master/commando-vm.ps1" -OutFile "$env:TEMP\commando-vm.ps1"

Write-Host "Running Commando VM setup..." -ForegroundColor Yellow
Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File $env:TEMP\commando-vm.ps1" -NoNewWindow -Wait

Write-Host "Downloading FLARE VM setup script..." -ForegroundColor Yellow
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/fireeye/flare-vm/master/flarevm-install.ps1" -OutFile "$env:TEMP\flarevm-install.ps1"

Write-Host "Running FLARE VM setup..." -ForegroundColor Yellow
Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File $env:TEMP\flarevm-install.ps1" -NoNewWindow -Wait

Write-Host "Rebooting system in 10 seconds to finalize changes..." -ForegroundColor Cyan
Start-Sleep -Seconds 10
Restart-Computer -Force
