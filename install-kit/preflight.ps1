# Read-only native Windows preparation. Run the Linux check inside WSL too.
[CmdletBinding()]
param([switch]$Report)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$checks = [System.Collections.Generic.List[object]]::new()
$script:hasFailure = $false
function Add-Check([string]$Code, [string]$Outcome, [string]$Message) {
    $checks.Add(@{code=$Code; outcome=$Outcome; checked_at=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')})
    if ($Outcome -eq 'fail') { $script:hasFailure = $true }
    if (-not $Report) { Write-Output $Message }
}
if (-not $Report) {
    Write-Output 'Files stay on your machine. Buyers receive copies. ai.market receives only approved information about them.'
    Write-Output 'Use your own secure web address. Ask IT to review the installation guide before making changes.'
    Write-Output 'This PC must stay awake with Docker running. After a reboot, sign in and start Docker to restore downloads.'
    Write-Output 'Your company may need a paid Docker Desktop licence. Ask IT to confirm the licence before installation.'
}
$isTarget = $false
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $isTarget = $os.Caption -match 'Windows 11' -and $env:PROCESSOR_ARCHITECTURE -eq 'AMD64'
} catch { $isTarget = $false }
if ($isTarget) {
    Add-Check 'platform' 'pass' 'This is a target Windows setup. IT must still complete the clean installation checks.'
} else {
    Add-Check 'platform' 'fail' 'This check could not confirm Windows 11 on this PC. Ask IT to use Windows 11 Home with WSL2 or a Linux server.'
}
try {
    $processors = @(Get-CimInstance Win32_Processor -ErrorAction Stop)
    if ($processors.Count -gt 0 -and @($processors | Where-Object { -not $_.VirtualizationFirmwareEnabled }).Count -eq 0) {
        Add-Check 'virtualization' 'pass' 'Hardware support is enabled. Continue with the local checks.'
    } else {
        Add-Check 'virtualization' 'fail' 'Hardware support is turned off. Ask IT to enable virtualization in the PC settings, then reboot and rerun this check.'
    }
} catch {
    Add-Check 'virtualization' 'unknown' 'The PC settings could not be read. Ask IT to check virtualization locally, then rerun this check.'
}
if (Get-Command wsl.exe -ErrorAction SilentlyContinue) {
    $savedEncoding = [Console]::OutputEncoding
    try {
        [Console]::OutputEncoding = [System.Text.Encoding]::Unicode
        $wslOutput = & wsl.exe --list --verbose 2>$null
        if ($LASTEXITCODE -eq 0 -and ($wslOutput -join "`n") -match '\s2\s*$|\s2\s*\r?\n') {
            Add-Check 'wsl' 'pass' 'WSL2 is present. Run the Linux preparation check inside your serving distribution too.'
        } else {
            Add-Check 'wsl' 'fail' 'WSL2 is not ready. Ask IT to install or update WSL2, reboot if requested, then rerun this check.'
        }
    } finally { [Console]::OutputEncoding = $savedEncoding }
} else {
    Add-Check 'wsl' 'fail' 'WSL is missing. Ask IT to install WSL2 and reboot, then rerun this check.'
}
if (Get-Command docker -ErrorAction SilentlyContinue) {
    Add-Check 'docker_installed' 'pass' 'Docker is installed. Continue with the local checks.'
    $engine = & docker info --format '{{.OSType}}' 2>$null
    if ($LASTEXITCODE -ne 0) {
        Add-Check 'docker_running' 'fail' 'Docker is installed but is not running. Open Docker Desktop, wait for it to start, then rerun this check.'
        Add-Check 'linux_containers' 'unknown' 'The container setting could not be read. Start Docker, select Linux containers, then rerun this check.'
    } else {
        Add-Check 'docker_running' 'pass' 'Docker is running. Continue with the local checks.'
        if ($engine.Trim() -eq 'linux') {
            Add-Check 'linux_containers' 'pass' 'Linux containers are selected. Continue with the local checks.'
        } else {
            Add-Check 'linux_containers' 'fail' 'Docker is using Windows containers. Switch Docker Desktop to Linux containers, then rerun this check.'
        }
    }
} else {
    Add-Check 'docker_installed' 'fail' 'Docker is missing. Ask IT to install Docker Desktop, confirm the licence, then rerun this check.'
    Add-Check 'docker_running' 'unknown' 'Docker could not be checked. Install and start Docker, then rerun this check.'
    Add-Check 'linux_containers' 'unknown' 'The container setting could not be checked. Install Docker and select Linux containers, then rerun this check.'
}
# Read current mains/battery sleep and lid policy without changing either.
# Even a disabled timeout cannot certify future uptime or sign-out recovery.
$sleepOutcome = 'unknown'
if (Get-Command powercfg.exe -ErrorAction SilentlyContinue) {
    try {
        $sleepSettings = & powercfg.exe /query SCHEME_CURRENT SUB_SLEEP STANDBYIDLE 2>$null
        $sleepRead = $LASTEXITCODE -eq 0
        $lidSettings = & powercfg.exe /query SCHEME_CURRENT SUB_BUTTONS LIDACTION 2>$null
        $lidRead = $LASTEXITCODE -eq 0
        $sleepIndices = [regex]::Matches(($sleepSettings -join "`n"), '0x[0-9a-fA-F]{8}')
        $lidIndices = [regex]::Matches(($lidSettings -join "`n"), '0x[0-9a-fA-F]{8}')
        if ($sleepRead -and $lidRead -and $sleepIndices.Count -eq 2 -and $lidIndices.Count -eq 2) {
            if (@($sleepIndices | Where-Object { [Convert]::ToUInt32($_.Value.Substring(2), 16) -gt 0 }).Count -gt 0 -or
                @($lidIndices | Where-Object { [Convert]::ToUInt32($_.Value.Substring(2), 16) -gt 0 }).Count -gt 0) {
                $sleepOutcome = 'fail'
            }
        }
    } catch { $sleepOutcome = 'unknown' }
}
Add-Check 'sleep_policy' $sleepOutcome 'This PC may sleep or stop downloads when its lid closes. Ask IT to review mains and battery settings, then test sleep and wake under company policy.'
$signinOutcome = 'unknown'
try {
    $settingsPath = Join-Path $env:APPDATA 'Docker/settings-store.json'
    if (Test-Path -LiteralPath $settingsPath -PathType Leaf) {
        $desktopSettings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
        if ($desktopSettings.PSObject.Properties.Name -contains 'autoStart' -and $desktopSettings.autoStart -eq $false) {
            $signinOutcome = 'fail'
        }
    }
} catch { $signinOutcome = 'unknown' }
Add-Check 'signin_start' $signinOutcome 'Downloads may wait after a reboot. Ask IT to enable Docker start at sign-in and test reboot, sign-in and sign-out recovery.'
Add-Check 'docker_licence' 'unknown' 'The licence needs a human check. Ask IT to confirm your company can use Docker Desktop before installation.'
foreach ($code in @('source_uid','state_write','hardening','image_digest','subnet_port','connect_proxy','egress','tls_inspection','upstream_proxy','tunnel','public_dns','firewall','tls_proxy','integrity')) {
    Add-Check $code 'unknown' 'The Windows preparation check does not prove file access or network safety. Run the Linux check inside WSL, then ask IT to complete the release checks.'
}
if ($Report) {
    @{schema_version=1; kit_version='0.0.0-c0'; platform='windows_wsl2'; generated_at=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'); checks=@($checks.ToArray())} | ConvertTo-Json -Depth 5 -Compress
} else {
    Write-Output 'Preparation is incomplete. Follow the installation guide with IT. Nothing was installed, started or uploaded.'
}
if ($script:hasFailure) { exit 1 }
exit 2
