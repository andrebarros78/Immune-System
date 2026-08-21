param(
    [Parameter(Mandatory=$true)][string]$InstallRoot,
    [Parameter(Mandatory=$true)][string]$DataRoot
)

$ErrorActionPreference='Stop'
$ExpectedInstall='C:\Program Files\BarrosTech\Sistema Imunologico'
$ExpectedData='C:\ProgramData\BarrosTech\Sistema Imunologico'
function Canon([string]$Path){ return [IO.Path]::GetFullPath($Path).TrimEnd('\\') }
if((Canon $InstallRoot) -ne (Canon $ExpectedInstall)){ throw "UNINSTALL_SCOPE_BLOCKED_INSTALL:$InstallRoot" }
if((Canon $DataRoot) -ne (Canon $ExpectedData)){ throw "UNINSTALL_SCOPE_BLOCKED_DATA:$DataRoot" }

$sc=Join-Path $env:SystemRoot 'System32\sc.exe'
$services=@('SistemaImuneCore','SistemaImuneVault','SistemaImunePolicy','SistemaImuneExecution','SistemaImuneGateway','SistemaImuneProvider','SistemaImuneAdapter','SistemaImuneWatchdog')

foreach($name in $services){
    $svc=Get-Service -Name $name -ErrorAction SilentlyContinue
    if($svc){
        if($svc.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped){
            Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
            try {
                $svc=Get-Service -Name $name -ErrorAction Stop
                $svc.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(20))
            } catch { }
        }
        & $sc delete $name *> $null
    }
}

# Wait for SCM deletion and first-party service host processes to exit.
$deadline=(Get-Date).AddSeconds(25)
do {
    $remaining=@($services | Where-Object { Get-Service -Name $_ -ErrorAction SilentlyContinue })
    $procs=@(Get-CimInstance Win32_Process -Filter "Name='ImmuneServiceHost.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.ExecutablePath -and (Canon $_.ExecutablePath).StartsWith((Canon $InstallRoot),[StringComparison]::OrdinalIgnoreCase) })
    if($remaining.Count -eq 0 -and $procs.Count -eq 0){ break }
    Start-Sleep -Milliseconds 400
} while((Get-Date) -lt $deadline)

foreach($p in @($procs)){
    try { Stop-Process -Id ([int]$p.ProcessId) -Force -ErrorAction Stop } catch { }
}

Get-NetFirewallRule -DisplayName 'Sistema Imunologico - deny outbound - *' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

# Maintenance ACL recovery is limited to the two canonical first-party paths.
if(Test-Path -LiteralPath $InstallRoot){
    & takeown.exe /F $InstallRoot /R /D Y *> $null
    & icacls.exe $InstallRoot /grant:r '*S-1-5-32-544:(OI)(CI)(F)' '*S-1-5-18:(OI)(CI)(F)' /T /C /Q *> $null
    if($LASTEXITCODE -ne 0){ throw "UNINSTALL_INSTALL_ACL_RECOVERY_FAILED:$LASTEXITCODE" }
}
if(Test-Path -LiteralPath $DataRoot){
    & takeown.exe /F $DataRoot /R /D Y *> $null
    & icacls.exe $DataRoot /grant:r '*S-1-5-32-544:(OI)(CI)(F)' '*S-1-5-18:(OI)(CI)(F)' /T /C /Q *> $null
    if($LASTEXITCODE -ne 0){ throw "UNINSTALL_DATA_ACL_RECOVERY_FAILED:$LASTEXITCODE" }
}

New-Item -ItemType Directory -Force -Path $DataRoot | Out-Null
[IO.File]::WriteAllText((Join-Path $DataRoot 'UNINSTALLED.txt'),[DateTime]::UtcNow.ToString('o'),(New-Object Text.UTF8Encoding($false)))
Write-Output 'UNINSTALL_HOST=PASS'
exit 0
