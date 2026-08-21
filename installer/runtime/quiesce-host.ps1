param(
    [Parameter(Mandatory=$true)][string]$InstallRoot,
    [Parameter(Mandatory=$true)][string]$DataRoot
)

$ErrorActionPreference='Stop'
$services=@('SistemaImuneCore','SistemaImuneVault','SistemaImunePolicy','SistemaImuneExecution','SistemaImuneGateway','SistemaImuneProvider','SistemaImuneAdapter','SistemaImuneWatchdog')
$ownedPids=New-Object System.Collections.Generic.HashSet[int]

foreach($name in $services){
    $cim=Get-CimInstance Win32_Service -Filter ("Name='"+$name+"'") -ErrorAction SilentlyContinue
    if($cim -and [int]$cim.ProcessId -gt 0){[void]$ownedPids.Add([int]$cim.ProcessId)}
    $svc=Get-Service -Name $name -ErrorAction SilentlyContinue
    if(-not $svc){ continue }
    if($svc.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped){
        Stop-Service -Name $name -Force -ErrorAction Stop
        $svc=Get-Service -Name $name -ErrorAction Stop
        $svc.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(20))
        $svc.Refresh()
        if($svc.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped){ throw "QUIESCE_TIMEOUT:${name}:$($svc.Status)" }
    }
}

# SCM can report STOPPED slightly before the service process and child runtime are fully gone.
$deadline=(Get-Date).AddSeconds(15)
do {
    $alive=@($ownedPids | Where-Object { Get-Process -Id $_ -ErrorAction SilentlyContinue })
    if($alive.Count -eq 0){break}
    Start-Sleep -Milliseconds 250
} while((Get-Date) -lt $deadline)

foreach($pidValue in @($ownedPids)){
    if(Get-Process -Id $pidValue -ErrorAction SilentlyContinue){
        Stop-Process -Id $pidValue -Force -ErrorAction Stop
    }
}

# Kill only orphaned first-party role runtimes from this exact installation.
$escaped=$InstallRoot.Replace('\','\\')
$orphans=@(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -eq 'python.exe' -and $_.CommandLine -and $_.CommandLine -like ('*'+$InstallRoot+'*host\role_runtime.py*')
})
foreach($proc in $orphans){
    Stop-Process -Id ([int]$proc.ProcessId) -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Milliseconds 500
Write-Output 'QUIESCE_HOST=PASS'
Write-Output ("QUIESCE_SERVICE_PIDS="+$ownedPids.Count)
Write-Output ("QUIESCE_ORPHANS_KILLED="+$orphans.Count)
exit 0