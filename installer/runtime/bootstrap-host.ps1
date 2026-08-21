param(
    [Parameter(Mandatory=$true)][string]$InstallRoot,
    [Parameter(Mandatory=$true)][string]$DataRoot,
    [Parameter(Mandatory=$true)][string]$RequestFile
)

$ErrorActionPreference='Stop'
$sc=Join-Path $env:SystemRoot 'System32\sc.exe'
$request=Get-Content -LiteralPath $RequestFile -Raw | ConvertFrom-Json
$isRepair=([string]$request.operation -eq 'repair')

function Write-JsonUtf8([string]$Path,$Object){
    [IO.File]::WriteAllText($Path,($Object|ConvertTo-Json -Depth 12),(New-Object Text.UTF8Encoding($false)))
}
function Service-Exists([string]$Name){
    & $sc query $Name *> $null
    return $LASTEXITCODE -eq 0
}
function Invoke-Sc([string[]]$Arguments){
    & $sc @Arguments *> $null
    if($LASTEXITCODE -ne 0){ throw ('SC_FAILED:' + ($Arguments -join ' ') + ':' + $LASTEXITCODE) }
}

if(-not(Test-Path -LiteralPath (Join-Path $InstallRoot 'payload.sha256'))){ throw 'PAYLOAD_MANIFEST_MISSING' }
New-Item -ItemType Directory -Force -Path $DataRoot,(Join-Path $DataRoot 'root'),(Join-Path $DataRoot 'roles'),(Join-Path $DataRoot 'service-config'),(Join-Path $DataRoot 'rollback') | Out-Null

# During repair, services are quiesced first. Temporarily recover maintenance control
# over first-party state that may be owned by restricted service SIDs, then harden again below.
if($isRepair){
    & takeown.exe /F $DataRoot /R /D Y *> $null
    if($LASTEXITCODE -ne 0){ throw "REPAIR_TAKEOWN_FAILED:$LASTEXITCODE" }
    & icacls.exe $DataRoot /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' /T /C /Q *> $null
    if($LASTEXITCODE -ne 0){ throw "REPAIR_MAINTENANCE_ACL_FAILED:$LASTEXITCODE" }
}

# Base ACL: inheritable rights on DataRoot itself; direct rights on request file that existed before hardening.
& icacls.exe $DataRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' '*S-1-5-19:(OI)(CI)(RX)' /C /Q *> $null
if($LASTEXITCODE -ne 0){ throw "BASE_ACL_FAILED:$LASTEXITCODE" }
& icacls.exe $RequestFile /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' '*S-1-5-19:(R)' /C /Q *> $null
if($LASTEXITCODE -ne 0){ throw "REQUEST_ACL_FAILED:$LASTEXITCODE" }

& (Join-Path $InstallRoot 'host\provision-root.ps1') -InstallRoot $InstallRoot -DataRoot $DataRoot | Out-Host
$security=Get-Content -LiteralPath (Join-Path $DataRoot 'host-security.json') -Raw | ConvertFrom-Json

$contractPath=Join-Path $DataRoot 'system-contract.json'
$preserveContract=([string]$request.operation -eq 'repair' -and (Test-Path -LiteralPath $contractPath))
if(-not $preserveContract){
    $targetType=[string]$request.target_type
    $targetValue=[string]$request.target_value
    if([string]::IsNullOrWhiteSpace($targetType)){ $targetType='none' }
    if($targetType -eq 'this_pc'){ $targetValue=$env:COMPUTERNAME }

    if($targetType -eq 'none'){
        $contract=[ordered]@{
            schema=1; system_id=$null; name=$null; type='NONE'; target=$null
            mode_initial='CONTAINED_READ_ONLY'; state='UNATTACHED'; protected_systems=0; adapter=$null
            interfaces_allowed=@(); actions_allowed=@(); actions_prohibited=@('material_action_without_homologation')
            created_at_utc=[DateTime]::UtcNow.ToString('o')
        }
        $discovery=[ordered]@{state='NOT_REQUESTED';read_only=$true;target_type='none';observed_at_utc=[DateTime]::UtcNow.ToString('o')}
    } else {
        $sha=[Security.Cryptography.SHA256]::Create()
        try { $hash=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes("$targetType|$targetValue"))).Replace('-','').ToLowerInvariant()).Substring(0,12) }
        finally { $sha.Dispose() }
        $contract=[ordered]@{
            schema=1; system_id="$targetType-$hash"; name=$targetValue; type=$targetType; target=$targetValue
            mode_initial='READ_ONLY'; state='PENDING_HOMOLOGATION'; protected_systems=0; adapter=$null
            interfaces_allowed=@('discovery_read_only','health_check'); actions_allowed=@('observe','diagnose','test','health_check')
            actions_prohibited=@('material_action_without_policy_capability_checkpoint'); created_at_utc=[DateTime]::UtcNow.ToString('o')
        }
        $discovery=[ordered]@{state='RECORDED_READ_ONLY';read_only=$true;target_type=$targetType;target=$targetValue;observed_at_utc=[DateTime]::UtcNow.ToString('o')}
        if($targetType -eq 'this_pc'){
            try {
                $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
                $discovery.os_caption=[string]$os.Caption
                $discovery.os_version=[string]$os.Version
                $discovery.architecture=[string]$os.OSArchitecture
                $discovery.hostname=$env:COMPUTERNAME
            } catch { $discovery.discovery_error=$_.Exception.Message }
        } elseif($targetType -eq 'local_project') {
            try {
                $resolved=(Resolve-Path -LiteralPath $targetValue -ErrorAction Stop).Path
                $discovery.resolved_path=$resolved
                $discovery.top_level_files=@(Get-ChildItem -LiteralPath $resolved -File -ErrorAction Stop | Select-Object -First 200 Name,Length,LastWriteTimeUtc)
                $discovery.top_level_directories=@(Get-ChildItem -LiteralPath $resolved -Directory -ErrorAction Stop | Select-Object -First 200 Name,LastWriteTimeUtc)
            } catch { $discovery.discovery_error=$_.Exception.Message; $contract.state='DISCOVERY_BLOCKED' }
        }
    }
    Write-JsonUtf8 $contractPath $contract
    Write-JsonUtf8 (Join-Path $DataRoot 'discovery.json') $discovery
}

$roles=@(
    @{role='core';service='SistemaImuneCore';display='Sistema Imunologico - Sovereign Core'},
    @{role='vault';service='SistemaImuneVault';display='Sistema Imunologico - Memory Audit Vault'},
    @{role='policy';service='SistemaImunePolicy';display='Sistema Imunologico - Policy Authority'},
    @{role='execution';service='SistemaImuneExecution';display='Sistema Imunologico - Execution Broker'},
    @{role='gateway';service='SistemaImuneGateway';display='Sistema Imunologico - Immune Gateway'},
    @{role='provider';service='SistemaImuneProvider';display='Sistema Imunologico - Provider Proxy'},
    @{role='adapter';service='SistemaImuneAdapter';display='Sistema Imunologico - Adapter Manager'},
    @{role='watchdog';service='SistemaImuneWatchdog';display='Sistema Imunologico - Supervisor Watchdog'}
)

# Install and repair use the same deterministic service lifecycle.
# Reusing stopped SCM registrations proved unreliable during real repair testing.
foreach($role in $roles){
    if(Service-Exists $role.service){
        $svc=Get-Service -Name $role.service -ErrorAction SilentlyContinue
        if($svc -and $svc.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped){
            Stop-Service -Name $role.service -Force -ErrorAction SilentlyContinue
            $svc=Get-Service -Name $role.service -ErrorAction SilentlyContinue
            if($svc){$svc.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(20))}
        }
        & $sc delete $role.service *> $null
        if($LASTEXITCODE -notin @(0,1060)){ throw "SERVICE_DELETE_FAILED:$($role.service):$LASTEXITCODE" }
        $deadline=(Get-Date).AddSeconds(30)
        do { Start-Sleep -Milliseconds 250 } while((Service-Exists $role.service) -and (Get-Date) -lt $deadline)
        if(Service-Exists $role.service){ throw "SERVICE_DELETE_TIMEOUT:$($role.service)" }
    }
}

$serviceHost=Join-Path $InstallRoot 'host\ImmuneServiceHost.exe'
$python=Join-Path $InstallRoot 'runtime\python\python.exe'
$roleScript=Join-Path $InstallRoot 'host\role_runtime.py'
$configDir=Join-Path $DataRoot 'service-config'

foreach($role in $roles){
    $roleDir=Join-Path $DataRoot ('roles\'+$role.role)
    New-Item -ItemType Directory -Force -Path $roleDir | Out-Null
    $cfg=Join-Path $configDir ($role.role+'.ini')
    $runtimeArgs=('"{0}" --role {1} --install-root "{2}" --data-root "{3}"' -f $roleScript,$role.role,$InstallRoot,$DataRoot)
    [string[]]$cfgLines=@(
        ('service_name='+[string]$role.service)
        ('executable='+$python)
        ('arguments='+$runtimeArgs)
        ('working_directory='+(Join-Path $InstallRoot 'host'))
        ('log_file='+(Join-Path $roleDir 'service-host.log'))
    )
    [IO.File]::WriteAllLines($cfg,$cfgLines,(New-Object Text.UTF8Encoding($false)))
    $hostCheck=& $serviceHost '--config' $cfg '--console' 2>&1
    if($LASTEXITCODE -ne 0){ throw "SERVICE_HOST_CONFIG_INVALID:$($role.service):$($hostCheck -join ' | ')" }

    $binPath=('"{0}" --config "{1}"' -f $serviceHost,$cfg)
    if(-not(Service-Exists $role.service)){
    $createResult=Invoke-CimMethod -ClassName Win32_Service -MethodName Create -Arguments @{
        Name=[string]$role.service
        DisplayName=[string]$role.display
        PathName=$binPath
        ServiceType=[byte]16
        ErrorControl=[byte]1
        StartMode='Automatic'
        DesktopInteract=$false
        StartName='NT AUTHORITY\LocalService'
        StartPassword=$null
    }
    if([int]$createResult.ReturnValue -ne 0){ throw "SERVICE_CREATE_FAILED:$($role.service):$($createResult.ReturnValue)" }
    }
    Invoke-Sc -Arguments @('description',$role.service,'Sovereign component of Sistema Imunologico. Managed by installer.')
    Invoke-Sc -Arguments @('sidtype',$role.service,'restricted')
    Invoke-Sc -Arguments @('failure',$role.service,'reset=','86400','actions=','restart/5000/restart/15000/restart/60000')

    & icacls.exe $InstallRoot /grant ("NT SERVICE\$($role.service):(OI)(CI)(RX)") /T /C /Q *> $null
    if($LASTEXITCODE -ne 0){ throw "INSTALL_ACL_FAILED:$($role.service):$LASTEXITCODE" }
    & icacls.exe $cfg /grant ("NT SERVICE\$($role.service):(R)") /C /Q *> $null
    if($LASTEXITCODE -ne 0){ throw "CONFIG_ACL_FAILED:$($role.service):$LASTEXITCODE" }
    # Apply inheritable ACLs to directories, and effective direct ACLs to existing files.
    # OI/CI grants applied recursively to existing files can leave them without an effective ACE.
    & icacls.exe $roleDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' ("NT SERVICE\$($role.service):(OI)(CI)(M)") /C /Q *> $null
    if($LASTEXITCODE -ne 0){ throw "ROLE_DIR_ACL_FAILED:$($role.service):$LASTEXITCODE" }
    foreach($childDir in @(Get-ChildItem -LiteralPath $roleDir -Directory -Recurse -Force -ErrorAction SilentlyContinue)){
        & icacls.exe $childDir.FullName /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' ("NT SERVICE\$($role.service):(OI)(CI)(M)") /C /Q *> $null
        if($LASTEXITCODE -ne 0){ throw "ROLE_CHILD_DIR_ACL_FAILED:$($role.service):$LASTEXITCODE" }
    }
    foreach($childFile in @(Get-ChildItem -LiteralPath $roleDir -File -Recurse -Force -ErrorAction SilentlyContinue)){
        & icacls.exe $childFile.FullName /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' ("NT SERVICE\$($role.service):(M)") /C /Q *> $null
        if($LASTEXITCODE -ne 0){ throw "ROLE_FILE_ACL_FAILED:$($role.service):$LASTEXITCODE" }
    }    & icacls.exe (Join-Path $DataRoot 'root') /grant ("NT SERVICE\$($role.service):(OI)(CI)(RX)") /T /C /Q *> $null
    if($LASTEXITCODE -ne 0){ throw "ROOT_ACL_FAILED:$($role.service):$LASTEXITCODE" }
    & icacls.exe $contractPath /grant ("NT SERVICE\$($role.service):(R)") /C /Q *> $null
    if($LASTEXITCODE -ne 0){ throw "CONTRACT_ACL_FAILED:$($role.service):$LASTEXITCODE" }
    & icacls.exe (Join-Path $DataRoot 'host-security.json') /grant ("NT SERVICE\$($role.service):(R)") /C /Q *> $null
    if($LASTEXITCODE -ne 0){ throw "SECURITY_ACL_FAILED:$($role.service):$LASTEXITCODE" }
}

$blockedNetworkServices=@('SistemaImuneCore','SistemaImuneVault','SistemaImunePolicy','SistemaImuneExecution','SistemaImuneAdapter','SistemaImuneWatchdog')
foreach($svc in $blockedNetworkServices){
    $ruleName="Sistema Imunologico - deny outbound - $svc"
    Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Action Block -Service $svc -Profile Any | Out-Null
}

# Allow the SCM and service-SID metadata to settle after deterministic recreation.
Start-Sleep -Seconds 3
foreach($role in $roles){
    $started=$false
    $lastCode=$null
    $lastOutput=''
    for($attempt=1; $attempt -le 6 -and -not $started; $attempt++){
        $svc=Get-Service -Name $role.service -ErrorAction Stop
        $svc.Refresh()
        if($svc.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running){
            $started=$true
            break
        }
        $out=& $sc start $role.service 2>&1
        $lastCode=$LASTEXITCODE
        $lastOutput=($out -join ' | ')
        if($lastCode -in @(0,1056)){
            try {
                $svc=Get-Service -Name $role.service -ErrorAction Stop
                $svc.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(12))
            } catch { }
            $svc=Get-Service -Name $role.service -ErrorAction Stop
            $svc.Refresh()
            if($svc.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running){
                $started=$true
                break
            }
        }
        Start-Sleep -Seconds 2
    }
    if(-not $started){
        $svc=Get-Service -Name $role.service -ErrorAction SilentlyContinue
        $state=if($svc){[string]$svc.Status}else{'MISSING'}
        throw "SERVICE_START_FAILED:$($role.service):STATE=${state}:SC=${lastCode}:OUT=${lastOutput}"
    }
}
Start-Sleep -Seconds 5

$state=[ordered]@{
    schema=1; installer_version=[string]$request.installer_version; core_version=[string]$request.core_version
    core_commit=[string]$request.core_commit; installed_at_utc=[DateTime]::UtcNow.ToString('o')
    root_attested=[bool]$security.root_attested; state='CONTAINED_READ_ONLY'; protected_systems=0
    target_contract=$contractPath; service_count=$roles.Count
}
Write-JsonUtf8 (Join-Path $DataRoot 'install-state.json') $state

& (Join-Path $InstallRoot 'host\self-test.ps1') -InstallRoot $InstallRoot -DataRoot $DataRoot
if($LASTEXITCODE -ne 0){ throw "INSTALLER_SELF_TEST_FAILED:$LASTEXITCODE" }

Write-Output 'BOOTSTRAP_HOST=PASS'
Write-Output "ROOT_ATTESTED=$($security.root_attested)"
Write-Output 'MODE=CONTAINED_READ_ONLY'
exit 0
