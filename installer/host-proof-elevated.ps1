param()
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'

$ProjectRoot='C:\New Projet\SISTEMA-IMUNOLOGICO-WORK'
$Setup=Join-Path $ProjectRoot 'installer\dist\Sistema-Imunologico-Setup.exe'
$InstallRoot='C:\Program Files\BarrosTech\Sistema Imunologico'
$DataRoot='C:\ProgramData\BarrosTech\Sistema Imunologico'
$ProofRoot='C:\ProgramData\BarrosTech\Sistema Imunologico-Proof'
$Log=Join-Path $ProofRoot 'HOST_INSTALL_PROOF.log'
$Json=Join-Path $ProofRoot 'HOST_INSTALL_PROOF.json'
$services=@('SistemaImuneCore','SistemaImuneVault','SistemaImunePolicy','SistemaImuneExecution','SistemaImuneGateway','SistemaImuneProvider','SistemaImuneAdapter','SistemaImuneWatchdog')
$blocked=@('SistemaImuneCore','SistemaImuneVault','SistemaImunePolicy','SistemaImuneExecution','SistemaImuneAdapter','SistemaImuneWatchdog')

New-Item -ItemType Directory -Force -Path $ProofRoot | Out-Null
if(Test-Path -LiteralPath $Log){Remove-Item -LiteralPath $Log -Force}

function Log([string]$Message){
    Add-Content -LiteralPath $Log -Value (([DateTime]::UtcNow.ToString('o'))+' '+$Message) -Encoding UTF8
}
function Fail([string]$Message){
    Log ('FAIL='+$Message)
    throw $Message
}
function Exact([string]$Path){
    return [IO.Path]::GetFullPath($Path).TrimEnd('\')
}
function SafeRemove([string]$Path){
    $target=Exact $Path
    $allowed=@((Exact $InstallRoot),(Exact $DataRoot))
    if($allowed -notcontains $target){throw "SAFE_REMOVE_BLOCKED:$target"}
    if(-not(Test-Path -LiteralPath $target)){return}

    Log "SAFE_REMOVE_BEGIN=$target"
    try{& takeown.exe /F $target /R /D Y *> $null}catch{}
    try{& icacls.exe $target /grant:r '*S-1-5-32-544:(OI)(CI)(F)' '*S-1-5-18:(OI)(CI)(F)' /C /Q *> $null}catch{}

    foreach($file in @(Get-ChildItem -LiteralPath $target -File -Recurse -Force -ErrorAction SilentlyContinue)){
        & icacls.exe $file.FullName /grant:r '*S-1-5-32-544:(F)' '*S-1-5-18:(F)' /C /Q *> $null
    }
    foreach($dir in @(Get-ChildItem -LiteralPath $target -Directory -Recurse -Force -ErrorAction SilentlyContinue | Sort-Object { $_.FullName.Length } -Descending)){
        & icacls.exe $dir.FullName /grant:r '*S-1-5-32-544:(OI)(CI)(F)' '*S-1-5-18:(OI)(CI)(F)' /C /Q *> $null
    }

    Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction Stop
    Log "SAFE_REMOVE_PASS=$target"
}
function RunSetup([string]$Name,[string[]]$SetupArgs){
    if($null -eq $SetupArgs -or $SetupArgs.Count -eq 0){Fail "$Name argument list empty"}
    Log ("START=$Name ARGS="+($SetupArgs -join ' '))
    $proc=Start-Process -FilePath $Setup -ArgumentList $SetupArgs -Wait -PassThru -WindowStyle Hidden
    Log ("END=$Name EXIT_CODE="+$proc.ExitCode)
    if($proc.ExitCode -ne 0){Fail "$Name exit code $($proc.ExitCode)"}
}
function Snapshot([string]$Stage){
    $svc=foreach($name in $services){
        $s=Get-CimInstance Win32_Service -Filter ("Name='"+$name+"'") -ErrorAction SilentlyContinue
        if($s){[ordered]@{name=$name;state=$s.State;start_mode=$s.StartMode;account=$s.StartName;path=$s.PathName}}
        else{[ordered]@{name=$name;state='MISSING'}}
    }
    $fw=foreach($name in $blocked){
        $rn="Sistema Imunologico - deny outbound - $name"
        $r=Get-NetFirewallRule -DisplayName $rn -ErrorAction SilentlyContinue
        [ordered]@{service=$name;exists=[bool]$r;enabled=if($r){[string]$r.Enabled}else{$null};action=if($r){[string]$r.Action}else{$null}}
    }
    $security=if(Test-Path (Join-Path $DataRoot 'host-security.json')){Get-Content (Join-Path $DataRoot 'host-security.json') -Raw|ConvertFrom-Json}else{$null}
    $state=if(Test-Path (Join-Path $DataRoot 'install-state.json')){Get-Content (Join-Path $DataRoot 'install-state.json') -Raw|ConvertFrom-Json}else{$null}
    $contract=if(Test-Path (Join-Path $DataRoot 'system-contract.json')){Get-Content (Join-Path $DataRoot 'system-contract.json') -Raw|ConvertFrom-Json}else{$null}
    [ordered]@{stage=$Stage;at_utc=[DateTime]::UtcNow.ToString('o');install_root_exists=(Test-Path $InstallRoot);data_root_exists=(Test-Path $DataRoot);services=@($svc);firewall=@($fw);security=$security;install_state=$state;contract=$contract}
}
function AssertInstalled([string]$Stage){
    if(-not(Test-Path $InstallRoot)){Fail "$Stage install root missing"}
    if(-not(Test-Path $DataRoot)){Fail "$Stage data root missing"}

    $lock=Get-Content (Join-Path $InstallRoot 'release-lock.txt') -Raw
    if($lock -notmatch 'CORE_TAG=v1\.1\.1'){Fail "$Stage core tag mismatch"}
    if($lock -notmatch 'CORE_COMMIT=d4750b24336d9b88663473d2db32a796e419e46f'){Fail "$Stage core commit mismatch"}

    $contract=Get-Content (Join-Path $DataRoot 'system-contract.json') -Raw|ConvertFrom-Json
    if([int]$contract.protected_systems -ne 0){Fail "$Stage protected_systems != 0"}
    if([string]$contract.state -ne 'UNATTACHED'){Fail "$Stage contract state != UNATTACHED"}

    $security=Get-Content (Join-Path $DataRoot 'host-security.json') -Raw|ConvertFrom-Json
    if(-not[bool]$security.secure_boot){Fail "$Stage secure boot not proven"}
    if(-not[bool]$security.tpm_present){Fail "$Stage TPM absent"}
    if(-not[bool]$security.tpm_ready){Fail "$Stage TPM not ready"}
    if(-not[bool]$security.root_attested){Fail "$Stage root not attested: $($security.reason)"}

    foreach($name in $services){
        $s=Get-Service -Name $name -ErrorAction SilentlyContinue
        if(-not$s){Fail "$Stage service missing: $name"}
        if($s.Status -ne 'Running'){Fail "$Stage service not running: $name/$($s.Status)"}
    }
    foreach($name in $blocked){
        $r=Get-NetFirewallRule -DisplayName "Sistema Imunologico - deny outbound - $name" -ErrorAction SilentlyContinue
        if(-not$r){Fail "$Stage firewall missing: $name"}
        if([string]$r.Action -ne 'Block'){Fail "$Stage firewall invalid: $name"}
    }

    $self=& (Join-Path $InstallRoot 'host\self-test.ps1') -InstallRoot $InstallRoot -DataRoot $DataRoot 2>&1
    $self|ForEach-Object{Log ("SELFTEST[$Stage]="+[string]$_)}
    if($LASTEXITCODE -ne 0){Fail "$Stage self-test failed: $LASTEXITCODE"}
}

try{
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $admin=(New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Log "ELEVATED=$admin IDENTITY=$($id.Name)"
    if(-not$admin){Fail 'proof harness is not elevated'}
    if(-not(Test-Path $Setup)){Fail 'setup executable missing'}

    Log 'CLEANUP_SERVICES_BEGIN'
    foreach($name in $services){
        if(Get-Service -Name $name -ErrorAction SilentlyContinue){
            & sc.exe stop $name *> $null
            Start-Sleep -Milliseconds 250
            & sc.exe delete $name *> $null
        }
    }
    Log 'CLEANUP_SERVICES_PASS'

    Log 'CLEANUP_FIREWALL_BEGIN'
    Get-NetFirewallRule -DisplayName 'Sistema Imunologico - deny outbound - *' -ErrorAction SilentlyContinue|Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Log 'CLEANUP_FIREWALL_PASS'

    SafeRemove $InstallRoot
    SafeRemove $DataRoot

    RunSetup -Name 'INSTALL' -SetupArgs @('/silent','/target=none')
    AssertInstalled 'INSTALL'
    $snapInstall=Snapshot 'INSTALL'

    RunSetup -Name 'REPAIR' -SetupArgs @('/silent','/repair')
    AssertInstalled 'REPAIR'
    $snapRepair=Snapshot 'REPAIR'

    RunSetup -Name 'UNINSTALL_PRESERVE_DATA' -SetupArgs @('/silent','/uninstall')
    Start-Sleep -Seconds 2
    if(Test-Path $InstallRoot){Fail 'uninstall left install root'}
    foreach($name in $services){if(Get-Service -Name $name -ErrorAction SilentlyContinue){Fail "uninstall left service: $name"}}
    if(-not(Test-Path $DataRoot)){Fail 'uninstall did not preserve data'}
    $snapUninstall=Snapshot 'UNINSTALL_PRESERVE_DATA'

    RunSetup -Name 'REINSTALL_FINAL' -SetupArgs @('/silent','/target=none')
    AssertInstalled 'REINSTALL_FINAL'
    $snapFinal=Snapshot 'REINSTALL_FINAL'

    $result=[ordered]@{
        schema=1
        mission='BUILD_WINDOWS_INSTALLER_HOST_PROOF'
        completed_at_utc=[DateTime]::UtcNow.ToString('o')
        result='PASS'
        final_state='CONTAINED_READ_ONLY'
        root_attested=$true
        protected_systems=0
        setup_sha256=(Get-FileHash $Setup -Algorithm SHA256).Hash.ToLowerInvariant()
        authenticode_status=[string](Get-AuthenticodeSignature $Setup).Status
        core_tag='v1.1.1'
        core_commit='d4750b24336d9b88663473d2db32a796e419e46f'
        stages=@($snapInstall,$snapRepair,$snapUninstall,$snapFinal)
    }
    [IO.File]::WriteAllText($Json,($result|ConvertTo-Json -Depth 16),(New-Object Text.UTF8Encoding($false)))
    Log 'HOST_INSTALL_PROOF=PASS'
    Copy-Item $Json (Join-Path $ProjectRoot 'installer\evidence\HOST_INSTALL_PROOF.json') -Force
    Copy-Item $Log (Join-Path $ProjectRoot 'installer\evidence\HOST_INSTALL_PROOF.log') -Force
    exit 0
}
catch{
    $err=[ordered]@{schema=1;mission='BUILD_WINDOWS_INSTALLER_HOST_PROOF';completed_at_utc=[DateTime]::UtcNow.ToString('o');result='FAIL';error=$_.Exception.Message}
    [IO.File]::WriteAllText($Json,($err|ConvertTo-Json -Depth 8),(New-Object Text.UTF8Encoding($false)))
    Log ('HOST_INSTALL_PROOF=FAIL ERROR='+$_.Exception.Message)
    try{
        Copy-Item $Json (Join-Path $ProjectRoot 'installer\evidence\HOST_INSTALL_PROOF.json') -Force
        Copy-Item $Log (Join-Path $ProjectRoot 'installer\evidence\HOST_INSTALL_PROOF.log') -Force
    }catch{}
    exit 1
}
