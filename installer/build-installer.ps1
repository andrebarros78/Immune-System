param()
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'

$InstallerVersion='1.2.0'
$CoreTag='v1.1.1'
$CoreCommit='d4750b24336d9b88663473d2db32a796e419e46f'
$PythonVersion='3.13.15'
$PythonSha256='d1f04d990aee1253d8569e8e5104e30fa9f5fa830899f14843448872d936a2cf'
$PythonUrl="https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-embed-amd64.zip"

$InstallerDir=$PSScriptRoot
$ProjectRoot=Split-Path $InstallerDir -Parent
$BuildDir=Join-Path $InstallerDir 'build'
$DistDir=Join-Path $InstallerDir 'dist'
$CacheDir=Join-Path $InstallerDir 'cache'
$PayloadDir=Join-Path $BuildDir 'payload'
$CoreStage=Join-Path $BuildDir 'core'
$CompilerTmp='C:\ProgramData\BarrosTech\ImmuneCompiler'
$Csc='C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if(-not(Test-Path $Csc)){throw 'CSC_NOT_FOUND'}

Push-Location $ProjectRoot
try{
  $resolved=(git rev-list -n 1 $CoreTag).Trim()
  if($LASTEXITCODE-ne0-or$resolved-ne$CoreCommit){throw "CORE_TAG_LOCK_FAILED:$resolved"}
}finally{Pop-Location}

Remove-Item $BuildDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $CompilerTmp -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $BuildDir,$DistDir,$CacheDir,$PayloadDir,$CoreStage,$CompilerTmp | Out-Null

$coreZip=Join-Path $BuildDir 'core-v1.1.1.zip'
Push-Location $ProjectRoot
try{git archive --format=zip --output=$coreZip $CoreTag;if($LASTEXITCODE-ne0){throw 'GIT_ARCHIVE_FAILED'}}finally{Pop-Location}
Expand-Archive -LiteralPath $coreZip -DestinationPath $CoreStage -Force
foreach($name in @('.github','donors','tests','evidence')){Remove-Item (Join-Path $CoreStage $name) -Recurse -Force -ErrorAction SilentlyContinue}
$appDir=Join-Path $PayloadDir 'app';New-Item -ItemType Directory -Force $appDir|Out-Null
Get-ChildItem -LiteralPath $CoreStage -Force | Copy-Item -Destination $appDir -Recurse -Force

$hostDir=Join-Path $PayloadDir 'host';New-Item -ItemType Directory -Force $hostDir|Out-Null
$serviceSource=Join-Path $CompilerTmp 'service-host.cs';Copy-Item (Join-Path $InstallerDir 'service-host.cs') $serviceSource -Force
$serviceTmp=Join-Path $CompilerTmp 'ImmuneServiceHost.exe'
$serviceRsp=Join-Path $CompilerTmp 'service.rsp'
@(
  '/nologo',
  '/target:exe',
  '/platform:x64',
  '/optimize+',
  ('/out:"'+$serviceTmp+'"'),
  '/r:System.ServiceProcess.dll',
  ('"'+$serviceSource+'"')
) | Set-Content -LiteralPath $serviceRsp -Encoding ASCII
& $Csc ('@'+$serviceRsp)
if($LASTEXITCODE-ne0-or-not(Test-Path $serviceTmp)){throw 'SERVICE_HOST_BUILD_FAILED'}
Copy-Item $serviceTmp (Join-Path $hostDir 'ImmuneServiceHost.exe') -Force
Copy-Item (Join-Path $InstallerDir 'runtime\*') -Destination $hostDir -Recurse -Force

@(
  'INSTALLER_VERSION='+$InstallerVersion,
  'CORE_TAG='+$CoreTag,
  'CORE_COMMIT='+$CoreCommit,
  'CORE_IMMUTABLE=true'
) | Set-Content -LiteralPath (Join-Path $PayloadDir 'release-lock.txt') -Encoding ASCII

$pythonZip=Join-Path $CacheDir "python-$PythonVersion-embed-amd64.zip"
if(-not(Test-Path $pythonZip)){Invoke-WebRequest -Uri $PythonUrl -OutFile $pythonZip -UseBasicParsing}
$actualPy=(Get-FileHash $pythonZip -Algorithm SHA256).Hash.ToLowerInvariant()
if($actualPy-ne$PythonSha256){throw "PYTHON_SHA256_MISMATCH:$actualPy"}
$pythonDir=Join-Path $PayloadDir 'runtime\python';New-Item -ItemType Directory -Force $pythonDir|Out-Null
Expand-Archive -LiteralPath $pythonZip -DestinationPath $pythonDir -Force

$manifest=Join-Path $PayloadDir 'payload.sha256'
$lines=Get-ChildItem -LiteralPath $PayloadDir -File -Recurse | Where-Object{$_.FullName-ne$manifest} | Sort-Object FullName | ForEach-Object{
  $rel=$_.FullName.Substring($PayloadDir.Length).TrimStart('\').Replace('\','/')
  $hash=(Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
  "$hash *$rel"
}
[IO.File]::WriteAllLines($manifest,[string[]]$lines,(New-Object Text.UTF8Encoding($false)))

$payloadZip=Join-Path $BuildDir 'payload.zip'
if(Test-Path $payloadZip){Remove-Item $payloadZip -Force}
Compress-Archive -Path (Join-Path $PayloadDir '*') -DestinationPath $payloadZip -CompressionLevel Optimal
$payloadHash=(Get-FileHash $payloadZip -Algorithm SHA256).Hash.ToLowerInvariant()

$constants=Join-Path $BuildDir 'BuildConstants.cs'
@"
namespace BarrosTech.ImmuneInstaller {
 internal static class BuildConstants {
  internal const string InstallerVersion = "$InstallerVersion";
  internal const string CoreVersion = "$CoreTag";
  internal const string CoreCommit = "$CoreCommit";
  internal const string PayloadZipSha256 = "$payloadHash";
 }
}
"@ | Set-Content -LiteralPath $constants -Encoding UTF8

Copy-Item (Join-Path $InstallerDir 'Setup.cs') (Join-Path $CompilerTmp 'Setup.cs') -Force
Copy-Item (Join-Path $InstallerDir 'app.manifest') (Join-Path $CompilerTmp 'app.manifest') -Force
Copy-Item $constants (Join-Path $CompilerTmp 'BuildConstants.cs') -Force
Copy-Item $payloadZip (Join-Path $CompilerTmp 'payload.zip') -Force
$setupTmp=Join-Path $CompilerTmp 'Sistema-Imunologico-Setup.exe'
$setupRsp=Join-Path $CompilerTmp 'setup.rsp'
@(
  '/nologo',
  '/target:winexe',
  '/platform:x64',
  '/optimize+',
  ('/out:"'+$setupTmp+'"'),
  ('/win32manifest:"'+(Join-Path $CompilerTmp 'app.manifest')+'"'),
  ('/resource:"'+(Join-Path $CompilerTmp 'payload.zip')+'",Immune.Payload.zip'),
  '/r:System.Windows.Forms.dll',
  '/r:System.Drawing.dll',
  '/r:System.IO.Compression.dll',
  '/r:System.IO.Compression.FileSystem.dll',
  '/r:System.Web.Extensions.dll',
  ('"'+(Join-Path $CompilerTmp 'Setup.cs')+'"'),
  ('"'+(Join-Path $CompilerTmp 'BuildConstants.cs')+'"')
) | Set-Content -LiteralPath $setupRsp -Encoding ASCII
& $Csc ('@'+$setupRsp)
if($LASTEXITCODE-ne0-or-not(Test-Path $setupTmp)){throw 'SETUP_BUILD_FAILED'}

$setup=Join-Path $DistDir 'Sistema-Imunologico-Setup.exe';Copy-Item $setupTmp $setup -Force
$setupHash=(Get-FileHash $setup -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content -LiteralPath ($setup+'.sha256') -Value ($setupHash+' *Sistema-Imunologico-Setup.exe') -Encoding ASCII
Remove-Item $CompilerTmp -Recurse -Force -ErrorAction SilentlyContinue

Write-Output 'INSTALLER_BUILD=PASS'
Write-Output "INSTALLER_VERSION=$InstallerVersion"
Write-Output "CORE_TAG=$CoreTag"
Write-Output "CORE_COMMIT=$CoreCommit"
Write-Output "PYTHON_SHA256=$actualPy"
Write-Output "PAYLOAD_SHA256=$payloadHash"
Write-Output "SETUP_SHA256=$setupHash"
Write-Output "SETUP_PATH=$setup"
