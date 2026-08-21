param([Parameter(Mandatory=$true)][string]$InstallRoot,[Parameter(Mandatory=$true)][string]$DataRoot)
$ErrorActionPreference='Stop'; $rootDir=Join-Path $DataRoot 'root'; New-Item -ItemType Directory -Force $rootDir|Out-Null
$securityPath=Join-Path $DataRoot 'host-security.json';$rootPath=Join-Path $rootDir 'root.json';$sigPath=Join-Path $rootDir 'payload.sig';$manifest=Join-Path $InstallRoot 'payload.sha256'
$state=[ordered]@{checked_at_utc=[DateTime]::UtcNow.ToString('o');secure_boot=$false;tpm_present=$false;tpm_ready=$false;hardware_backed_root=$false;root_attested=$false;mode='CONTAINED_READ_ONLY';reason='NOT_PROVISIONED'}
try{
 try{$state.secure_boot=[bool](Confirm-SecureBootUEFI -ErrorAction Stop)}catch{$state.secure_boot=$false}
 try{$t=Get-Tpm -ErrorAction Stop;$state.tpm_present=[bool]$t.TpmPresent;$state.tpm_ready=[bool]$t.TpmReady}catch{}
 if(-not $state.secure_boot){throw 'SECURE_BOOT_NOT_PROVEN'};if(-not $state.tpm_present){throw 'TPM_NOT_PRESENT'};if(-not $state.tpm_ready){throw 'TPM_NOT_READY'};if(-not(Test-Path $manifest)){throw 'PAYLOAD_MANIFEST_MISSING'}
 $subject='CN=Sistema Imunologico Host Root';$cert=Get-ChildItem Cert:\LocalMachine\My|Where-Object{$_.Subject-eq$subject-and$_.HasPrivateKey}|Sort-Object NotBefore -Descending|Select-Object -First 1
 if(-not $cert){$cert=New-SelfSignedCertificate -Subject $subject -FriendlyName 'Sistema Imunologico Host Root' -CertStoreLocation 'Cert:\LocalMachine\My' -Provider 'Microsoft Platform Crypto Provider' -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -KeyExportPolicy NonExportable -KeyUsage DigitalSignature -NotAfter (Get-Date).AddYears(10)}
 $rsa=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert);if(-not$rsa){throw 'TPM_PRIVATE_KEY_UNAVAILABLE'}
 $provider='';try{$provider=[string]$rsa.Key.Provider.Provider}catch{$provider=[string]$rsa.GetType().FullName};if($provider-notmatch'Platform Crypto Provider'){throw "ROOT_PROVIDER_NOT_TPM:$provider"}
 $bytes=[IO.File]::ReadAllBytes($manifest);$sig=$rsa.SignData($bytes,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1);[IO.File]::WriteAllText($sigPath,[Convert]::ToBase64String($sig),(New-Object Text.UTF8Encoding($false)))
 $pub=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert);if(-not $pub.VerifyData($bytes,$sig,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)){throw 'TPM_SIGNATURE_VERIFY_FAILED'}
 [ordered]@{schema=1;thumbprint=$cert.Thumbprint;subject=$cert.Subject;provider=$provider;algorithm='RSA-2048-SHA256-PKCS1';manifest='payload.sha256';hardware_backed=$true;created_or_verified_at_utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json|Set-Content $rootPath -Encoding UTF8
 $state.hardware_backed_root=$true;$state.root_attested=$true;$state.mode='ROOT_ATTESTED';$state.reason='TPM_ROOT_ATTESTED'
}catch{$state.reason=[string]$_.Exception.Message}
finally{$state|ConvertTo-Json|Set-Content $securityPath -Encoding UTF8}
"SECURE_BOOT=$($state.secure_boot)";"TPM_PRESENT=$($state.tpm_present)";"TPM_READY=$($state.tpm_ready)";"ROOT_ATTESTED=$($state.root_attested)";"MODE=$($state.mode)";"REASON=$($state.reason)";exit 0
