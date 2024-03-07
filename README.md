# Azure Key Vault demos

Azure Key Vault demos

## Generate Certificates

This example borrows heavily
[estiller/build-pki-net-azure-sample](https://github.com/estiller/build-pki-net-azure-sample)
and
[novotnyllc/RSAKeyVaultProvider](https://github.com/novotnyllc/RSAKeyVaultProvider).
Credits to those authors.

---

Here is example if you want to create certificate chain (based on [this](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/certauth)):

```powershell
# Create Root CA
$rootCA = New-SelfSignedCertificate `
  -Subject "Janne Root CA" `
  -FriendlyName "Janne Root CA" `
  -CertStoreLocation "cert:\LocalMachine\My" `
  -NotAfter (Get-Date).AddYears(20) `
  -KeyUsageProperty All -KeyUsage CertSign, CRLSign, DigitalSignature

$password = ConvertTo-SecureString -String "1234" -Force -AsPlainText

Get-ChildItem -Path cert:\localMachine\my\$($rootCA.Thumbprint) | 
  Export-PfxCertificate -FilePath JanneRootCA.pfx -Password $password

Export-Certificate -Cert cert:\localMachine\my\$($rootCA.Thumbprint) -FilePath JanneRootCA.crt

# Create Intermediate Certificate
$intermediateCertificate = New-SelfSignedCertificate `
  -CertStoreLocation cert:\localmachine\my `
  -Subject "Janne Intermediate certificate" `
  -FriendlyName "Janne Intermediate certificate" `
  -Signer $rootCA `
  -NotAfter (Get-Date).AddYears(20) `
  -KeyUsageProperty All -KeyUsage CertSign, CRLSign, DigitalSignature `
  -TextExtension @("2.5.29.19={text}CA=1&pathlength=1")

$intermediatePassword = ConvertTo-SecureString -String "2345" -Force -AsPlainText

Get-ChildItem -Path cert:\localMachine\my\$($intermediateCertificate.Thumbprint) | 
  Export-PfxCertificate -FilePath IntermediateCertificate.pfx -Password $intermediatePassword

Export-Certificate -Cert cert:\localMachine\my\$($intermediateCertificate.Thumbprint) -FilePath IntermediateCertificate.crt
```

Now you can use `IntermediateCertificate.pfx` and it's password `2345` to
run example application `GenerateCertificate` folder.
It uploads this to Azure Key Vault and then uses it to generate
other certificates.

You can then upload that newly created certificate to Entra ID to service principal and
use it to authenticate to Azure. 

```powershell
Connect-AzAccount -ServicePrincipal -ApplicationId $appid -Tenant $tenantid -CertificateThumbprint $thumbprint
```
