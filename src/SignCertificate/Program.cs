// Links:
// https://github.com/Azure/azure-sdk-for-net/blob/main/sdk/keyvault/Azure.Security.KeyVault.Keys/samples/Sample5_SignVerify.md
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Microsoft.Extensions.Configuration;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

var config = new ConfigurationBuilder()
    .AddUserSecrets<Program>()
    .Build();

var vaultUrl = config["vaultUrl"];  // Example: https://myvault.vault.azure.net/
var caName = config["caName"];      // Example: MyRootCA
var csrPath = config["csrPath"];    // Example: c:\temp\request.csr

/*
// Prepare My CA
openssl genpkey -algorithm RSA -out ca.key -pkeyopt rsa_keygen_bits:2048
openssl req -new -x509 -key ca.key -out ca.crt -days 365 -subj "/CN=MyRootCA"

// Upload the CA certificate to the Key Vault by name of that matches the caName (in the above configuration)

// Sign the CSR
openssl x509 -req -in request.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out request-signed.crt -days 365 -sha256

// Validate the certificate
openssl x509 -in request-signed.crt -text -noout

// Prepare other party
openssl genpkey -algorithm RSA -out other-private.key -pkeyopt rsa_keygen_bits:2048

# Generate a CSR
openssl req -new -key other-private.key -out request.csr -subj "/CN=JanneCorp, O=JanneCorp, L=Espoo, S=Uusimaa, C=FI"

// Sign the CSR

# Validate the signed certificate
openssl x509 -in request-signed.crt -text -noout

# Output the CSR
cat request.csr

-----BEGIN CERTIFICATE REQUEST-----
MIIEHDCCAwQCAQAwVzELMAkGA1UEBhMCRkkxEDAOBgNVBAgMB1V1c2ltYWExDjAM
...
xwzgg6dj8wB9QvJoGAyo2kj8mMk8jSY3g0BSXKdkg3WvDTmUVQl3AOkO9NvXWxzh
-----END CERTIFICATE REQUEST-----

# Output the signed CSR
cat request-signed.crt

-----BEGIN CERTIFICATE-----
MIICojCCAYqgAwIBAgIJAJW4VmXTSd0IMA0GCSqGSIb3DQEBCwUAMBMxETAPBgNV
...
HD1ueH4b
-----END CERTIFICATE-----
*/

var keyClient = new KeyClient(vaultUri: new Uri(vaultUrl), credential: new DefaultAzureCredential());
var cryptographyClient = keyClient.GetCryptographyClient(caName);

// Example sign data
//var signResult = cryptographyClient.SignData(SignatureAlgorithm.RS256, data);

var certificateClient = new CertificateClient(new Uri(vaultUrl), new DefaultAzureCredential());
var caCertificate = await certificateClient.GetCertificateAsync(caName);
using var issuerCertificate = X509CertificateLoader.LoadCertificate(caCertificate.Value.Cer);

var csrTextContent = File.ReadAllText(csrPath);
var certificateRequest = CertificateRequest.LoadSigningRequestPem(csrTextContent, HashAlgorithmName.SHA256);

using var rsaCA = await cryptographyClient.CreateRSAAsync();
var generator = X509SignatureGenerator.CreateForRSA(rsaCA, RSASignaturePadding.Pkcs1);

// This needs to be unique for each certificate!
var serialNumber = new BigInteger(DateTime.Now.Ticks);
var serialNumberArray = serialNumber.ToByteArray();

using var signRequest = certificateRequest.Create(issuerCertificate.SubjectName, generator, DateTime.Today.AddDays(-1), DateTime.Today.AddYears(1), serialNumberArray);

string signedCsrPem = PemEncoding.WriteString("CERTIFICATE", signRequest.RawData);
File.WriteAllText("../../../request-signed.crt", signedCsrPem);
