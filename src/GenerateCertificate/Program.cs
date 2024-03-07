using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Microsoft.Extensions.Configuration;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Reflection.Metadata;
using System.Numerics;
using Azure.Security.KeyVault.Secrets;
using Azure.Security.KeyVault.Keys;

const string SubjectIdExtensionOid = "2.5.29.14";
const string AuthorityIdExtensionOid = "2.5.29.35";

var config = new ConfigurationBuilder()
    .AddUserSecrets<Program>()
    .Build();

var vaultUrl = config["vaultUrl"];

var caPath = config["caPath"]; // Example: IntermediateCA.pfx
var caPassword = config["caPassword"];
var caName = config["caName"];

var certificateClient = new CertificateClient(new Uri(vaultUrl), new DefaultAzureCredential());

// Step 1: Import the CA certificate
if (string.IsNullOrEmpty(caName))
{
    Console.WriteLine("Importing CA certificate...");
    var caData = File.ReadAllBytes(caPath);
    var options = new ImportCertificateOptions(caName, caData)
    {
        Password = caPassword
    };

    var caCertificateCreated = await certificateClient.ImportCertificateAsync(options);
    Console.WriteLine($"CA: {caCertificateCreated.Value.Id}");
}
else
{
    Console.WriteLine("CA already exists");
}

// Step 2: Fetch the CA certificate from the Key Vault
Console.WriteLine("Fetching CA certificate...");
var caCertificate = await certificateClient.GetCertificateAsync(caName);
Console.WriteLine($"CA: {caCertificate.Value.Name}");
Console.WriteLine($"CA SecretId: {caCertificate.Value.SecretId}");

var keyClient = new KeyClient(vaultUri: new Uri(vaultUrl), credential: new DefaultAzureCredential());
var cryptographyClient = keyClient.GetCryptographyClient(caName);

// Below heavily borrows from these two sources:
// https://github.com/estiller/build-pki-net-azure-sample/blob/05-CertificateRequestClient/BuildPkiSample.CertificateAuthority.BusinessLogic/CertificateIssuer.cs
// https://github.com/novotnyllc/RSAKeyVaultProvider/blob/main/RSAKeyVaultProvider/RSAKeyVault.cs

// Step 3: Create a new certificate
// Prepare the issuer
using var issuerCertificate = new X509Certificate2(caCertificate.Value.Cer);
using var rsaCA = await cryptographyClient.CreateRSAAsync();

// Prepare the key
var subjectName = "CN=Janne-" + DateTime.Now.ToString("yyyy-dd-MM-HH-mm-ss");
using var key = RSA.Create();
var publicParameters = key.ExportParameters(false);
using RSA certificateKey = RSA.Create(new RSAParameters()
{
    Modulus = publicParameters.Modulus,
    Exponent = publicParameters.Exponent
});
var subjectDistinguishedName = new X500DistinguishedName("CN=" + subjectName);
var request = new CertificateRequest(subjectDistinguishedName, certificateKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, true, 0, true));
request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.2"), new Oid("1.3.6.1.5.5.7.3.1") }, false));
request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
request.CertificateExtensions.Add(BuildAuthorityKeyIdentifierExtension(issuerCertificate.Extensions[SubjectIdExtensionOid]));

// This needs to be unique for each certificate!
var serialNumber = new BigInteger(DateTime.Now.Ticks);
var serialNumberArray = serialNumber.ToByteArray();

var generator = X509SignatureGenerator.CreateForRSA(rsaCA, RSASignaturePadding.Pkcs1);
var signRequest = request.Create(issuerCertificate.SubjectName, generator, DateTime.Today.AddDays(-1), DateTime.Today.AddYears(1), serialNumberArray);

// Save the certificate to disk
File.WriteAllBytes($"{subjectName}.cer", signRequest.RawData);

var certificateWithPrivateKey = signRequest.CopyWithPrivateKey(key);
var rawCertificate = certificateWithPrivateKey.Export(X509ContentType.Pfx);
File.WriteAllBytes($"{subjectName}.pfx", rawCertificate);

static X509Extension BuildAuthorityKeyIdentifierExtension(X509Extension authorityKeyIdentifierExtension)
{
    var authoritySubjectKey = authorityKeyIdentifierExtension.RawData;
    var segment = new Span<byte>(authoritySubjectKey, 2, authoritySubjectKey.Length - 2);
    var authorityKeyIdentifier = new byte[segment.Length + 4];
    // these bytes define the "KeyID" part of the AuthorityKeyIdentifier
    authorityKeyIdentifier[0] = 0x30;
    authorityKeyIdentifier[1] = 0x16;
    authorityKeyIdentifier[2] = 0x80;
    authorityKeyIdentifier[3] = 0x14;
    segment.CopyTo(new Span<byte>(authorityKeyIdentifier, 4, authorityKeyIdentifier.Length - 4));
    return new X509Extension(AuthorityIdExtensionOid, authorityKeyIdentifier, false);
}