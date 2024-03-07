using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Microsoft.Extensions.Configuration;

var config = new ConfigurationBuilder()
    .AddUserSecrets<Program>()
    .Build();

var vaultUrl = config["vaultUrl"];

var caPath = config["caPath"]; // Example: IntermediateCA.pfx
var caPassword = config["caPassword"];
var caUrl = config["caUrl"];

var client = new CertificateClient(new Uri(vaultUrl), new DefaultAzureCredential());

// Step 1: Import the CA certificate
if (string.IsNullOrEmpty(caUrl))
{
    Console.WriteLine("Importing CA certificate...");
    var caData = File.ReadAllBytes(caPath);
    var options = new ImportCertificateOptions("JanneIntermediateCA", caData)
    {
        Password = caPassword
    };

    var caCertificateCreated = await client.ImportCertificateAsync(options);
    Console.WriteLine($"CA: {caCertificateCreated.Value.Id}");
    caUrl = caCertificateCreated.Value.Id.ToString();
}
else
{
    Console.WriteLine("CA already exists");
}

// Step 2: Fetch the CA certificate from the Key Vault
Console.WriteLine("Fetching CA certificate...");
var caCertificate = await client.GetCertificateAsync(caUrl);
Console.WriteLine($"CA: {caCertificate.Value.Name}");

