using Hl7.Fhir.Model;
using Hl7.Fhir.Model.CdsHooks;
using Hl7.Fhir.Rest;
using Hl7.Fhir.Serialization;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;

Console.WriteLine("Starting...");

string fhirEndpoint = "https://int.api.service.nhs.uk/record-locator/consumer/FHIR/R4";
string tokenURL = "https://int.api.service.nhs.uk/oauth2/token";
string nhsNumber = "9693893123";

string myJWT = makeJWT();
JsonDocument tokens = await getAccessTokenAsync(myJWT, tokenURL);
string accessToken = tokens.RootElement.GetProperty("access_token").GetString();

var handler = new AuthorizationMessageHandler();
handler.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
var fhirClient = new FhirClient(fhirEndpoint, FhirClientSettings.CreateDefault(), handler);
SearchParams queryParameter = new SearchParams()
    .Where("subject:identifier=https://fhir.nhs.uk/Id/nhs-number|" + nhsNumber);

// Initialize the FHIR JSON serializer
var serializer = new FhirJsonSerializer(new SerializerSettings { Pretty = true });

try
{
    Bundle docs = fhirClient.Search<DocumentReference>(queryParameter);
    Console.Out.WriteLine("Found: " + docs.Entry.Count + " pointers.");
    foreach (var e in docs.Entry)
    {

        DocumentReference docReference = (DocumentReference)e.Resource;


        // Serialize the Patient resource to a JSON string
        string jsonString = serializer.SerializeToString(docReference);

        // Output the JSON string to the console
        Console.WriteLine(jsonString);

        // Let's write the fully qualified url for the resource to the console:
        Console.WriteLine("url for this resource: " + docReference.Content[0].Attachment.Url.ToString());

        //var pat_entry = e.Resource;

        // Do something with this patient, for example write the family name that's in the first
        // element of the name list to the console:
        //Console.WriteLine("Status: " + pat_entry.Status);
    }
}
catch (Hl7.Fhir.Rest.FhirOperationException except)
{
    Console.Out.WriteLine("Exception caught: " + except.Message);
}
Console.Out.WriteLine("Done");


//
// Create a signed JWT that we'll use to prove identity when asking
// for an access token.
string makeJWT()
{
    // reading the content of a private key PEM file, PKCS8 encoded 
    string privateKeyPem = File.ReadAllText("C:\\Users\\tim\\source\\repos\\NRLClient\\private_key.pem");
    // keeping only the payload of the key 
    privateKeyPem = privateKeyPem.Replace("-----BEGIN PRIVATE KEY-----", "");
    privateKeyPem = privateKeyPem.Replace("-----END PRIVATE KEY-----", "");
    byte[] privateKeyRaw = Convert.FromBase64String(privateKeyPem);
    // creating the RSA key 
    RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
    provider.ImportPkcs8PrivateKey(new ReadOnlySpan<byte>(privateKeyRaw), out _);
    RsaSecurityKey rsaSecurityKey = new RsaSecurityKey(provider);
    // Generating the token 
    var now = DateTime.UtcNow;
    var claims = new[] {
                    new System.Security.Claims.Claim(JwtRegisteredClaimNames.Sub, "ia5524GLwUzdyfUWgAdXy6cbbMvnyhqV"),
                    new System.Security.Claims.Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };
    var handler = new JwtSecurityTokenHandler();
    var token = new JwtSecurityToken
    (
        "ia5524GLwUzdyfUWgAdXy6cbbMvnyhqV",
        "https://int.api.service.nhs.uk/oauth2/token",
        claims,
        now.AddMilliseconds(-30),
        now.AddMinutes(5),
        new SigningCredentials(rsaSecurityKey, SecurityAlgorithms.RsaSha512)
    );
    token.Header["kid"] = "1";
    //Console.WriteLine(handler.WriteToken(token));
    return handler.WriteToken(token);
}

//
// Here we exchange our signed JWT for a set of tokens
async Task<JsonDocument> getAccessTokenAsync(string signedJWT, string tokenURL)
{
    JsonDocument responseJSON;

    // Create HttpClient instance
    using (HttpClient client = new HttpClient())
    {
        // Prepare data to send as key-value pairs
        var formData = new List<KeyValuePair<string, string>>
    {
        new KeyValuePair<string, string>("grant_type", "client_credentials"),
        new KeyValuePair<string, string>("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
        new KeyValuePair<string, string>("client_assertion", signedJWT),

    };

        // Convert the form data to x-www-form-urlencoded content
        HttpContent content = new FormUrlEncodedContent(formData);

        // Set Content-Type header to x-www-form-urlencoded
        content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");

        // Send the POST request
        HttpResponseMessage response = await client.PostAsync(tokenURL, content);

        // Check if the response was successful
        if (response.IsSuccessStatusCode)
        {
            // Read response content
            string responseBody = await response.Content.ReadAsStringAsync();
            //Console.WriteLine("Response: " + responseBody);
            responseJSON = JsonDocument.Parse(responseBody);
        }
        else
        {
            string responseBody = await response.Content.ReadAsStringAsync();
            responseJSON = JsonDocument.Parse(responseBody);
            Console.WriteLine("Error: " + response.StatusCode);
            Console.WriteLine("Response: " + responseBody);
        }
    }
    return responseJSON;
}


// See: https://docs.fire.ly/projects/Firely-NET-SDK/en/stable/client/request-response.html#adding-extra-headers
// Handler to add extra headers
public class AuthorizationMessageHandler : HttpClientHandler
{
    public System.Net.Http.Headers.AuthenticationHeaderValue Authorization { get; set; }
    protected async override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (Authorization != null)
        {
            request.Headers.Authorization = Authorization;
            string XRequestID = Guid.NewGuid().ToString();
            Console.Out.WriteLine("Sending X-Request-ID: " + XRequestID);
            request.Headers.Add("X-Request-ID", XRequestID);
            request.Headers.Add("NHSD-End-User-Organisation-ODS", "X26");
        }
        return await base.SendAsync(request, cancellationToken);
    }
}

