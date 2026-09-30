// A console client for Demo 3. It holds a Nostr key and signs a NIP-98 event for each request,
// like a bot or CLI tool would. Usage:
//   dotnet run -- [--url http://localhost:5103] [--sec nsec1...]
// Without --sec it makes a throwaway key.
using System.Net.Http.Headers;
using System.Text;
using NostrAuth;

var baseUrl = Arg("--url") ?? "http://localhost:5103";
var key = Arg("--sec") is { } sec ? NostrKey.Parse(sec) : NostrKey.Generate();
Console.WriteLine($"Using key {Nip19.ToNpub(key.PublicKeyHex)}\n");

using var http = new HttpClient();

await Send(HttpMethod.Get, "/api/me");
await Send(HttpMethod.Post, "/api/notes", """{"text":"Hello from the console client"}""");
await Send(HttpMethod.Get, "/api/notes");

Console.WriteLine("--- Negative checks ---");
// Same signed header twice: the server remembers event ids for the time window.
var replay = Signed(HttpMethod.Get, "/api/me");
await Send(HttpMethod.Get, "/api/me", header: replay, label: "first use");
await Send(HttpMethod.Get, "/api/me", header: replay, label: "replay of the same header");
// Signed for one body, sent with another.
await Send(HttpMethod.Post, "/api/notes", """{"text":"changed"}""",
    header: Signed(HttpMethod.Post, "/api/notes", """{"text":"original"}"""), label: "body swapped after signing");
await Send(HttpMethod.Get, "/api/me", header: null, label: "no header");

async Task Send(HttpMethod method, string path, string? json = null, AuthenticationHeaderValue? header = null, string? label = null)
{
    using var request = new HttpRequestMessage(method, baseUrl + path);
    if (json is not null) request.Content = new StringContent(json, Encoding.UTF8, "application/json");
    // "header: null" with a label means: send without auth on purpose.
    request.Headers.Authorization = label is null ? Signed(method, path, json) : header;
    using var response = await http.SendAsync(request);
    Console.WriteLine($"{method} {path}{(label is null ? "" : $" ({label})")} -> {(int)response.StatusCode}");
    var body = await response.Content.ReadAsStringAsync();
    if (body.Length > 0) Console.WriteLine("  " + body);
}

AuthenticationHeaderValue Signed(HttpMethod method, string path, string? json = null)
{
    var body = json is null ? null : Encoding.UTF8.GetBytes(json);
    var evt = Nip98.CreateTemplate(baseUrl + path, method.Method, DateTimeOffset.UtcNow, body: body).Sign(key);
    return AuthenticationHeaderValue.Parse(Nip98.ToAuthorizationHeader(evt));
}

string? Arg(string name)
{
    var i = Array.IndexOf(args, name);
    return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
}
