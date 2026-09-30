using System.Reflection;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore.Http;

namespace NostrAuth.Authentication;

/// <summary>Serves the built-in login page from an embedded resource.</summary>
internal static class LoginPage
{
    private static readonly Lazy<string> Template = new(() =>
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("NostrAuth.Assets.login.html")
            ?? throw new InvalidOperationException("login.html resource is missing.");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    });

    public static Task WriteAsync(HttpContext context, string appName, object config)
    {
        // The default JSON encoder escapes <, > and &, so the config cannot close the <script> tag.
        var html = Template.Value
            .Replace("{{title}}", HtmlEncoder.Default.Encode(appName))
            .Replace("{{config}}", JsonSerializer.Serialize(config));
        return WriteHtmlAsync(context, StatusCodes.Status200OK, html);
    }

    public static Task WriteErrorAsync(HttpContext context, string message, string? retryUrl)
    {
        // Only local paths. RedirectUri comes from our own protected state, but a cheap check here
        // keeps this page safe even if a future caller passes something else.
        var retry = retryUrl is ['/', not '/' and not '\\', ..] or "/" ? retryUrl : "/";
        var html = $"""
            <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
            <title>Login failed</title><style>body{"{"}font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;line-height:1.5{"}"}</style></head>
            <body><h1>Login failed</h1><p>{HtmlEncoder.Default.Encode(message)}</p><p><a href="{HtmlEncoder.Default.Encode(retry)}">Try again</a></p></body></html>
            """;
        return WriteHtmlAsync(context, StatusCodes.Status400BadRequest, html);
    }

    private static async Task WriteHtmlAsync(HttpContext context, int status, string html)
    {
        context.Response.StatusCode = status;
        context.Response.ContentType = "text/html; charset=utf-8";
        context.Response.Headers.CacheControl = "no-store";
        // A login page in a hidden frame is a clickjacking target.
        context.Response.Headers.XFrameOptions = "DENY";
        await context.Response.WriteAsync(html);
    }
}
