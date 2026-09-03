using System.Net;

namespace Tunneld.Net.Runtime;

public static class ReverseProxy
{
    private static readonly HttpClient Client = new(new HttpClientHandler
    {
        AllowAutoRedirect = false,
        UseCookies = false,
    });

    public static async Task ForwardAsync(HttpListenerContext context, string service, CancellationToken cancellationToken)
    {
        var targetBase = new Uri(service);
        var target = new Uri(targetBase, context.Request.RawUrl ?? "/");
        using var request = new HttpRequestMessage(new HttpMethod(context.Request.HttpMethod), target);

        foreach (var headerNameRaw in context.Request.Headers.AllKeys)
        {
            if (headerNameRaw is null)
            {
                continue;
            }
            var headerName = headerNameRaw;
            var values = context.Request.Headers.GetValues(headerName);
            if (values is null || string.Equals(headerName, "Host", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            if (!request.Headers.TryAddWithoutValidation(headerName, values))
            {
                request.Content ??= new StreamContent(context.Request.InputStream);
                request.Content.Headers.TryAddWithoutValidation(headerName, values);
            }
        }

        if (context.Request.HasEntityBody && request.Content is null)
        {
            request.Content = new StreamContent(context.Request.InputStream);
        }

        using var response = await Client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        context.Response.StatusCode = (int)response.StatusCode;
        foreach (var header in response.Headers)
        {
            context.Response.Headers[header.Key] = string.Join(",", header.Value);
        }
        foreach (var header in response.Content.Headers)
        {
            context.Response.Headers[header.Key] = string.Join(",", header.Value);
        }
        await response.Content.CopyToAsync(context.Response.OutputStream, cancellationToken);
        context.Response.Close();
    }
}
