using System.Text;

namespace Tunneld.Net.Runtime;

public static class TlsReverseProxy
{
    private static readonly HttpClient Client = new(new HttpClientHandler
    {
        AllowAutoRedirect = false,
        UseCookies = false,
    });

    public static async Task ForwardAsync(Stream clientStream, HttpRequest inbound, string service, CancellationToken cancellationToken)
    {
        var target = new Uri(new Uri(service), inbound.RawTarget);
        using var request = new HttpRequestMessage(new HttpMethod(inbound.Method), target);
        foreach (var header in inbound.Headers)
        {
            if (string.Equals(header.Key, "Host", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            request.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }
        if (inbound.Body.Length > 0)
        {
            request.Content = new ByteArrayContent(inbound.Body);
        }

        using var response = await Client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        var head = new StringBuilder();
        head.Append($"HTTP/1.1 {(int)response.StatusCode} {response.ReasonPhrase}\r\n");
        foreach (var header in response.Headers)
        {
            head.Append($"{header.Key}: {string.Join(",", header.Value)}\r\n");
        }
        foreach (var header in response.Content.Headers)
        {
            head.Append($"{header.Key}: {string.Join(",", header.Value)}\r\n");
        }
        head.Append("Connection: close\r\n\r\n");
        await clientStream.WriteAsync(Encoding.ASCII.GetBytes(head.ToString()), cancellationToken);
        await response.Content.CopyToAsync(clientStream, cancellationToken);
    }
}
