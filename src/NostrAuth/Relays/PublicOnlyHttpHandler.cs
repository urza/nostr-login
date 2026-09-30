using System.Net;
using System.Net.Sockets;

namespace NostrAuth.Relays;

/// <summary>
/// HTTP handler for requests to user-chosen hosts (NIP-05 domains). It refuses to connect to
/// loopback, private and link-local addresses, so a profile cannot make the server call its own
/// internal network (SSRF). The check runs on the resolved IP at connect time, so a DNS name
/// that points to 127.0.0.1 is caught too.
/// </summary>
internal static class PublicOnlyHttpHandler
{
    public static SocketsHttpHandler Create() => new()
    {
        AllowAutoRedirect = false,
        ConnectTimeout = TimeSpan.FromSeconds(5),
        ConnectCallback = async (context, ct) =>
        {
            // Through a proxy we connect to the proxy, not to the target. The operator chose that
            // proxy, so trust it; the proxy decides where the request may go.
            var viaProxy = !string.Equals(context.DnsEndPoint.Host, context.InitialRequestMessage.RequestUri?.Host, StringComparison.OrdinalIgnoreCase);

            var addresses = await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, ct);
            var allowed = viaProxy ? addresses : addresses.Where(IsPublic).ToArray();
            if (allowed.Length == 0) throw new HttpRequestException($"{context.DnsEndPoint.Host} has no public address.");

            var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                await socket.ConnectAsync(allowed, context.DnsEndPoint.Port, ct);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        },
    };

    internal static bool IsPublic(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip)) return false;
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            // fc00::/7 unique local, fe80::/10 link local, fec0::/10 old site local, :: unspecified.
            return !(ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast
                || (ip.GetAddressBytes()[0] & 0xfe) == 0xfc || ip.Equals(IPAddress.IPv6Any));
        }
        var b = ip.GetAddressBytes();
        return !(b[0] == 0                                  // 0.0.0.0/8
            || b[0] == 10                                   // 10.0.0.0/8
            || (b[0] == 100 && b[1] >= 64 && b[1] <= 127)   // 100.64.0.0/10 carrier-grade NAT
            || (b[0] == 169 && b[1] == 254)                 // 169.254.0.0/16 link local, cloud metadata
            || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)    // 172.16.0.0/12
            || (b[0] == 192 && b[1] == 168)                 // 192.168.0.0/16
            || b[0] >= 224);                                // multicast and reserved
    }
}
