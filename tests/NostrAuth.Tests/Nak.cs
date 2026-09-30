using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace NostrAuth.Tests;

/// <summary>Runs <c>nak</c> (https://github.com/fiatjaf/nak) as relay or signer for tests. Null when nak is missing.</summary>
internal sealed class Nak : IDisposable
{
    public static readonly string? Path = Find();
    private readonly List<Process> _processes = [];

    private Process? _relay;
    private int _relayPort;

    /// <summary>Starts an in-memory relay and returns its ws:// URL.</summary>
    public async Task<string> StartRelayAsync(string? eventsFile = null, int? port = null)
    {
        _relayPort = port ?? FreePort();
        var args = new List<string> { "serve", "--hostname", "127.0.0.1", "--port", _relayPort.ToString() };
        if (eventsFile is not null) args.AddRange(["--events", eventsFile]);
        _relay = Start([.. args]);
        await WaitForPortAsync(_relayPort);
        return $"ws://127.0.0.1:{_relayPort}";
    }

    /// <summary>Kills the relay, so every connection to it drops. <see cref="StartRelayAsync"/> with the old port brings it back.</summary>
    public int StopRelay()
    {
        _relay?.Kill(entireProcessTree: true);
        _relay?.WaitForExit();
        return _relayPort;
    }

    public Process Start(params string[] args)
    {
        var psi = new ProcessStartInfo(Path!) { RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true };
        foreach (var a in args) psi.ArgumentList.Add(a);
        var p = Process.Start(psi)!;
        // nak reads events from stdin when stdin is a pipe, and waits for EOF before it starts.
        p.StandardInput.Close();
        // Drain output, or the process blocks once the pipe buffer is full.
        p.OutputDataReceived += (_, _) => { };
        p.ErrorDataReceived += (_, _) => { };
        p.BeginOutputReadLine();
        p.BeginErrorReadLine();
        _processes.Add(p);
        return p;
    }

    public void Dispose()
    {
        foreach (var p in _processes)
        {
            try { p.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            p.Dispose();
        }
    }

    private static string? Find()
    {
        var paths = (Environment.GetEnvironmentVariable("PATH") ?? "").Split(System.IO.Path.PathSeparator)
            .Append(System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "bin"));
        return paths.Select(p => System.IO.Path.Combine(p, OperatingSystem.IsWindows() ? "nak.exe" : "nak")).FirstOrDefault(File.Exists);
    }

    private static int FreePort()
    {
        using var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        return ((IPEndPoint)l.LocalEndpoint).Port;
    }

    private static async Task WaitForPortAsync(int port)
    {
        for (var i = 0; i < 50; i++)
        {
            try
            {
                using var c = new TcpClient();
                await c.ConnectAsync(IPAddress.Loopback, port);
                return;
            }
            catch (SocketException)
            {
                await Task.Delay(100);
            }
        }
        throw new TimeoutException($"Relay did not start on port {port}.");
    }
}
