using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using ModelContextProtocol.Client;

try
{
    if (args.Length != 1 || !File.Exists(args[0]))
        throw new InvalidOperationException("Pass the built API DLL path.");
    var apiDll = Path.GetFullPath(args[0]);
    var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
    var auditPath = Path.Combine(Path.GetTempPath(), "AccessControlStudio.Demo", Guid.NewGuid() + ".db");
    var port = ReserveEphemeralPort();
    var origin = new Uri($"http://127.0.0.1:{port}");
    var start = new ProcessStartInfo("dotnet")
    {
        UseShellExecute = false,
        CreateNoWindow = true,
        RedirectStandardOutput = true,
        RedirectStandardError = true
    };
    start.ArgumentList.Add(apiDll);
    start.ArgumentList.Add("--urls");
    start.ArgumentList.Add(origin.AbsoluteUri);
    start.Environment["ASPNETCORE_ENVIRONMENT"] = "Development";
    start.Environment["Jwt__SigningKey"] = key;
    start.Environment["Audit__DatabasePath"] = auditPath;
    using var server = Process.Start(start) ?? throw new InvalidOperationException("Could not start API.");
    server.OutputDataReceived += (_, _) => { };
    server.ErrorDataReceived += (_, _) => { };
    server.BeginOutputReadLine();
    server.BeginErrorReadLine();
    try
    {
        using var budget = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        using var http = new HttpClient(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false })
        {
            BaseAddress = origin,
            Timeout = TimeSpan.FromSeconds(10)
        };
        await WaitUntilReady(http, server, budget.Token);
        Console.WriteLine("Gateway ready on loopback; CRM upstream is internal.");

        var viewer = await GetToken(http, "viewer", budget.Token);
        using (var viewerReport = await Report(http, viewer, budget.Token))
            if (viewerReport.StatusCode != HttpStatusCode.Forbidden)
                throw new InvalidOperationException("Viewer reached global audit reporting.");
        await using (var connection = await Connect(origin, viewer, budget.Token))
        {
            var names = (await connection.Client.ListToolsAsync(cancellationToken: budget.Token))
                .Select(tool => tool.Name).Order(StringComparer.Ordinal).ToArray();
            var expected = new[] { "crm.delete_customer", "crm.export_customers", "crm.get_customer", "crm.list_orders", "crm.update_order" };
            if (!names.SequenceEqual(expected))
                throw new InvalidOperationException("Unexpected MCP tool catalog.");
            await Allowed(connection.Client, "crm.get_customer", new() { ["customerId"] = "customer-1" }, budget.Token);
            await Allowed(connection.Client, "crm.list_orders", null, budget.Token);
            await Denied(connection.Client, "crm.update_order", new() { ["orderId"] = "order-1", ["amount"] = 5 }, budget.Token);
            await Denied(connection.Client, "crm.delete_customer", new() { ["customerId"] = "customer-1" }, budget.Token);
            await Denied(connection.Client, "crm.export_customers", null, budget.Token);
            Console.WriteLine("Viewer: reads allowed; update, delete and export blocked.");
        }

        var operatorToken = await GetToken(http, "operator", budget.Token);
        await using (var connection = await Connect(origin, operatorToken, budget.Token))
        {
            await Allowed(connection.Client, "crm.update_order", new() { ["orderId"] = "order-1", ["amount"] = 50 }, budget.Token);
            await Denied(connection.Client, "crm.delete_customer", new() { ["customerId"] = "customer-1" }, budget.Token);
            await Denied(connection.Client, "crm.export_customers", null, budget.Token);
            Console.WriteLine("Operator: valid update allowed; delete and export blocked.");
        }

        var adminToken = await GetToken(http, "admin", budget.Token);
        await using (var connection = await Connect(origin, adminToken, budget.Token))
        {
            await Allowed(connection.Client, "crm.export_customers", null, budget.Token);
            await Allowed(connection.Client, "crm.delete_customer", new() { ["customerId"] = "customer-1" }, budget.Token);
            Console.WriteLine("Admin: export and delete allowed.");
        }
        using (var report = await Report(http, adminToken, budget.Token))
        {
            report.EnsureSuccessStatusCode();
            using var json = JsonDocument.Parse(await report.Content.ReadAsStringAsync(budget.Token));
            if (json.RootElement.GetProperty("persistedTerminalCount").GetInt64() != 10)
                throw new InvalidOperationException("Unexpected persisted audit count.");
        }
        Console.WriteLine("Admin: persisted overview reports 10 MCP calls; Viewer reporting blocked.");

        server.Kill(entireProcessTree: true);
        await server.WaitForExitAsync(budget.Token);
        var restartedOrigin = new Uri($"http://127.0.0.1:{ReserveEphemeralPort()}");
        start.ArgumentList[2] = restartedOrigin.AbsoluteUri;
        using var restarted = Process.Start(start) ?? throw new InvalidOperationException("Could not restart API.");
        restarted.OutputDataReceived += (_, _) => { };
        restarted.ErrorDataReceived += (_, _) => { };
        restarted.BeginOutputReadLine();
        restarted.BeginErrorReadLine();
        try
        {
            using var restartedHttp = new HttpClient(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false })
            {
                BaseAddress = restartedOrigin, Timeout = TimeSpan.FromSeconds(10)
            };
            await WaitUntilReady(restartedHttp, restarted, budget.Token);
            var restartedAdmin = await GetToken(restartedHttp, "admin", budget.Token);
            using var report = await Report(restartedHttp, restartedAdmin, budget.Token);
            report.EnsureSuccessStatusCode();
            using var json = JsonDocument.Parse(await report.Content.ReadAsStringAsync(budget.Token));
            if (json.RootElement.GetProperty("persistedTerminalCount").GetInt64() != 10)
                throw new InvalidOperationException("Audit records did not survive restart.");
            Console.WriteLine("SQLite audit records survived API restart.");
        }
        finally
        {
            if (!restarted.HasExited)
            {
                restarted.Kill(entireProcessTree: true);
                await restarted.WaitForExitAsync();
            }
        }
        Console.WriteLine("Real MCP SDK demonstration passed.");
    }
    finally
    {
        if (!server.HasExited)
        {
            server.Kill(entireProcessTree: true);
            await server.WaitForExitAsync();
        }
        foreach (var suffix in new[] { "", "-wal", "-shm" })
            File.Delete(auditPath + suffix);
    }
    return 0;
}
catch (Exception exception)
{
    // Never write exception messages, JWTs, arguments or tool results.
    Console.Error.WriteLine($"Demo failed ({exception.GetType().Name}).");
    return 1;
}

static int ReserveEphemeralPort()
{
    var listener = new TcpListener(IPAddress.Loopback, 0);
    listener.Start();
    var port = ((IPEndPoint)listener.LocalEndpoint).Port;
    listener.Stop();
    return port;
}

static async Task WaitUntilReady(HttpClient http, Process server, CancellationToken token)
{
    while (!token.IsCancellationRequested)
    {
        if (server.HasExited) throw new InvalidOperationException("API exited before readiness.");
        try
        {
            using var response = await http.PostAsJsonAsync("/api/authorization/evaluate", new { }, token);
            if (response.StatusCode == HttpStatusCode.Unauthorized) return;
        }
        catch (HttpRequestException) { }
        await Task.Delay(100, token);
    }
    token.ThrowIfCancellationRequested();
}

static async Task<string> GetToken(HttpClient http, string identity, CancellationToken token)
{
    using var response = await http.PostAsJsonAsync("/api/demo/token", new { identity }, token);
    response.EnsureSuccessStatusCode();
    using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(token));
    return json.RootElement.GetProperty("accessToken").GetString()!;
}

static Task<HttpResponseMessage> Report(HttpClient http, string token, CancellationToken cancellation)
{
    using var request = new HttpRequestMessage(HttpMethod.Get, "/api/security/overview");
    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
    return http.SendAsync(request, cancellation);
}

static async Task<Connection> Connect(Uri origin, string token, CancellationToken cancellation)
{
    var http = new HttpClient(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false });
    http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
    var transport = new HttpClientTransport(new HttpClientTransportOptions
    {
        Endpoint = new Uri(origin, "/mcp"),
        TransportMode = HttpTransportMode.StreamableHttp,
        ConnectionTimeout = TimeSpan.FromSeconds(10)
    }, http, ownsHttpClient: true);
    try
    {
        var client = await McpClient.CreateAsync(transport, cancellationToken: cancellation);
        return new Connection(transport, client);
    }
    catch
    {
        await transport.DisposeAsync();
        throw;
    }
}

static async Task Allowed(McpClient client, string name, Dictionary<string, object?>? arguments, CancellationToken token)
{
    var result = await client.CallToolAsync(name, arguments, cancellationToken: token);
    if (result.IsError == true) throw new InvalidOperationException("Expected tool allowance.");
}

static async Task Denied(McpClient client, string name, Dictionary<string, object?>? arguments, CancellationToken token)
{
    var result = await client.CallToolAsync(name, arguments, cancellationToken: token);
    if (result.IsError != true) throw new InvalidOperationException("Expected tool denial.");
}

sealed record Connection(HttpClientTransport Transport, McpClient Client) : IAsyncDisposable
{
    public async ValueTask DisposeAsync()
    {
        await Client.DisposeAsync();
        await Transport.DisposeAsync();
    }
}
