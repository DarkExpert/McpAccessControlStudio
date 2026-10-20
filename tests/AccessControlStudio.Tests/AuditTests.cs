using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Collections.Concurrent;
using AccessControlStudio.Api;
using AccessControlStudio.CrmDemo;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Client;
using Microsoft.Data.Sqlite;

namespace AccessControlStudio.Tests;

public class AuditTests
{
    private static readonly string Key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

    private static WebApplicationFactory<Program> Factory(string path, bool failWrites = false, ILoggerProvider? logger = null) =>
        new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Development");
            builder.UseSetting("Jwt:SigningKey", Key);
            builder.UseSetting("Audit:DatabasePath", path);
            if (logger is not null) builder.ConfigureLogging(logging => logging.AddProvider(logger));
            builder.ConfigureTestServices(services =>
            {
                services.AddTransient<IStartupFilter>(_ => new LoopbackFilter());
                if (failWrites) services.Replace(ServiceDescriptor.Singleton<IAuditWriter, FailingWriter>());
            });
        });

    private sealed class FailingWriter : IAuditWriter
    {
        public Task WriteAsync(SecurityAuditEvent entry, CancellationToken token) =>
            throw new IOException("SENSITIVE_EXCEPTION_MARKER");
    }

    private sealed class CaptureLogger : ILoggerProvider
    {
        public ConcurrentQueue<string> Messages { get; } = new();
        public ILogger CreateLogger(string categoryName) => new Sink(Messages);
        public void Dispose() { }
        private sealed class Sink(ConcurrentQueue<string> messages) : ILogger
        {
            public IDisposable BeginScope<TState>(TState state) where TState : notnull => Scope.Instance;
            public bool IsEnabled(LogLevel level) => true;
            public void Log<TState>(LogLevel level, EventId id, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter) => messages.Enqueue(formatter(state, exception));
        }
        private sealed class Scope : IDisposable
        {
            public static readonly Scope Instance = new();
            public void Dispose() { }
        }
    }

    private sealed class LoopbackFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use((context, continuation) =>
            {
                context.Connection.RemoteIpAddress = IPAddress.Loopback;
                return continuation();
            });
            next(app);
        };
    }

    private static string Database() => Path.Combine(Path.GetTempPath(), "AccessControlStudio.Tests", Guid.NewGuid() + ".db");

    private static async Task<string> Token(HttpClient http, string identity)
    {
        using var response = await http.PostAsJsonAsync("/api/demo/token", new { identity });
        response.EnsureSuccessStatusCode();
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("accessToken").GetString()!;
    }

    private static async Task<HttpResponseMessage> Call(HttpClient http, string? token, string name, string arguments = "{}")
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/mcp")
        {
            Content = new StringContent(JsonSerializer.Serialize(new
            {
                jsonrpc = "2.0", id = 1, method = "tools/call",
                @params = new { name, arguments = JsonDocument.Parse(arguments).RootElement }
            }), Encoding.UTF8, "application/json")
        };
        request.Headers.TryAddWithoutValidation("Accept", "application/json, text/event-stream");
        request.Headers.Add("MCP-Protocol-Version", "2025-06-18");
        if (token is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await http.SendAsync(request);
    }

    private static async Task<AuditPage> Events(WebApplicationFactory<Program> factory) =>
        await factory.Services.GetRequiredService<SqliteAuditStore>().ReadPageAsync(100, null, default);

    [Fact]
    public async Task UnsupportedSchemaVersionLeavesExistingDatabaseUnchanged()
    {
        var path = Database();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        await using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString()))
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = "CREATE TABLE sentinel (value TEXT NOT NULL); INSERT INTO sentinel VALUES ('retain-me'); PRAGMA user_version = 99;";
            await command.ExecuteNonQueryAsync();
        }
        var before = await File.ReadAllBytesAsync(path);
        var store = new SqliteAuditStore(path);
        await Assert.ThrowsAsync<InvalidOperationException>(() => store.InitializeAsync());
        Assert.Equal(before, await File.ReadAllBytesAsync(path));
        Assert.False(File.Exists(path + "-wal"));
        Assert.False(File.Exists(path + "-shm"));
        await using var verify = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString());
        await verify.OpenAsync();
        await using var query = verify.CreateCommand();
        query.CommandText = "SELECT value FROM sentinel;";
        Assert.Equal("retain-me", await query.ExecuteScalarAsync());
        query.CommandText = "PRAGMA user_version;";
        Assert.Equal(99L, await query.ExecuteScalarAsync());
        query.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE name = 'audit_events';";
        Assert.Equal(0L, await query.ExecuteScalarAsync());
    }

    [Fact]
    public async Task AllowedDeniedAndUnknownCallsHavePairedSafeEventsAndCorrectAttribution()
    {
        using var factory = Factory(Database());
        using var http = factory.CreateClient();
        var viewer = await Token(http, "viewer");
        using var allowed = await Call(http, viewer, "crm.get_customer", "{\"customerId\":\"customer-1\",\"credential\":\"SECRET_ARGUMENT_MARKER\"}");
        using var denied = await Call(http, viewer, "crm.delete_customer", "{\"customerId\":\"customer-1\"}");
        using var unknown = await Call(http, viewer, "SECRET_TOOL_MARKER");
        var events = (await Events(factory)).Items;
        Assert.Equal(6, events.Count);
        foreach (var pair in events.GroupBy(e => e.CorrelationId))
        {
            Assert.Equal(2, pair.Count());
            Assert.Contains(pair, e => e.Kind == "Decision");
            Assert.Contains(pair, e => e.Kind == "Terminal");
            Assert.All(pair, e =>
            {
                Assert.Equal("viewer", e.Subject);
                Assert.Equal("Viewer", e.Role);
                Assert.Equal(TimeSpan.Zero, e.TimestampUtc.Offset);
                Assert.True(e.DurationMs >= 0);
            });
        }
        Assert.All(events.Where(e => e.Kind == "Decision"), e =>
        {
            Assert.Equal("Pending", e.Enforcement);
            Assert.Equal("NotAttempted", e.UpstreamStatus);
        });
        Assert.Contains(events, e => e.Kind == "Terminal" && e.ToolName == "crm.get_customer" &&
            e.Decision == "Allow" && e.ReasonCode == "Allowed" && e.Enforcement == "Forwarded" && e.UpstreamStatus == "Succeeded");
        Assert.Contains(events, e => e.Kind == "Terminal" && e.ToolName == "crm.delete_customer" &&
            e.Decision == "Deny" && e.ReasonCode == "RoleDenied" && e.Enforcement == "Blocked" && e.UpstreamStatus == "NotAttempted");
        Assert.Contains(events, e => e.Kind == "Terminal" && e.ToolName == "UnknownTool" && e.ReasonCode == "UnknownTool");
        var counters = factory.Services.GetRequiredService<CrmTools>();
        Assert.Equal(1, counters.InvocationCount("crm.get_customer"));
        Assert.Equal(0, counters.InvocationCount("crm.delete_customer"));
        var stored = string.Join(" ", events.Select(e => e.ToString()));
        Assert.DoesNotContain(viewer, stored);
        Assert.DoesNotContain(Key, stored);
        Assert.DoesNotContain("SECRET_ARGUMENT_MARKER", stored);
        Assert.DoesNotContain("SECRET_TOOL_MARKER", stored);
        Assert.DoesNotContain("Ada Example", stored);
    }

    [Fact]
    public async Task ToolErrorAndCancellationAreReportedWithoutClaimingSideEffectCertainty()
    {
        using var factory = Factory(Database());
        using var http = factory.CreateClient();
        var viewer = await Token(http, "viewer");
        using var toolError = await Call(http, viewer, "crm.get_customer", "{\"customerId\":\"missing\"}");
        Assert.Contains((await Events(factory)).Items, e => e.Kind == "Terminal" && e.UpstreamStatus == "ToolError");

        var counters = factory.Services.GetRequiredService<CrmTools>();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        counters.BeforeReadResult = async cancellation =>
        {
            started.TrySetResult();
            await Task.Delay(TimeSpan.FromSeconds(30), cancellation);
        };
        using var cancellation = new CancellationTokenSource();
        using var clientHttp = factory.CreateClient();
        clientHttp.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", viewer);
        await using var transport = new HttpClientTransport(new HttpClientTransportOptions
        {
            Endpoint = new Uri("http://localhost/mcp"), TransportMode = HttpTransportMode.StreamableHttp
        }, clientHttp, ownsHttpClient: false);
        await using var client = await McpClient.CreateAsync(transport);
        var pending = client.CallToolAsync("crm.get_customer", new Dictionary<string, object?>
        {
            ["customerId"] = "customer-1"
        }, cancellationToken: cancellation.Token).AsTask();
        await started.Task.WaitAsync(TimeSpan.FromSeconds(10));
        cancellation.Cancel();
        try { await pending; } catch (Exception) { /* SDK cancellation shapes vary. */ }
        var terminal = (await Events(factory)).Items.Where(e => e.Kind == "Terminal").ToArray();
        Assert.Contains(terminal, e => e.UpstreamStatus == "Unknown" && e.ErrorCategory == "Canceled");
        Assert.Equal(2, counters.InvocationCount("crm.get_customer"));
    }

    [Fact]
    public async Task AdminOnlyReportsArePagedAndPersistAfterRestart()
    {
        var path = Database();
        using (var first = Factory(path))
        using (var http = first.CreateClient())
        {
            var viewer = await Token(http, "viewer");
            var admin = await Token(http, "admin");
            using var call1 = await Call(http, viewer, "crm.get_customer", "{\"customerId\":\"customer-1\"}");
            using var call2 = await Call(http, viewer, "crm.delete_customer");
            using var anonymous = await http.GetAsync("/api/audit");
            Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", viewer);
            http.DefaultRequestHeaders.Add("X-Role", "Admin");
            using var forbidden = await http.GetAsync("/api/audit");
            using var forbiddenOverview = await http.GetAsync("/api/security/overview");
            Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, forbiddenOverview.StatusCode);
            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", admin);
            using var page = await http.GetAsync("/api/audit?limit=1");
            Assert.Equal(HttpStatusCode.OK, page.StatusCode);
            using var firstPage = JsonDocument.Parse(await page.Content.ReadAsStringAsync());
            Assert.Equal(1, firstPage.RootElement.GetProperty("items").GetArrayLength());
            var cursor = firstPage.RootElement.GetProperty("nextCursor").GetInt64();
            using var secondPage = await http.GetAsync($"/api/audit?limit=1&cursor={cursor}");
            using var second = JsonDocument.Parse(await secondPage.Content.ReadAsStringAsync());
            Assert.True(second.RootElement.GetProperty("items")[0].GetProperty("id").GetInt64() < cursor);
            using var invalid = await http.GetAsync("/api/audit?limit=101");
            Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
            using var overview = await http.GetAsync("/api/security/overview");
            using var summary = JsonDocument.Parse(await overview.Content.ReadAsStringAsync());
            Assert.Equal(2, summary.RootElement.GetProperty("persistedTerminalCount").GetInt64());
            Assert.Equal(1, summary.RootElement.GetProperty("allowed").GetInt64());
            Assert.Equal(1, summary.RootElement.GetProperty("denied").GetInt64());
            Assert.Equal(1, summary.RootElement.GetProperty("forwarded").GetInt64());
            Assert.Equal(1, summary.RootElement.GetProperty("blocked").GetInt64());
            Assert.DoesNotContain(viewer, await page.Content.ReadAsStringAsync());
        }
        using var restarted = Factory(path);
        using var restartHttp = restarted.CreateClient();
        var restartedAdmin = await Token(restartHttp, "admin");
        restartHttp.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", restartedAdmin);
        using var persisted = await restartHttp.GetAsync("/api/security/overview");
        using var persistedJson = JsonDocument.Parse(await persisted.Content.ReadAsStringAsync());
        Assert.Equal(2, persistedJson.RootElement.GetProperty("persistedTerminalCount").GetInt64());
    }

    [Fact]
    public async Task AuditWriteFailureDoesNotRetryOrChangeToolResult()
    {
        var logger = new CaptureLogger();
        using var factory = Factory(Database(), failWrites: true, logger: logger);
        using var http = factory.CreateClient();
        var viewer = await Token(http, "viewer");
        using var allowed = await Call(http, viewer, "crm.get_customer", "{\"customerId\":\"customer-1\"}");
        using var denied = await Call(http, viewer, "crm.delete_customer");
        Assert.Contains("Ada Example", await allowed.Content.ReadAsStringAsync());
        Assert.Contains("RoleDenied", await denied.Content.ReadAsStringAsync());
        var counters = factory.Services.GetRequiredService<CrmTools>();
        Assert.Equal(1, counters.InvocationCount("crm.get_customer"));
        Assert.Equal(0, counters.InvocationCount("crm.delete_customer"));
        Assert.Empty((await Events(factory)).Items);
        var logs = string.Join("\n", logger.Messages);
        Assert.Contains("Security audit persistence failed", logs);
        Assert.DoesNotContain("SENSITIVE_EXCEPTION_MARKER", logs);
        Assert.DoesNotContain(viewer, logs);
        Assert.DoesNotContain(Key, logs);
    }

    [Fact]
    public async Task AuthenticationFailureDoesNotCreateAttributedAuditRecords()
    {
        using var factory = Factory(Database());
        using var http = factory.CreateClient();
        using var missing = await Call(http, null, "crm.get_customer");
        using var invalid = await Call(http, "INVALID_TOKEN_MARKER", "crm.get_customer");
        Assert.Equal(HttpStatusCode.Unauthorized, missing.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, invalid.StatusCode);
        Assert.Empty((await Events(factory)).Items);
        Assert.Equal(0, factory.Services.GetRequiredService<CrmTools>().InvocationCount("crm.get_customer"));
    }

    [Fact]
    public async Task OperatorArgumentPolicyAndConcurrentCallsKeepIdentityAndPairs()
    {
        using var factory = Factory(Database());
        using var http = factory.CreateClient();
        var token = await Token(http, "operator");
        var calls = Enumerable.Range(0, 8).Select(async index =>
        {
            using var response = await Call(http, token, "crm.update_order",
                index % 2 == 0 ? "{\"orderId\":\"order-1\",\"amount\":5}" :
                    "{\"orderId\":\"order-1\",\"amount\":1001}");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        });
        await Task.WhenAll(calls);
        var events = (await Events(factory)).Items;
        Assert.Equal(16, events.Count);
        Assert.All(events, e => { Assert.Equal("operator", e.Subject); Assert.Equal("Operator", e.Role); });
        Assert.All(events.GroupBy(e => e.CorrelationId), pair => Assert.Equal(2, pair.Count()));
        Assert.Equal(4, events.Count(e => e.Kind == "Terminal" && e.ReasonCode == "AmountLimitExceeded" && e.Enforcement == "Blocked"));
        Assert.Equal(4, factory.Services.GetRequiredService<CrmTools>().InvocationCount("crm.update_order"));
    }

    [Fact]
    public async Task ReportingStorageFailureReturnsSafeUnavailableResponse()
    {
        var path = Database();
        using var factory = Factory(path);
        using var http = factory.CreateClient();
        var admin = await Token(http, "admin");
        await using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path }.ToString()))
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = "DROP TABLE audit_events;";
            await command.ExecuteNonQueryAsync();
        }
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", admin);
        foreach (var endpoint in new[] { "/api/audit", "/api/security/overview" })
        {
            using var response = await http.GetAsync(endpoint);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
            var body = await response.Content.ReadAsStringAsync();
            Assert.Contains("AuditUnavailable", body);
            Assert.DoesNotContain(path, body);
            Assert.DoesNotContain(admin, body);
            Assert.DoesNotContain("audit_events", body);
        }
    }

    [Fact]
    public async Task GatewayTimeoutRecordsUnknownUpstreamStatus()
    {
        using var factory = Factory(Database());
        using var http = factory.CreateClient();
        var viewer = await Token(http, "viewer");
        var counters = factory.Services.GetRequiredService<CrmTools>();
        counters.BeforeReadResult = async cancellation =>
            await Task.Delay(TimeSpan.FromSeconds(30), cancellation);
        try
        {
            using var response = await Call(http, viewer, "crm.get_customer", "{\"customerId\":\"customer-1\"}");
        }
        catch (Exception exception) when (exception is OperationCanceledException or HttpRequestException) { }
        var terminal = (await Events(factory)).Items.Single(e => e.Kind == "Terminal");
        Assert.Equal("Allow", terminal.Decision);
        Assert.Equal("Forwarded", terminal.Enforcement);
        Assert.Equal("Unknown", terminal.UpstreamStatus);
        Assert.Equal("Timeout", terminal.ErrorCategory);
        Assert.Equal(1, counters.InvocationCount("crm.get_customer"));
    }
}
