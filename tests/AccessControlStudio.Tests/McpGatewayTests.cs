using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Collections.Concurrent;
using AccessControlStudio.CrmDemo;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using Microsoft.IdentityModel.Tokens;

namespace AccessControlStudio.Tests;

public class McpGatewayTests
{
    private const string Issuer = "AccessControlStudio.Demo";
    private const string Audience = "AccessControlStudio.Api";
    private static readonly string Key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

    private static WebApplicationFactory<Program> Factory(ILoggerProvider? logger = null) =>
        new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Development");
            builder.UseSetting("Jwt:SigningKey", Key);
            if (logger is not null) builder.ConfigureLogging(logging => logging.AddProvider(logger));
            builder.ConfigureTestServices(services =>
                services.AddTransient<IStartupFilter>(_ => new LoopbackFilter()));
        });

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

    private static async Task<string> DemoToken(HttpClient client, string identity)
    {
        using var response = await client.PostAsJsonAsync("/api/demo/token", new { identity });
        response.EnsureSuccessStatusCode();
        using var json = System.Text.Json.JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("accessToken").GetString()!;
    }

    private static async Task<(HttpClientTransport Transport, McpClient Client)> Connect(
        WebApplicationFactory<Program> factory, string token)
    {
        var http = factory.CreateClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var transport = new HttpClientTransport(new HttpClientTransportOptions
        {
            Endpoint = new Uri("http://localhost/mcp"),
            TransportMode = HttpTransportMode.StreamableHttp,
            ConnectionTimeout = TimeSpan.FromSeconds(10)
        }, http, ownsHttpClient: true);
        var client = await McpClient.CreateAsync(transport, cancellationToken: new CancellationTokenSource(TimeSpan.FromSeconds(20)).Token);
        return (transport, client);
    }

    private static string SignedToken(string issuer = Issuer, string audience = Audience,
        string? signingKey = null, DateTime? expires = null)
    {
        var jwt = new JwtSecurityToken(issuer, audience,
            [new Claim(JwtRegisteredClaimNames.Sub, "viewer"), new Claim("role", "Viewer")],
            notBefore: DateTime.UtcNow.AddMinutes(-20),
            expires: expires ?? DateTime.UtcNow.AddMinutes(5),
            signingCredentials: new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey ?? Key)), SecurityAlgorithms.HmacSha256));
        return new JwtSecurityTokenHandler().WriteToken(jwt);
    }

    private static async Task<HttpResponseMessage> RawCall(HttpClient client, string name, string arguments,
        string? token, bool addSpoofedRole = false)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/mcp")
        {
            Content = new StringContent("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"" + name + "\",\"arguments\":" + arguments + "}}",
                Encoding.UTF8, "application/json")
        };
        request.Headers.TryAddWithoutValidation("Accept", "application/json, text/event-stream");
        request.Headers.Add("MCP-Protocol-Version", "2025-06-18");
        if (token is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        if (addSpoofedRole) request.Headers.Add("X-Role", "Admin");
        return await client.SendAsync(request);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("expired")]
    [InlineData("tampered")]
    [InlineData("issuer")]
    [InlineData("audience")]
    public async Task InvalidJwtCannotReachMcpHandler(string scenario)
    {
        using var factory = Factory();
        using var client = factory.CreateClient();
        var token = scenario switch
        {
            "missing" => null,
            "expired" => SignedToken(expires: DateTime.UtcNow.AddMinutes(-1)),
            "tampered" => SignedToken(signingKey: Convert.ToBase64String(RandomNumberGenerator.GetBytes(64))),
            "issuer" => SignedToken(issuer: "wrong-issuer"),
            "audience" => SignedToken(audience: "wrong-audience"),
            _ => throw new InvalidOperationException()
        };
        using var response = await RawCall(client, "crm.get_customer", "{\"customerId\":\"customer-1\"}", token);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(0, factory.Services.GetRequiredService<CrmTools>().InvocationCount("crm.get_customer"));
    }

    [Fact]
    public async Task ViewerDeniedMutationsHaveZeroUpstreamCallsEvenWithForgedRoles()
    {
        using var factory = Factory();
        using var http = factory.CreateClient();
        var token = await DemoToken(http, "viewer");
        var (transport, client) = await Connect(factory, token);
        await using var transportLifetime = transport;
        await using var clientLifetime = client;
        foreach (var (name, arguments) in new[]
        {
            ("crm.update_order", new Dictionary<string, object?> { ["orderId"] = "order-1", ["amount"] = 5, ["role"] = "Admin" }),
            ("crm.delete_customer", new Dictionary<string, object?> { ["customerId"] = "customer-1", ["role"] = "Admin" }),
            ("crm.export_customers", new Dictionary<string, object?> { ["role"] = "Admin" })
        })
        {
            Assert.True((await client.CallToolAsync(name, arguments)).IsError);
            Assert.Equal(0, factory.Services.GetRequiredService<CrmTools>().InvocationCount(name));
        }
        using var spoofed = await RawCall(http, "crm.delete_customer", "{\"customerId\":\"customer-1\",\"role\":\"Admin\"}", token, true);
        Assert.Equal(0, factory.Services.GetRequiredService<CrmTools>().InvocationCount("crm.delete_customer"));
    }

    [Fact]
    public async Task OperatorArgumentAndRoleDenialsNeverReachUpstream()
    {
        using var factory = Factory();
        using var http = factory.CreateClient();
        var token = await DemoToken(http, "operator");
        var (transport, client) = await Connect(factory, token);
        await using var transportLifetime = transport;
        await using var clientLifetime = client;
        foreach (var amount in new object?[] { 1000.01m, "5", null })
        {
            var arguments = new Dictionary<string, object?> { ["orderId"] = "order-1" };
            if (amount is not null) arguments["amount"] = amount;
            Assert.True((await client.CallToolAsync("crm.update_order", arguments)).IsError);
        }
        foreach (var name in new[] { "crm.delete_customer", "crm.export_customers" })
            Assert.True((await client.CallToolAsync(name)).IsError);
        var counters = factory.Services.GetRequiredService<CrmTools>();
        Assert.Equal(0, counters.InvocationCount("crm.update_order"));
        Assert.Equal(0, counters.InvocationCount("crm.delete_customer"));
        Assert.Equal(0, counters.InvocationCount("crm.export_customers"));

        // Duplicate JSON properties would be collapsed by a dictionary decoder; reject before SDK dispatch.
        using var duplicate = await RawCall(http, "crm.update_order",
            "{\"orderId\":\"order-1\",\"amount\":5,\"amount\":1001}", token);
        Assert.Equal(HttpStatusCode.BadRequest, duplicate.StatusCode);
        Assert.Equal(0, counters.InvocationCount("crm.update_order"));
    }

    [Fact]
    public async Task OperatorAndAdminAllowedCallsReachSeededCrm()
    {
        using var factory = Factory();
        using var http = factory.CreateClient();
        var operatorToken = await DemoToken(http, "operator");
        var (operatorTransport, operatorClient) = await Connect(factory, operatorToken);
        await using var operatorTransportLifetime = operatorTransport;
        await using var operatorClientLifetime = operatorClient;
        var update = await operatorClient.CallToolAsync("crm.update_order",
            new Dictionary<string, object?> { ["orderId"] = "order-1", ["amount"] = 1000 });
        Assert.NotEqual(true, update.IsError);

        var adminToken = await DemoToken(http, "admin");
        var (adminTransport, adminClient) = await Connect(factory, adminToken);
        await using var adminTransportLifetime = adminTransport;
        await using var adminClientLifetime = adminClient;
        Assert.NotEqual(true, (await adminClient.CallToolAsync("crm.export_customers")).IsError);
        Assert.NotEqual(true, (await adminClient.CallToolAsync("crm.delete_customer",
            new Dictionary<string, object?> { ["customerId"] = "customer-1" })).IsError);
        var counters = factory.Services.GetRequiredService<CrmTools>();
        Assert.Equal(1, counters.InvocationCount("crm.update_order"));
        Assert.Equal(1, counters.InvocationCount("crm.export_customers"));
        Assert.Equal(1, counters.InvocationCount("crm.delete_customer"));
    }

    [Theory]
    [InlineData("unknown")]
    [InlineData("crm.Get_customer")]
    public async Task DirectUnknownOrCaseMismatchedCallNeverReachesUpstream(string name)
    {
        using var factory = Factory();
        using var http = factory.CreateClient();
        var token = await DemoToken(http, "admin");
        var (transport, client) = await Connect(factory, token);
        await using var transportLifetime = transport;
        await using var clientLifetime = client;
        Assert.True((await client.CallToolAsync(name)).IsError);
        var counters = factory.Services.GetRequiredService<CrmTools>();
        foreach (var tool in new[] { "crm.get_customer", "crm.list_orders", "crm.update_order", "crm.delete_customer", "crm.export_customers" })
            Assert.Equal(0, counters.InvocationCount(tool));
    }

    [Fact]
    public async Task UpstreamToolErrorRemainsToolError()
    {
        using var factory = Factory();
        using var http = factory.CreateClient();
        var token = await DemoToken(http, "viewer");
        var (transport, client) = await Connect(factory, token);
        await using var transportLifetime = transport;
        await using var clientLifetime = client;
        var result = await client.CallToolAsync("crm.get_customer",
            new Dictionary<string, object?> { ["customerId"] = "missing" });
        Assert.True(result.IsError);
        Assert.Equal(1, factory.Services.GetRequiredService<CrmTools>().InvocationCount("crm.get_customer"));
    }

    [Fact]
    public async Task CancellationAfterForwardingDoesNotProveNoUpstreamInvocation()
    {
        using var factory = Factory();
        using var http = factory.CreateClient();
        var token = await DemoToken(http, "viewer");
        var (transport, client) = await Connect(factory, token);
        await using var transportLifetime = transport;
        await using var clientLifetime = client;
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var counters = factory.Services.GetRequiredService<CrmTools>();
        counters.BeforeReadResult = async cancellation =>
        {
            started.TrySetResult();
            await Task.Delay(TimeSpan.FromSeconds(30), cancellation);
        };
        using var cancellation = new CancellationTokenSource();
        var call = client.CallToolAsync("crm.get_customer",
            new Dictionary<string, object?> { ["customerId"] = "customer-1" },
            cancellationToken: cancellation.Token).AsTask();
        await started.Task.WaitAsync(TimeSpan.FromSeconds(10));
        cancellation.Cancel();
        try { Assert.True((await call).IsError); }
        catch (Exception exception) when (exception is OperationCanceledException or ModelContextProtocol.McpException or HttpRequestException) { }
        Assert.Equal(1, counters.InvocationCount("crm.get_customer"));
    }

    [Fact]
    public async Task GatewayTimeoutAfterForwardingHasUnknownSideEffectOutcome()
    {
        using var factory = Factory();
        using var http = factory.CreateClient();
        var token = await DemoToken(http, "viewer");
        var (transport, client) = await Connect(factory, token);
        await using var transportLifetime = transport;
        await using var clientLifetime = client;
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var counters = factory.Services.GetRequiredService<CrmTools>();
        counters.BeforeReadResult = async cancellation =>
        {
            started.TrySetResult();
            await Task.Delay(TimeSpan.FromSeconds(30), cancellation);
        };
        var call = client.CallToolAsync("crm.get_customer",
            new Dictionary<string, object?> { ["customerId"] = "customer-1" }).AsTask();
        await started.Task.WaitAsync(TimeSpan.FromSeconds(10));
        try { Assert.True((await call.WaitAsync(TimeSpan.FromSeconds(15))).IsError); }
        catch (Exception exception) when (exception is OperationCanceledException or ModelContextProtocol.McpException or HttpRequestException) { }
        Assert.Equal(1, counters.InvocationCount("crm.get_customer"));
    }

    [Fact]
    public async Task GatewayAndCrmLogsExcludeBearerKeyArgumentsAndResultPayload()
    {
        var logger = new CaptureLoggerProvider();
        using var factory = Factory(logger);
        using var http = factory.CreateClient();
        var token = await DemoToken(http, "viewer");
        var (transport, client) = await Connect(factory, token);
        await using var transportLifetime = transport;
        await using var clientLifetime = client;
        var result = await client.CallToolAsync("crm.get_customer",
            new Dictionary<string, object?> { ["customerId"] = "customer-1", ["credential"] = "SECRET_ARGUMENT_MARKER" });
        Assert.NotEqual(true, result.IsError);
        var logs = string.Join("\n", logger.Messages);
        Assert.DoesNotContain(token, logs);
        Assert.DoesNotContain(Key, logs);
        Assert.DoesNotContain("SECRET_ARGUMENT_MARKER", logs);
        Assert.DoesNotContain("Ada Example", logs);
    }

    private sealed class CaptureLoggerProvider : ILoggerProvider
    {
        public ConcurrentQueue<string> Messages { get; } = new();
        public ILogger CreateLogger(string categoryName) => new CaptureLogger(Messages);
        public void Dispose() { }
        private sealed class CaptureLogger(ConcurrentQueue<string> messages) : ILogger
        {
            public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;
            public bool IsEnabled(LogLevel logLevel) => true;
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter) => messages.Enqueue(formatter(state, exception));
        }
        private sealed class NullScope : IDisposable
        {
            public static readonly NullScope Instance = new();
            public void Dispose() { }
        }
    }

    [Fact]
    public async Task ViewerCanReadAndCannotUpdate()
    {
        using var factory = Factory();
        using var http = factory.CreateClient();
        var token = await DemoToken(http, "viewer");
        var (transport, client) = await Connect(factory, token);
        await using var transportLifetime = transport;
        await using var clientLifetime = client;
        var tools = await client.ListToolsAsync();
        Assert.Equal(5, tools.Count);
        var read = await client.CallToolAsync("crm.get_customer", new Dictionary<string, object?> { ["customerId"] = "customer-1" });
        Assert.NotEqual(true, read.IsError);
        var update = await client.CallToolAsync("crm.update_order", new Dictionary<string, object?> { ["orderId"] = "order-1", ["amount"] = 5 });
        Assert.True(update.IsError);
        var counters = factory.Services.GetRequiredService<CrmTools>();
        Assert.Equal(1, counters.InvocationCount("crm.get_customer"));
        Assert.Equal(0, counters.InvocationCount("crm.update_order"));
    }
}
