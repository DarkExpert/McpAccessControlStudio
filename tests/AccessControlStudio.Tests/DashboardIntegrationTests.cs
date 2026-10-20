using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using AccessControlStudio.Api;
using AccessControlStudio.CrmDemo;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol.Client;

namespace AccessControlStudio.Tests;

public class DashboardIntegrationTests
{
    private static readonly string Key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

    private static WebApplicationFactory<Program> Factory(IPAddress? peer = null) =>
        new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Development");
            builder.UseSetting("Jwt:SigningKey", Key);
            builder.UseSetting("Audit:DatabasePath", Path.Combine(Path.GetTempPath(), "AccessControlStudio.Tests", Guid.NewGuid() + ".db"));
            builder.ConfigureTestServices(services => services.AddTransient<IStartupFilter>(_ =>
                new PeerFilter(peer ?? IPAddress.Loopback)));
        });

    private sealed class PeerFilter(IPAddress address) : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use((context, continuation) =>
            {
                context.Connection.RemoteIpAddress = address;
                return continuation();
            });
            next(app);
        };
    }

    private static async Task<string> Token(HttpClient http, string identity)
    {
        using var response = await http.PostAsJsonAsync("/api/demo/token", new { identity });
        response.EnsureSuccessStatusCode();
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("accessToken").GetString()!;
    }

    [Fact]
    public async Task ReadOnlyPolicyMetadataUsesTheEnforcingPolicyAndRequiresAuthentication()
    {
        using var factory = Factory();
        using var http = factory.CreateClient();
        using var anonymous = await http.GetAsync("/api/security/policy");
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
        var viewer = await Token(http, "viewer");
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", viewer);
        using var response = await http.GetAsync("/api/security/policy");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var tools = json.RootElement.EnumerateArray().ToArray();
        Assert.Equal(5, tools.Length);
        var update = tools.Single(tool => tool.GetProperty("name").GetString() == "crm.update_order");
        Assert.Equal(1000m, update.GetProperty("maximumAmount").GetDecimal());
        Assert.DoesNotContain("Viewer", update.GetProperty("allowedRoles").EnumerateArray().Select(x => x.GetString()));
        Assert.Contains("Operator", update.GetProperty("allowedRoles").EnumerateArray().Select(x => x.GetString()));
        Assert.DoesNotContain(viewer, await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task RealMcpResultMetadataMatchesPersistedTerminalAndNeverUsesAdminForViewer()
    {
        using var factory = Factory();
        using var http = factory.CreateClient();
        var viewer = await Token(http, "viewer");
        using var mcpHttp = factory.CreateClient();
        mcpHttp.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", viewer);
        await using var transport = new HttpClientTransport(new HttpClientTransportOptions
        {
            Endpoint = new Uri("http://localhost/mcp"), TransportMode = HttpTransportMode.StreamableHttp
        }, mcpHttp, ownsHttpClient: false);
        await using var client = await McpClient.CreateAsync(transport);
        var denied = await client.CallToolAsync("crm.delete_customer",
            new Dictionary<string, object?> { ["customerId"] = "customer-1", ["role"] = "Admin" });
        Assert.True(denied.IsError);
        var meta = denied.Meta?["accessControlStudio"];
        Assert.NotNull(meta);
        var correlation = meta!["correlationId"]!.GetValue<string>();
        Assert.Matches("^[a-f0-9]{32}$", correlation);
        Assert.Equal("Deny", meta["decision"]!.GetValue<string>());
        Assert.Equal("RoleDenied", meta["reasonCode"]!.GetValue<string>());
        Assert.Equal("Blocked", meta["enforcement"]!.GetValue<string>());
        Assert.Equal("NotAttempted", meta["upstreamStatus"]!.GetValue<string>());
        var events = (await factory.Services.GetRequiredService<SqliteAuditStore>()
            .ReadPageAsync(100, null, default)).Items.Where(entry => entry.CorrelationId == correlation).ToArray();
        Assert.Equal(2, events.Length);
        Assert.Contains(events, entry => entry.Kind == "Decision" && entry.Enforcement == "Pending");
        Assert.Contains(events, entry => entry.Kind == "Terminal" && entry.Enforcement == "Blocked" && entry.Subject == "viewer");
        Assert.Equal(0, factory.Services.GetRequiredService<CrmTools>().InvocationCount("crm.delete_customer"));
        using var forbidden = await http.SendAsync(new HttpRequestMessage(HttpMethod.Get, "/api/audit")
        { Headers = { Authorization = new AuthenticationHeaderValue("Bearer", viewer) } });
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);
    }

    [Fact]
    public async Task DevelopmentCorsAllowsOnlyTheExactLocalStudioOriginWithoutCredentials()
    {
        using var factory = Factory();
        using var http = factory.CreateClient();
        using var allowed = new HttpRequestMessage(HttpMethod.Options, "/api/demo/token");
        allowed.Headers.Add("Origin", "http://127.0.0.1:5173");
        allowed.Headers.Add("Access-Control-Request-Method", "POST");
        allowed.Headers.Add("Access-Control-Request-Headers", "content-type");
        using var allowedResponse = await http.SendAsync(allowed);
        Assert.Equal("http://127.0.0.1:5173", allowedResponse.Headers.GetValues("Access-Control-Allow-Origin").Single());
        Assert.False(allowedResponse.Headers.Contains("Access-Control-Allow-Credentials"));

        using var rejected = new HttpRequestMessage(HttpMethod.Options, "/api/demo/token");
        rejected.Headers.Add("Origin", "http://localhost:5173");
        rejected.Headers.Add("Access-Control-Request-Method", "POST");
        using var rejectedResponse = await http.SendAsync(rejected);
        Assert.False(rejectedResponse.Headers.Contains("Access-Control-Allow-Origin"));
    }

    [Fact]
    public async Task AllowedStudioOriginCannotBypassRemoteDemoIssuerRestriction()
    {
        using var factory = Factory(IPAddress.Parse("203.0.113.10"));
        using var http = factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/demo/token")
        { Content = JsonContent.Create(new { identity = "admin" }) };
        request.Headers.Add("Origin", "http://127.0.0.1:5173");
        request.Headers.Add("X-Forwarded-For", "127.0.0.1");
        using var response = await http.SendAsync(request);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.DoesNotContain("accessToken", await response.Content.ReadAsStringAsync());
    }
}
