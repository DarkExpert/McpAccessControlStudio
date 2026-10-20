using System.IdentityModel.Tokens.Jwt;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using AccessControlStudio.Core;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace AccessControlStudio.Tests;

public class AuthorizationTests
{
    private static readonly AuthorizationPolicy Policy = new();
    private const string Key = "integration-test-signing-key-64-bytes-minimum-for-algorithm-regression-123";
    private const string Issuer = "AccessControlStudio.Demo";
    private const string Audience = "AccessControlStudio.Api";

    [Theory]
    [InlineData(StudioRole.Viewer, "crm.get_customer", true)]
    [InlineData(StudioRole.Viewer, "crm.list_orders", true)]
    [InlineData(StudioRole.Viewer, "crm.update_order", false)]
    [InlineData(StudioRole.Viewer, "crm.delete_customer", false)]
    [InlineData(StudioRole.Viewer, "crm.export_customers", false)]
    [InlineData(StudioRole.Operator, "crm.get_customer", true)]
    [InlineData(StudioRole.Operator, "crm.list_orders", true)]
    [InlineData(StudioRole.Operator, "crm.update_order", true)]
    [InlineData(StudioRole.Operator, "crm.delete_customer", false)]
    [InlineData(StudioRole.Operator, "crm.export_customers", false)]
    [InlineData(StudioRole.Admin, "crm.get_customer", true)]
    [InlineData(StudioRole.Admin, "crm.list_orders", true)]
    [InlineData(StudioRole.Admin, "crm.update_order", true)]
    [InlineData(StudioRole.Admin, "crm.delete_customer", true)]
    [InlineData(StudioRole.Admin, "crm.export_customers", true)]
    public void RoleMatrix(StudioRole role, string tool, bool allowed)
    {
        var decision = Policy.Evaluate(new("user", role, tool, JsonDocument.Parse("""{"amount":100}""").RootElement));
        Assert.Equal(allowed, decision.Allowed);
        Assert.Equal(allowed ? DecisionCode.Allowed : DecisionCode.RoleDenied, decision.Code);
    }

    [Theory]
    [InlineData("crm.Get_customer")]
    [InlineData("crm.get_customer ")]
    [InlineData("CRM.get_customer")]
    [InlineData("unknown")]
    public void UnknownOrInexactToolDefaultsToDeny(string tool)
    {
        Assert.Equal(DecisionCode.UnknownTool, Policy.Evaluate(new("user", StudioRole.Admin, tool, default)).Code);
    }

    [Theory]
    [InlineData("""{"amount":1000}""", true, DecisionCode.Allowed)]
    [InlineData("""{"amount":1000.01}""", false, DecisionCode.AmountLimitExceeded)]
    [InlineData("""{"amount":-1}""", false, DecisionCode.InvalidArguments)]
    [InlineData("""{"amount":"10"}""", false, DecisionCode.InvalidArguments)]
    [InlineData("""{"amount":null}""", false, DecisionCode.InvalidArguments)]
    [InlineData("""{}""", false, DecisionCode.InvalidArguments)]
    [InlineData("""{"amount":1e100}""", false, DecisionCode.InvalidArguments)]
    [InlineData("""{"amount":5,"amount":6}""", false, DecisionCode.InvalidArguments)]
    [InlineData("""[]""", false, DecisionCode.InvalidArguments)]
    public void AmountConstraint(string arguments, bool allowed, DecisionCode code)
    {
        var decision = Policy.Evaluate(new("user", StudioRole.Operator, "crm.update_order", JsonDocument.Parse(arguments).RootElement));
        Assert.Equal(allowed, decision.Allowed);
        Assert.Equal(code, decision.Code);
    }

    private static WebApplicationFactory<Program> Factory(string environment = "Development", ILoggerProvider? logger = null) =>
        new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment(environment);
            builder.UseSetting("Jwt:SigningKey", Key);
            if (environment != "Development") builder.UseSetting("Jwt:Issuer", "Production.Test.Issuer");
            if (logger is not null) builder.ConfigureLogging(logging => logging.AddProvider(logger));
        });

    private static string Token(string subject = "viewer", string role = "Viewer",
        string issuer = Issuer, string audience = Audience, string? key = null,
        string algorithm = SecurityAlgorithms.HmacSha256, DateTime? expires = null,
        bool includeSubject = true, bool includeRole = true)
    {
        var claims = new List<Claim>();
        if (includeSubject) claims.Add(new(JwtRegisteredClaimNames.Sub, subject));
        if (includeRole) claims.Add(new("role", role));
        var jwt = new JwtSecurityToken(issuer, audience, claims,
            notBefore: DateTime.UtcNow.AddMinutes(-20),
            expires: expires ?? DateTime.UtcNow.AddMinutes(5),
            signingCredentials: new(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key ?? Key)), algorithm));
        return new JwtSecurityTokenHandler().WriteToken(jwt);
    }

    private static async Task<HttpResponseMessage> Evaluate(HttpClient client, string? token, object? payload = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/authorization/evaluate")
        {
            Content = JsonContent.Create(payload ?? new { toolName = "crm.delete_customer", arguments = new { }, role = "Admin" })
        };
        request.Headers.Add("X-Role", "Admin");
        if (token is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await client.SendAsync(request);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("invalid")]
    [InlineData("expired")]
    [InlineData("tampered")]
    [InlineData("issuer")]
    [InlineData("audience")]
    [InlineData("algorithm")]
    [InlineData("subject")]
    [InlineData("role")]
    public async Task InvalidTokensAreRejectedAtHttpBoundary(string scenario)
    {
        using var factory = Factory();
        using var client = factory.CreateClient();
        var token = scenario switch
        {
            "missing" => null,
            "invalid" => "not-a-jwt",
            "expired" => Token(expires: DateTime.UtcNow.AddMinutes(-1)),
            "tampered" => Token(key: "different-integration-test-signing-key-32-bytes"),
            "issuer" => Token(issuer: "another-issuer"),
            "audience" => Token(audience: "another-audience"),
            "algorithm" => Token(algorithm: SecurityAlgorithms.HmacSha384),
            "subject" => Token(includeSubject: false),
            "role" => Token(includeRole: false),
            _ => throw new InvalidOperationException()
        };
        using var response = await Evaluate(client, token);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.DoesNotContain(Key, await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task HeaderAndBodyRoleCannotEscalate()
    {
        using var factory = Factory();
        using var client = factory.CreateClient();
        using var response = await Evaluate(client, Token());
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("RoleDenied", body);
        Assert.DoesNotContain("Admin", body);
    }

    [Fact]
    public async Task EvaluationResponseDoesNotEchoArgumentsOrToken()
    {
        using var factory = Factory();
        using var client = factory.CreateClient();
        var token = Token(role: "Operator");
        using var response = await Evaluate(client, token,
            new { toolName = "crm.update_order", arguments = new { amount = 1001, secret = "SENSITIVE_MARKER" } });
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("AmountLimitExceeded", body);
        Assert.DoesNotContain("SENSITIVE_MARKER", body);
        Assert.DoesNotContain(token, body);
    }

    [Fact]
    public async Task ApplicationLogsDoNotContainArgumentsTokensOrSigningKey()
    {
        var logger = new CaptureLoggerProvider();
        using var factory = Factory(logger: logger);
        using var client = factory.CreateClient();
        var token = Token(role: "Operator");
        using var response = await Evaluate(client, token,
            new { toolName = "crm.update_order", arguments = new { amount = 1001, secret = "SENSITIVE_MARKER" } });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var logs = string.Join("\n", logger.Messages);
        Assert.DoesNotContain("SENSITIVE_MARKER", logs);
        Assert.DoesNotContain(token, logs);
        Assert.DoesNotContain(Key, logs);
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
    public async Task DemoTokensAreSignedShortLivedAndDevelopmentOnly()
    {
        using var development = Factory();
        using var client = development.CreateClient();
        using var tokenResponse = await client.PostAsJsonAsync("/api/demo/token", new { identity = "operator" });
        Assert.Equal(HttpStatusCode.OK, tokenResponse.StatusCode);
        using var document = JsonDocument.Parse(await tokenResponse.Content.ReadAsStringAsync());
        var token = document.RootElement.GetProperty("accessToken").GetString()!;
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
        Assert.True(jwt.ValidTo <= DateTime.UtcNow.AddMinutes(11));
        Assert.Equal(SecurityAlgorithms.HmacSha256, jwt.Header.Alg);
        using var evaluation = await Evaluate(client, token,
            new { toolName = "crm.update_order", arguments = new { amount = 5 } });
        Assert.Contains("Allowed", await evaluation.Content.ReadAsStringAsync());

        using var production = Factory("Production");
        using var productionClient = production.CreateClient();
        using var unavailable = await productionClient.PostAsJsonAsync("/api/demo/token", new { identity = "admin" });
        Assert.Equal(HttpStatusCode.NotFound, unavailable.StatusCode);
    }

    [Fact]
    public async Task UnknownDemoIdentityIsRejected()
    {
        using var factory = Factory();
        using var client = factory.CreateClient();
        using var response = await client.PostAsJsonAsync("/api/demo/token", new { identity = "root" });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }
}
