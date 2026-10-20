using System.IdentityModel.Tokens.Jwt;
using System.Diagnostics;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Nodes;
using AccessControlStudio.Core;
using AccessControlStudio.CrmDemo;
using ModelContextProtocol;
using ModelContextProtocol.AspNetCore;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;

namespace AccessControlStudio.Api;

/// <summary>Owns one internal CRM host and its SDK connection.</summary>
public sealed class GatewayRuntime : IAsyncDisposable
{
    public static readonly TimeSpan OperationTimeout = TimeSpan.FromSeconds(10);
    private static readonly HashSet<string> ExpectedNames = new(StringComparer.Ordinal)
    {
        "crm.get_customer", "crm.list_orders", "crm.update_order",
        "crm.delete_customer", "crm.export_customers"
    };

    private readonly CrmTools tools = new();
    private readonly AuthorizationPolicy policy;
    private WebApplication? crm;
    private HttpClientTransport? transport;
    private McpClient? upstream;
    private Tool[]? catalogTools;
    private HashSet<string>? catalog;

    private GatewayRuntime(AuthorizationPolicy policy) => this.policy = policy;

    // Register handlers before building the gateway. Initialize the upstream after Build,
    // but before the gateway listener starts. This keeps startup fail-closed.
    public static GatewayRuntime Register(WebApplicationBuilder builder, AuthorizationPolicy policy)
    {
        var runtime = new GatewayRuntime(policy);
        builder.Logging.AddFilter("ModelContextProtocol", LogLevel.None);
        builder.Logging.AddFilter("Microsoft.AspNetCore.Hosting.Diagnostics", LogLevel.None);
        builder.Services.AddHttpContextAccessor();
        builder.Services.AddSingleton(runtime.tools);
        builder.Services.AddMcpServer()
            .WithHttpTransport(options => options.SessionMode = HttpServerSessionMode.Stateless)
            .WithListToolsHandler((_, token) =>
            {
                token.ThrowIfCancellationRequested();
                return ValueTask.FromResult(new ListToolsResult
                {
                    Tools = runtime.catalogTools?.ToList() ?? []
                });
            })
            .WithCallToolHandler((request, token) => runtime.CallAsync(
                request.Params, request.Services, request.Server.NegotiatedProtocolVersion, token));
        return runtime;
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        var crmBuilder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Development" });
        crm = CrmDemoHost.Build(crmBuilder, tools);
        try
        {
            using var startup = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            startup.CancelAfter(OperationTimeout);
            await crm.StartAsync(startup.Token);
            var endpoint = new Uri(AssertLoopbackEndpoint(crm));
            var http = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false, UseProxy = false })
            {
                Timeout = OperationTimeout
            };
            transport = new HttpClientTransport(new HttpClientTransportOptions
            {
                Endpoint = endpoint,
                TransportMode = HttpTransportMode.StreamableHttp,
                ConnectionTimeout = OperationTimeout
            }, http, ownsHttpClient: true);
            upstream = await McpClient.CreateAsync(transport, new McpClientOptions
            {
                InitializationTimeout = OperationTimeout
            }, cancellationToken: startup.Token);
            catalogTools = (await upstream.ListToolsAsync(cancellationToken: startup.Token))
                .Select(tool => tool.ProtocolTool).ToArray();
            var discovered = new HashSet<string>(StringComparer.Ordinal);
            foreach (var tool in catalogTools)
                if (string.IsNullOrWhiteSpace(tool.Name) || !discovered.Add(tool.Name))
                    throw new InvalidOperationException("CRM upstream advertised invalid or duplicate tool names.");
            if (!discovered.SetEquals(ExpectedNames))
                throw new InvalidOperationException("CRM upstream catalog does not match the required tool set.");
            catalog = discovered;
        }
        catch
        {
            await DisposeAsync();
            throw;
        }
    }

    private async ValueTask<CallToolResult> CallAsync(CallToolRequestParams? parameters,
        IServiceProvider? services, string? protocolVersion, CancellationToken token)
    {
        var principal = services?.GetService<IHttpContextAccessor>()?.HttpContext?.User;
        if (principal?.Identity?.IsAuthenticated != true ||
            principal.FindAll(JwtRegisteredClaimNames.Sub).Count() != 1 ||
            principal.FindAll("role").Count() != 1 ||
            !Enum.TryParse<StudioRole>(principal.FindFirstValue("role"), false, out var role) ||
            !Enum.IsDefined(role))
            return Denied("InvalidIdentity");

        var subject = principal.FindFirstValue(JwtRegisteredClaimNames.Sub)!;
        var audit = services!.GetRequiredService<AuditRecorder>();
        var name = parameters?.Name ?? string.Empty;
        var auditName = catalog?.Contains(name) == true ? name : "UnknownTool";
        var correlation = Guid.NewGuid().ToString("N");
        var started = Stopwatch.StartNew();
        var reason = "InvalidArguments";
        var decisionName = "Deny";
        var enforcement = "Blocked";
        var upstreamStatus = "NotAttempted";
        string? errorCategory = null;
        var allowed = false;
        try
        {
            if (parameters is null || catalog?.Contains(name) != true || upstream is null)
                reason = "UnknownTool";
            else
            {
                try
                {
                    var arguments = JsonSerializer.SerializeToElement(parameters.Arguments);
                    var decision = policy.Evaluate(new AuthorizationContext(subject, role, name, arguments));
                    reason = decision.Code.ToString();
                    allowed = decision.Allowed;
                }
                catch (Exception) { reason = "InvalidArguments"; }
            }

            decisionName = allowed ? "Allow" : "Deny";
            await audit.RecordAsync(new(0, correlation, "Decision", DateTimeOffset.UtcNow,
                subject, role.ToString(), auditName, decisionName, reason, "Pending", "NotAttempted", null, 0));
            token.ThrowIfCancellationRequested();
            if (!allowed)
                return WithExecutionMeta(Denied(reason), correlation, decisionName, reason,
                    "Blocked", "NotAttempted");

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(OperationTimeout);
            enforcement = "Forwarded";
            // The application does not retry; SDK continuation may repeat an allowed operation.
            var result = await upstream!.CallToolAsync(new CallToolRequestParams
            {
                Name = name,
                Arguments = parameters!.Arguments
            }, timeout.Token);
            upstreamStatus = result.IsError == true ? "ToolError" : "Succeeded";
            if (result.IsError == true) errorCategory = "ToolError";
            return WithExecutionMeta(AdaptResult(result, protocolVersion), correlation,
                decisionName, reason, enforcement, upstreamStatus);
        }
        catch (OperationCanceledException)
        {
            upstreamStatus = enforcement == "Forwarded" ? "Unknown" : "NotAttempted";
            errorCategory = token.IsCancellationRequested ? "Canceled" : "Timeout";
            throw;
        }
        catch (Exception)
        {
            if (enforcement == "Forwarded" && upstreamStatus == "NotAttempted") upstreamStatus = "Unknown";
            errorCategory = "GatewayError";
            throw;
        }
        finally
        {
            started.Stop();
            await audit.RecordAsync(new(0, correlation, "Terminal", DateTimeOffset.UtcNow,
                subject, role.ToString(), auditName, decisionName, reason, enforcement, upstreamStatus,
                errorCategory, started.ElapsedMilliseconds));
        }
    }

    private static string AssertLoopbackEndpoint(WebApplication app)
    {
        // app.Urls may retain port 0 on Linux; Kestrel's bound-address feature has the actual port.
        var addresses = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()?.Addresses;
        if (addresses?.Count != 1 ||
            !Uri.TryCreate(addresses.Single(), UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttp || uri.Port == 0 || !uri.IsLoopback || uri.UserInfo.Length != 0 ||
            uri.Query.Length != 0 || uri.Fragment.Length != 0)
            throw new InvalidOperationException("CRM upstream must use one loopback HTTP listener.");
        return uri.AbsoluteUri.TrimEnd('/') + "/mcp";
    }

    private static CallToolResult AdaptResult(CallToolResult result, string? version)
    {
        if (result.ResultType is not null && result.ResultType != "complete")
            throw new McpException("Unsupported upstream result type.");
        var adapted = new CallToolResult
        {
            Content = result.Content.ToList(),
            StructuredContent = result.StructuredContent?.Clone(),
            IsError = result.IsError,
            Meta = result.Meta?.DeepClone().AsObject()
        };
        if (version is "2024-11-05" or "2025-03-26" && adapted.StructuredContent is { } structured)
        {
            adapted.Content.Add(new TextContentBlock { Text = structured.GetRawText() });
            adapted.StructuredContent = null;
        }
        return adapted;
    }

    private static CallToolResult Denied(string code) => new()
    {
        IsError = true,
        Content = [new TextContentBlock { Text = $"Tool execution denied: {code}." }]
    };

    private static CallToolResult WithExecutionMeta(CallToolResult result, string correlation,
        string decision, string reason, string enforcement, string upstreamStatus)
    {
        result.Meta ??= new JsonObject();
        result.Meta["accessControlStudio"] = new JsonObject
        {
            ["correlationId"] = correlation,
            ["decision"] = decision,
            ["reasonCode"] = reason,
            ["enforcement"] = enforcement,
            ["upstreamStatus"] = upstreamStatus
        };
        return result;
    }

    public async ValueTask DisposeAsync()
    {
        if (upstream is not null) await upstream.DisposeAsync();
        if (transport is not null) await transport.DisposeAsync();
        if (crm is not null)
        {
            await crm.StopAsync();
            await crm.DisposeAsync();
        }
    }
}
