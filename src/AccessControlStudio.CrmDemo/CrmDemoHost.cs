using ModelContextProtocol.AspNetCore;

namespace AccessControlStudio.CrmDemo;

/// <summary>Internal-only upstream. Never maps a management or counter endpoint.</summary>
public static class CrmDemoHost
{
    public static WebApplication Build(WebApplicationBuilder builder, CrmTools tools)
    {
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Logging.AddFilter("ModelContextProtocol", LogLevel.None);
        builder.Logging.AddFilter("Microsoft.AspNetCore.Hosting.Diagnostics", LogLevel.None);
        builder.Services.AddSingleton(tools);
        builder.Services.AddMcpServer()
            .WithHttpTransport(options => options.SessionMode = HttpServerSessionMode.Stateless)
            .WithTools(tools);
        var app = builder.Build();
        app.MapMcp("/mcp");
        return app;
    }
}
