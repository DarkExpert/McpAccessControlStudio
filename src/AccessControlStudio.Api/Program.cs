using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using AccessControlStudio.Core;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);
var issuer = builder.Configuration["Jwt:Issuer"] ?? "AccessControlStudio.Demo";
var audience = builder.Configuration["Jwt:Audience"] ?? "AccessControlStudio.Api";
if (!builder.Environment.IsDevelopment() && issuer == "AccessControlStudio.Demo")
    throw new InvalidOperationException("The demo issuer is restricted to Development; configure a distinct Jwt:Issuer.");
var signingSecret = builder.Configuration["Jwt:SigningKey"];
if (string.IsNullOrEmpty(signingSecret) || Encoding.UTF8.GetByteCount(signingSecret) < 32)
    throw new InvalidOperationException("Jwt:SigningKey must be supplied externally and contain at least 32 UTF-8 bytes.");
var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingSecret));

builder.Services.AddSingleton<AuthorizationPolicy>();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
{
    options.MapInboundClaims = false;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = key,
        ValidateIssuer = true,
        ValidIssuer = issuer,
        ValidateAudience = true,
        ValidAudience = audience,
        ValidateLifetime = true,
        RequireExpirationTime = true,
        RequireSignedTokens = true,
        ClockSkew = TimeSpan.Zero,
        ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
        NameClaimType = JwtRegisteredClaimNames.Sub,
        RoleClaimType = "role"
    };
    options.Events = new JwtBearerEvents
    {
        OnTokenValidated = context =>
        {
            var subjects = context.Principal?.FindAll(JwtRegisteredClaimNames.Sub).ToArray() ?? [];
            var roles = context.Principal?.FindAll("role").ToArray() ?? [];
            if (subjects.Length != 1 || string.IsNullOrWhiteSpace(subjects[0].Value) ||
                roles.Length != 1 || !Enum.TryParse<StudioRole>(roles[0].Value, false, out var role) ||
                !Enum.IsDefined(role))
                context.Fail("Required identity claims are invalid.");
            return Task.CompletedTask;
        }
    };
});
builder.Services.AddAuthorization();
var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

// This endpoint evaluates policy only. It never invokes an MCP tool.
app.MapPost("/api/authorization/evaluate", (EvaluationRequest request, ClaimsPrincipal user, AuthorizationPolicy policy) =>
{
    var subject = user.FindFirstValue(JwtRegisteredClaimNames.Sub)!;
    var role = Enum.Parse<StudioRole>(user.FindFirstValue("role")!, false);
    var decision = policy.Evaluate(new AuthorizationContext(subject, role, request.ToolName, request.Arguments));
    return Results.Ok(new EvaluationResponse(decision.Allowed, decision.Code.ToString()));
}).RequireAuthorization();

if (app.Environment.IsDevelopment())
{
    app.MapPost("/api/demo/token", (DemoTokenRequest request) =>
    {
        var identities = new Dictionary<string, StudioRole>(StringComparer.Ordinal)
        {
            ["viewer"] = StudioRole.Viewer,
            ["operator"] = StudioRole.Operator,
            ["admin"] = StudioRole.Admin
        };
        if (!identities.TryGetValue(request.Identity ?? "", out var role))
            return Results.BadRequest(new { code = "UnknownDemoIdentity" });
        var expires = DateTime.UtcNow.AddMinutes(10);
        var token = new JwtSecurityToken(issuer, audience,
            [new Claim(JwtRegisteredClaimNames.Sub, request.Identity!), new Claim("role", role.ToString())],
            notBefore: DateTime.UtcNow, expires: expires,
            signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256));
        return Results.Ok(new { accessToken = new JwtSecurityTokenHandler().WriteToken(token), expiresAtUtc = expires });
    });
}

app.Run();

public sealed record EvaluationRequest(string ToolName, JsonElement Arguments);
public sealed record EvaluationResponse(bool Allowed, string Code);
public sealed record DemoTokenRequest(string? Identity);
public partial class Program;
