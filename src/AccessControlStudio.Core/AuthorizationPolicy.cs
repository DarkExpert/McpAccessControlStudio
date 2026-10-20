using System.Collections.Frozen;
using System.Text.Json;

namespace AccessControlStudio.Core;

public enum StudioRole { Viewer, Operator, Admin }
public enum DecisionCode { Allowed, UnknownTool, RoleDenied, InvalidArguments, AmountLimitExceeded }
public sealed record AuthorizationContext(string Subject, StudioRole Role, string ToolName, JsonElement Arguments);
public sealed record AuthorizationDecision(bool Allowed, DecisionCode Code);

public sealed class AuthorizationPolicy
{
    private sealed record Rule(FrozenSet<StudioRole> Roles, decimal? MaximumAmount = null);
    private static readonly FrozenDictionary<string, Rule> Rules =
        new Dictionary<string, Rule>(StringComparer.Ordinal)
        {
            ["crm.get_customer"] = new(Enum.GetValues<StudioRole>().ToFrozenSet()),
            ["crm.list_orders"] = new(Enum.GetValues<StudioRole>().ToFrozenSet()),
            ["crm.update_order"] = new(new[] { StudioRole.Operator, StudioRole.Admin }.ToFrozenSet(), 1000m),
            ["crm.delete_customer"] = new(new[] { StudioRole.Admin }.ToFrozenSet()),
            ["crm.export_customers"] = new(new[] { StudioRole.Admin }.ToFrozenSet())
        }.ToFrozenDictionary(StringComparer.Ordinal);

    public AuthorizationDecision Evaluate(AuthorizationContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (string.IsNullOrWhiteSpace(context.Subject) || !Enum.IsDefined(context.Role))
            return new(false, DecisionCode.RoleDenied);
        if (context.ToolName is null || !Rules.TryGetValue(context.ToolName, out var rule))
            return new(false, DecisionCode.UnknownTool);
        if (!rule.Roles.Contains(context.Role))
            return new(false, DecisionCode.RoleDenied);
        if (rule.MaximumAmount is not { } limit)
            return new(true, DecisionCode.Allowed);
        if (context.Arguments.ValueKind != JsonValueKind.Object ||
            !context.Arguments.TryGetProperty("amount", out var amount) ||
            context.Arguments.EnumerateObject().Count(property => property.NameEquals("amount")) != 1 ||
            amount.ValueKind != JsonValueKind.Number ||
            !amount.TryGetDecimal(out var value) || value < 0)
            return new(false, DecisionCode.InvalidArguments);
        return value <= limit ? new(true, DecisionCode.Allowed) : new(false, DecisionCode.AmountLimitExceeded);
    }
}
