using System.Collections.Concurrent;
using System.ComponentModel;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace AccessControlStudio.CrmDemo;

/// <summary>Seeded, non-sensitive CRM data. One instance belongs to one local server.</summary>
public sealed class CrmTools
{
    // In-process test hook; never exposed through MCP or HTTP.
    internal Func<CancellationToken, Task>? BeforeReadResult { get; set; }
    private readonly ConcurrentDictionary<string, int> counts = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, string> customers = new(
        [new KeyValuePair<string, string>("customer-1", "Ada Example"),
         new KeyValuePair<string, string>("customer-2", "Lin Example")], StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, decimal> orders = new(
        [new KeyValuePair<string, decimal>("order-1", 25m)], StringComparer.Ordinal);

    public int InvocationCount(string name) => counts.GetValueOrDefault(name);
    private void Count(string name) => counts.AddOrUpdate(name, 1, (_, value) => value + 1);

    [McpServerTool(Name = "crm.get_customer"), Description("Read a seeded demonstration customer.")]
    public async Task<CallToolResult> GetCustomer(string customerId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Count("crm.get_customer");
        if (BeforeReadResult is { } beforeReadResult)
            await beforeReadResult(cancellationToken);
        return customers.TryGetValue(customerId, out var name)
            ? Result($"{customerId}: {name}") : Result("Customer not found.", true);
    }

    [McpServerTool(Name = "crm.list_orders"), Description("List seeded demonstration orders.")]
    public CallToolResult ListOrders(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Count("crm.list_orders");
        return Result(string.Join("; ", orders.OrderBy(entry => entry.Key, StringComparer.Ordinal)
            .Select(entry => $"{entry.Key}: {entry.Value}")));
    }

    [McpServerTool(Name = "crm.update_order"), Description("Update a seeded demonstration order amount.")]
    public CallToolResult UpdateOrder(string orderId, decimal amount, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Count("crm.update_order");
        if (!orders.ContainsKey(orderId)) return Result("Order not found.", true);
        orders[orderId] = amount;
        return Result("Order updated.");
    }

    [McpServerTool(Name = "crm.delete_customer"), Description("Delete a seeded demonstration customer.")]
    public CallToolResult DeleteCustomer(string customerId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Count("crm.delete_customer");
        return customers.TryRemove(customerId, out _) ? Result("Customer deleted.") : Result("Customer not found.", true);
    }

    [McpServerTool(Name = "crm.export_customers"), Description("Export seeded demonstration customers.")]
    public CallToolResult ExportCustomers(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Count("crm.export_customers");
        var rows = customers.OrderBy(entry => entry.Key, StringComparer.Ordinal)
            .Select(entry => $"{entry.Key},{entry.Value}");
        return Result("id,name\n" + string.Join("\n", rows));
    }

    private static CallToolResult Result(string text, bool isError = false) => new()
    {
        IsError = isError,
        Content = [new TextContentBlock { Text = text }]
    };
}
