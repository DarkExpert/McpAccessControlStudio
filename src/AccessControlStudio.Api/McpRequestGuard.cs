using System.Text.Json;

namespace AccessControlStudio.Api;

/// <summary>Reject ambiguous JSON before the SDK turns argument objects into dictionaries.</summary>
public static class McpRequestGuard
{
    private const int MaximumRequestBytes = 1024 * 1024;

    public static async Task CheckAsync(HttpContext context, RequestDelegate next)
    {
        if (!HttpMethods.IsPost(context.Request.Method) || !context.Request.Path.StartsWithSegments("/mcp"))
        {
            await next(context);
            return;
        }

        try
        {
            context.Request.EnableBuffering(bufferLimit: MaximumRequestBytes);
            using var document = await JsonDocument.ParseAsync(context.Request.Body, cancellationToken: context.RequestAborted);
            if (HasDuplicateProperties(document.RootElement))
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                return;
            }
            context.Request.Body.Position = 0;
        }
        catch (JsonException)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }
        catch (IOException)
        {
            context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
            return;
        }

        await next(context);
    }

    private static bool HasDuplicateProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
                if (!names.Add(property.Name) || HasDuplicateProperties(property.Value))
                    return true;
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
                if (HasDuplicateProperties(item))
                    return true;
        }
        return false;
    }
}
