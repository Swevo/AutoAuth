using System.Text.Json;

namespace AutoAuth.Features;

internal static class AutoAuthAuditRedactor
{
    public static string RedactToJson(object payload, HashSet<string> redactedFields)
    {
        var element = JsonSerializer.SerializeToElement(payload);
        var sanitized = RedactElement(element, redactedFields);
        return JsonSerializer.Serialize(sanitized);
    }

    private static object? RedactElement(JsonElement element, HashSet<string> redactedFields)
    {
        return element.ValueKind switch
        {
            JsonValueKind.Object => RedactObject(element, redactedFields),
            JsonValueKind.Array => element.EnumerateArray().Select(item => RedactElement(item, redactedFields)).ToList(),
            JsonValueKind.String => element.GetString(),
            JsonValueKind.Number => element.TryGetInt64(out var l) ? l :
                element.TryGetDouble(out var d) ? d : element.GetRawText(),
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.Null => null,
            _ => element.GetRawText()
        };
    }

    private static Dictionary<string, object?> RedactObject(JsonElement element, HashSet<string> redactedFields)
    {
        var result = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        foreach (var property in element.EnumerateObject())
        {
            if (redactedFields.Contains(property.Name))
            {
                result[property.Name] = "***REDACTED***";
            }
            else
            {
                result[property.Name] = RedactElement(property.Value, redactedFields);
            }
        }

        return result;
    }
}
