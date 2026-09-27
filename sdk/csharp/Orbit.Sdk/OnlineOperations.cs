using System.Text.Json;

namespace Orbit.Sdk;

public sealed record UsageLimit(long Limit, UsagePeriod Period, string? RequiredFeature);
public sealed record ResourceLimit(long Limit, string? RequiredFeature);
public enum UsagePeriod { Day, Month, Lifetime }
public sealed record UsageCounter(string Name, UsagePeriod Period, long Limit, long Used, long Remaining,
    DateTimeOffset? PeriodStartedAt, DateTimeOffset? ResetsAt);
public sealed record UsageConsumption(UsageCounter Counter, string IdempotencyKey, long ConsumedUnits);
public sealed record ResourceCounter(string Name, long Limit, long Used, long Remaining);
public enum AllocationState { Active, Released }
public sealed record ResourceAllocation(ResourceCounter Counter, string AllocationId, string ResourceId,
    long Units, AllocationState State, string IdempotencyKey);

public sealed partial class OrbitClient
{
    public Task<UsageCounter> UsageAsync(string name, CancellationToken cancellationToken = default)
    {
        OnlineWire.Name(name);
        return OnlineAsync($"usage/{name}", [], v => OnlineWire.Usage(v, name), cancellationToken);
    }

    public Task<UsageConsumption> ConsumeAsync(string name, long units = 1, string? idempotencyKey = null,
        CancellationToken cancellationToken = default)
    {
        OnlineWire.Name(name);
        OnlineWire.Units(units);
        var operation = OnlineWire.Operation(idempotencyKey);
        return MeterAsync($"usage/{name}/consume", name, operation, units, false,
            new() { ["units"] = units, ["idempotency_key"] = operation }, v =>
            {
                var counter = OnlineWire.Usage(v, name);
                if (JsonWire.String(v, "idempotency_key") != operation ||
                    OnlineWire.Number(v, "consumed_units", 1) != units || counter.Used < units) throw JsonWire.Invalid();
                return new UsageConsumption(counter, operation, units);
            }, cancellationToken);
    }

    public Task<ResourceCounter> ResourcesAsync(string name, CancellationToken cancellationToken = default)
    {
        OnlineWire.Name(name);
        return OnlineAsync($"resources/{name}", [], v => OnlineWire.Resource(v, name), cancellationToken);
    }

    public Task<ResourceAllocation> AcquireResourceAsync(string name, string resourceId, long units = 1,
        string? idempotencyKey = null, CancellationToken cancellationToken = default)
    {
        OnlineWire.Name(name);
        OnlineWire.Units(units);
        if (!JsonWire.Opaque(resourceId)) throw new OrbitException(OrbitError.Configuration);
        var operation = OnlineWire.Operation(idempotencyKey);
        return MeterAsync($"resources/{name}/acquire", name, operation, units, true,
            new() { ["resource_id"] = resourceId, ["units"] = units, ["idempotency_key"] = operation }, v =>
            {
                var result = OnlineWire.Allocation(v, name, operation);
                if (result.ResourceId != resourceId || result.Units != units) throw JsonWire.Invalid();
                return result;
            }, cancellationToken);
    }

    public Task<ResourceAllocation> ReleaseResourceAsync(string name, string allocationId,
        string? idempotencyKey = null, CancellationToken cancellationToken = default)
    {
        OnlineWire.Name(name);
        if (!JsonWire.Opaque(allocationId)) throw new OrbitException(OrbitError.Configuration);
        var operation = OnlineWire.Operation(idempotencyKey);
        return MeterAsync($"resources/{name}/allocations/{allocationId}/release", name, operation, 0, true,
            new() { ["idempotency_key"] = operation }, v =>
            {
                var result = OnlineWire.Allocation(v, name, operation);
                if (result.AllocationId != allocationId || result.State != AllocationState.Released) throw JsonWire.Invalid();
                return result;
            }, cancellationToken);
    }

    private async Task<T> MeterAsync<T>(string route, string name, string operation, long units, bool resource,
        Dictionary<string, object?> extra, Func<JsonElement, T> parse, CancellationToken cancellationToken)
    {
        try { return await OnlineAsync(route, extra, parse, cancellationToken).ConfigureAwait(false); }
        catch (OrbitException error)
        {
            error.OperationId = operation;
            if (error.Code is "usage_limit_reached" or "resource_limit_reached")
            {
                try
                {
                    if (units == 0 || error.HttpStatus != 409 ||
                        error.Code != (resource ? "resource_limit_reached" : "usage_limit_reached") ||
                        error.WireError is not { } detail || JsonWire.String(detail, "idempotency_key") != operation ||
                        OnlineWire.Number(detail, "requested_units", 1) != units) throw JsonWire.Invalid();
                    if (resource) error.ResourceCounter = OnlineWire.Resource(JsonWire.Field(detail, "counter"), name);
                    else error.UsageCounter = OnlineWire.Usage(JsonWire.Field(detail, "counter"), name);
                    if (units <= (error.ResourceCounter?.Remaining ?? error.UsageCounter!.Remaining)) throw JsonWire.Invalid();
                    error.RequestedUnits = units;
                }
                catch (OrbitException) { throw new OrbitException(OrbitError.InvalidResponse) { OperationId = operation }; }
            }
            throw;
        }
    }

    private async Task<T> OnlineAsync<T>(string route, Dictionary<string, object?> extra,
        Func<JsonElement, T> parse, CancellationToken cancellationToken)
    {
        using var owned = InstallationOperation(cancellationToken);
        cancellationToken = owned?.Token ?? cancellationToken;
        StoredCredential saved;
        long expected;
        lock (gate)
        {
            SyncStorage();
            OrbitException.CheckCancellation(cancellationToken);
            if (offlineFileMode) throw new OrbitException(OrbitError.Denied, "online_activation_required");
            saved = credential ?? throw new OrbitException(OrbitError.ReauthenticationRequired);
            expected = generation;
        }
        var body = CredentialBody(saved);
        foreach (var field in extra) body.Add(field.Key, field.Value);
        try
        {
            var response = await transport.PostAsync($"/api/client/v1/activations/{saved.ActivationId}/{route}",
                body, true, cancellationToken, expectedStatus: 200).ConfigureAwait(false) ?? throw JsonWire.Invalid();
            var result = parse(response);
            lock (gate)
            {
                CheckGeneration(expected);
                OrbitException.CheckCancellation(cancellationToken);
            }
            return result;
        }
        catch (OrbitException)
        {
            lock (gate)
            {
                CheckGeneration(expected);
                OrbitException.CheckCancellation(cancellationToken);
            }
            throw;
        }
    }
}

internal static class OnlineWire
{
    internal const long Maximum = 9007199254740991;
    internal static void Name(string name)
    { if (!JsonWire.Feature(name)) throw new OrbitException(OrbitError.Configuration); }
    internal static void Units(long units)
    { if (units is < 1 or > Maximum) throw new OrbitException(OrbitError.Configuration); }
    internal static string Operation(string? value)
    {
        if (value != null && !JsonWire.OperationId(value)) throw new OrbitException(OrbitError.Configuration);
        return value ?? Device.NewInstallation().InstallationId;
    }
    internal static long Number(JsonElement value, string key, long minimum = 0)
    {
        var result = JsonWire.Integer(value, key);
        if (result < minimum || result > Maximum) throw JsonWire.Invalid();
        return result;
    }
    internal static DateTimeOffset? Time(JsonElement value, string key)
    {
        var field = JsonWire.Field(value, key);
        if (field.ValueKind == JsonValueKind.Null) return null;
        var time = JsonWire.Text(field);
        if (!System.Text.RegularExpressions.Regex.IsMatch(time,
            @"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$",
            System.Text.RegularExpressions.RegexOptions.CultureInvariant)) throw JsonWire.Invalid();
        // .NET stores 100 ns ticks. Truncate finer server precision rather than extending an expiry.
        if (time.Length > 28) time = time[..27] + "Z";
        if (!DateTimeOffset.TryParse(time, System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.None, out var result)) throw JsonWire.Invalid();
        return result;
    }
    internal static IReadOnlyDictionary<string, T> Definitions<T>(JsonElement value, string field, Func<JsonElement, T> parse)
    {
        var result = new Dictionary<string, T>(StringComparer.Ordinal);
        var entries = JsonWire.Field(value, field);
        if (entries.ValueKind != JsonValueKind.Object) throw JsonWire.Invalid();
        foreach (var property in entries.EnumerateObject())
        {
            if (result.Count == 32 || !JsonWire.Feature(property.Name)) throw JsonWire.Invalid();
            result.Add(property.Name, parse(property.Value));
        }
        return new System.Collections.ObjectModel.ReadOnlyDictionary<string, T>(result);
    }
    internal static string? RequiredFeature(JsonElement value)
    {
        var feature = JsonWire.Field(value, "required_feature");
        if (feature.ValueKind == JsonValueKind.Null) return null;
        var text = JsonWire.Text(feature);
        if (!JsonWire.Feature(text)) throw JsonWire.Invalid();
        return text;
    }
    internal static UsageLimit UsageDefinition(JsonElement value)
    {
        JsonWire.ExactFields(value, "limit", "period", "required_feature");
        var period = JsonWire.String(value, "period") switch
        { "day" => UsagePeriod.Day, "month" => UsagePeriod.Month, "lifetime" => UsagePeriod.Lifetime, _ => throw JsonWire.Invalid() };
        return new(Number(value, "limit"), period, RequiredFeature(value));
    }
    internal static ResourceLimit ResourceDefinition(JsonElement value)
    {
        JsonWire.ExactFields(value, "limit", "required_feature");
        return new(Number(value, "limit"), RequiredFeature(value));
    }
    internal static ResourceCounter Resource(JsonElement value, string name)
    {
        if (JsonWire.String(value, "name") != name) throw JsonWire.Invalid();
        var limit = Number(value, "limit");
        var used = Number(value, "used");
        var remaining = Number(value, "remaining");
        if (used > limit || remaining != limit - used) throw JsonWire.Invalid();
        return new(name, limit, used, remaining);
    }
    internal static UsageCounter Usage(JsonElement value, string name)
    {
        var counter = Resource(value, name);
        var period = JsonWire.String(value, "period") switch
        {
            "day" => UsagePeriod.Day,
            "month" => UsagePeriod.Month,
            "lifetime" => UsagePeriod.Lifetime,
            _ => throw JsonWire.Invalid()
        };
        var start = Time(value, "period_started_at");
        var reset = Time(value, "resets_at");
        if (period == UsagePeriod.Lifetime ? start != null || reset != null :
            start == null || reset == null || start >= reset) throw JsonWire.Invalid();
        return new(name, period, counter.Limit, counter.Used, counter.Remaining, start, reset);
    }
    internal static ResourceAllocation Allocation(JsonElement value, string name, string operation)
    {
        var counter = Resource(value, name);
        var allocation = JsonWire.String(value, "allocation_id");
        var resource = JsonWire.String(value, "resource_id");
        if (!JsonWire.Opaque(allocation) || !JsonWire.Opaque(resource) ||
            JsonWire.String(value, "idempotency_key") != operation) throw JsonWire.Invalid();
        var state = JsonWire.String(value, "state") switch
        {
            "active" => AllocationState.Active,
            "released" => AllocationState.Released,
            _ => throw JsonWire.Invalid()
        };
        var units = Number(value, "units", 1);
        if (state == AllocationState.Active && units > counter.Used) throw JsonWire.Invalid();
        return new(counter, allocation, resource, units, state, operation);
    }
}
