#if ORBIT_LOCAL_DEVELOPMENT
using System.Text.Json.Nodes;
using Orbit.Sdk;

internal static partial class InstalledTests
{
    private static async Task OnlineOperations()
    {
        await using var fixture = new Fixture();
        await using var client = await fixture.Open();
        await fixture.Activate(client);
        var mode = 0;
        var calls = 0;
        string? operation = null;
        fixture.OnlineResponse = request =>
        {
            if (!request.Path.Contains("/usage/") && !request.Path.Contains("/resources/")) return null;
            var body = JsonNode.Parse(request.Body)!.AsObject();
            Require(body["credential"] != null && body["installation_id"] != null && body["application_id"]!.GetValue<string>() == "app");
            if (request.Path.Contains("/consume"))
            {
                calls++;
                var id = body["idempotency_key"]!.GetValue<string>();
                operation ??= id;
                Require(id == operation, "transport retries must retain their generated operation ID");
                if (mode == 0 && calls == 1) return new(503, "{}");
                var counter = JsonNode.Parse("{\"name\":\"exports\",\"period\":\"lifetime\",\"limit\":5,\"used\":2,\"remaining\":3,\"period_started_at\":null,\"resets_at\":null}")!.AsObject();
                if (mode is 1 or 2 or 3 or 6)
                {
                    if (mode != 6) { counter["used"] = 4; counter["remaining"] = 1; }
                    if (mode == 2) counter["remaining"] = 5;
                    return new(409, new JsonObject { ["error"] = new JsonObject {
                        ["code"] = "usage_limit_reached", ["message"] = "Limit", ["request_id"] = "fixture",
                        ["counter"] = counter, ["idempotency_key"] = mode == 3 ? "different_operation" : id,
                        ["requested_units"] = 2 } }.ToJsonString());
                }
                counter["idempotency_key"] = id;
                counter["consumed_units"] = 2;
                if (mode == 4) counter["used"] = 9007199254740992L;
                if (mode == 5) { counter["used"] = 0; counter["remaining"] = 5; }
                return new(200, counter.ToJsonString());
            }
            var value = JsonNode.Parse("{\"name\":\"projects\",\"limit\":5,\"used\":1,\"remaining\":4,\"allocation_id\":\"allocation_one\",\"resource_id\":\"project_one\",\"units\":1,\"state\":\"released\"}")!.AsObject();
            value["idempotency_key"] = body["idempotency_key"]!.GetValue<string>();
            if (mode == 7) { value["state"] = "active"; value["used"] = 0; value["remaining"] = 5; }
            return new(200, value.ToJsonString());
        };
        var consumed = await client.ConsumeAsync("exports", 2);
        Require(calls == 2 && consumed.Counter.Used == 2 && consumed.ConsumedUnits == 2 && consumed.IdempotencyKey == operation);
        for (mode = 1; mode <= 6; mode++)
        {
            try { await client.ConsumeAsync("exports", 2, operation); throw new InvalidOperationException("invalid consume accepted"); }
            catch (OrbitException e)
            {
                Require(e.OperationId == operation, "uncertain outcomes retain the original operation ID");
                Require(e.Error == (mode == 1 ? OrbitError.Denied : OrbitError.InvalidResponse));
                Require(mode == 1 ? e.UsageCounter is { Name: "exports", Remaining: 1 } && e.RequestedUnits == 2 : e.UsageCounter == null && e.RequestedUnits == null);
            }
        }
        mode = 0;
        var allocation = await client.AcquireResourceAsync("projects", "project_one", idempotencyKey: "project_create_job_01");
        Require(allocation.State == AllocationState.Released && allocation.Counter.Used == 1,
            "old acquire replay must retain the released state and current counter");
        var released = await client.ReleaseResourceAsync("projects", allocation.AllocationId);
        Require(released.State == AllocationState.Released && released.AllocationId == allocation.AllocationId);
        mode = 7;
        await Expect(OrbitError.InvalidResponse, () => client.AcquireResourceAsync("projects", "project_one"));
        await Expect(OrbitError.Configuration, () => client.ConsumeAsync("exports", 0));
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        try { await client.ConsumeAsync("exports", cancellationToken: cancelled.Token); }
        catch (OrbitException e) { Require(e.Error == OrbitError.Cancelled && e.OperationId != null); }
        var requests = fixture.Server.RequestCount;
        await client.RequireAccessAsync("export");
        Require(requests == fixture.Server.RequestCount, "feature checks must not meter or perform another online operation");
    }

    private static async Task UpdateOperations()
    {
        await using var fixture = new Fixture();
        await using var client = await fixture.Open();
        await fixture.Activate(client);
        var mode = 0;
        var artifact = JsonNode.Parse("{\"id\":\"artifact\",\"release_id\":\"release\",\"platform\":\"linux\",\"architecture\":\"x64\",\"filename\":\"app.bin\",\"byte_length\":3,\"sha256\":\"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\",\"delivery_mode\":\"public\",\"url\":\"https://downloads.example.test/app.bin\",\"required_feature\":null}")!.AsObject();
        fixture.OnlineResponse = request =>
        {
            if (request.Path.EndsWith("/updates"))
            {
                var body = JsonNode.Parse(request.Body)!;
                Require(body["channel"]!.GetValue<string>() == "stable");
                if (mode == 1) return new(200, "{\"release\":null,\"artifact\":null}");
                var artifacts = new JsonArray(artifact.DeepClone());
                if (mode == 2) artifacts.Add(artifact.DeepClone());
                if (mode == 3) artifact["architecture"] = "arm64";
                return new(200, new JsonObject { ["artifact"] = artifact.DeepClone(), ["release"] = new JsonObject {
                    ["id"] = "release", ["channel"] = "stable", ["version"] = "1.2", ["notes"] = "Changes",
                    ["release_number"] = 2, ["state"] = "published", ["created_at"] = "2026-09-27T00:00:00.123456Z",
                    ["published_at"] = "2026-09-27T00:00:00Z", ["artifacts"] = artifacts } }.ToJsonString());
            }
            if (request.Path.EndsWith("/downloads/authorize")) return new(200,
                new JsonObject { ["artifact"] = artifact.DeepClone(), ["ticket"] = null, ["expires_at"] = null }.ToJsonString());
            return null;
        };
        var update = await client.CheckForUpdateAsync(1, target: new("linux", "x64"));
        Require(update is { Release.ReleaseNumber: 2 } && update.Release.Artifacts.Count == 1);
        var auth = await client.AuthorizeDownloadAsync("release", "artifact");
        Require(auth.Ticket == null && !auth.ToString().Contains("https:"));
        mode = 1;
        Require(await client.CheckForUpdateAsync(1) == null);
        mode = 2;
        await Expect(OrbitError.InvalidResponse, () => client.CheckForUpdateAsync(1, target: new("linux", "x64")));
        mode = 3;
        await Expect(OrbitError.InvalidResponse, () => client.CheckForUpdateAsync(1, target: new("linux", "x64")));
    }
}
#endif
