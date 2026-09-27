import { Client, type ResourceAllocation, type UsageConsumption } from "../../sdk/typescript-installed/index.mjs";

export async function exportReport(client: Client, durableJobId: string,
  writeReportOnce: (jobId: string) => Promise<void>): Promise<UsageConsumption> {
  await client.requireAccess("export");
  const consumption = await client.consume("exports", 1, { idempotencyKey: durableJobId });
  // Make this application operation idempotent too. Failures do not refund quota.
  await writeReportOnce(durableJobId);
  return consumption;
}

export async function downloadUpdate(client: Client, installedNumber: number, destination: string): Promise<string | null> {
  const update = await client.checkForUpdate(installedNumber);
  if (!update) return null;
  const authorization = await client.authorizeDownload(update.release.id, update.artifact.id);
  return client.download(authorization, destination, { maxBytes: 200_000_000 });
}

export async function trackProject(client: Client, projectId: string, durableJobId: string): Promise<ResourceAllocation> {
  // Save allocationId alongside the actual project, and keep it across restarts.
  return client.acquireResource("projects", projectId, 1, { idempotencyKey: durableJobId });
}

export async function forgetRemovedProject(client: Client, allocationId: string, durableJobId: string): Promise<ResourceAllocation> {
  // Call after removing the actual project; close/logout must not release it.
  return client.releaseResource("projects", allocationId, { idempotencyKey: durableJobId });
}
