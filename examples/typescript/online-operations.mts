import { OrbitBackendClient, type UsageConsumption, type UpdateTarget } from "../../sdk/typescript/index.mjs";

/** Load this job from your own database after authenticating and authorizing the user. */
export interface AuthorizedExportJob {
  readonly id: string;
  readonly licenceId: string;
  readonly activationId: string;
  readonly orbitCustomerId: string;
}

export async function exportReport(orbit: OrbitBackendClient, job: AuthorizedExportJob, customerSession: string,
  recordAndWriteReportOnce: (jobId: string, consumption: UsageConsumption) => Promise<void>): Promise<UsageConsumption> {
  const decision = await orbit.requireFeature({ customerSession, licenceId: job.licenceId,
    activationId: job.activationId, entitlement: "export" });
  if (decision.customer_id !== job.orbitCustomerId) throw new Error("Customer does not own this job");
  const consumption = await orbit.consume(job.licenceId, "exports", 1, { idempotencyKey: job.id });
  // Store the result with this durable job and make report creation idempotent.
  // Orbit's counter transaction is separate from the seller's job database.
  await recordAndWriteReportOnce(job.id, consumption);
  return consumption;
}

export async function discoverUpdate(orbit: OrbitBackendClient, authorizedLicenceId: string,
  installedNumber: number, clientTarget: UpdateTarget) {
  // authorizedLicenceId comes from your own authenticated account/ownership check.
  const update = await orbit.checkForUpdate(authorizedLicenceId, installedNumber, { target: clientTarget });
  if (!update) return null;
  return orbit.authorizeDownload(authorizedLicenceId, update.release.id, update.artifact.id);
}

export async function trackProject(orbit: OrbitBackendClient, authorizedLicenceId: string, projectId: string, jobId: string) {
  return orbit.acquireResource(authorizedLicenceId, "projects", projectId, 1, { idempotencyKey: jobId });
}

export async function forgetRemovedProject(orbit: OrbitBackendClient, authorizedLicenceId: string, allocationId: string, jobId: string) {
  // Release the stored allocation ID only when the actual project is removed.
  return orbit.releaseResource(authorizedLicenceId, "projects", allocationId, { idempotencyKey: jobId });
}
