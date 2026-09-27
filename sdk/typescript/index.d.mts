import type * as Online from "./online.mjs";
export type * from "./online.mjs";
export type AppKeyEnvironment = "test" | "live";

/**
 * A parsed Orbit app key: the single pasted value from Orbit's Integration
 * page that names the API origin, application and environment.
 */
export class AppKey {
  private constructor();

  /** The public API origin the key names, for example https://orbit.example.com. */
  readonly api_origin: string;
  /** The expected grant issuer; always equal to api_origin. */
  readonly issuer: string;
  readonly application_id: string;
  readonly environment_id: string;
  /** "test" or "live". */
  readonly environment: AppKeyEnvironment;

  /** Parse and validate an app key string. Throws TypeError on any invalid input. */
  static parse(key: string): AppKey;
}

export interface OrbitBackendConfig {
  /** The app key from Orbit's Integration page, or an already-parsed AppKey. */
  appKey: string | AppKey;
  /** Scoped management Bearer token. Keep it on your backend. */
  managementToken: string;
}

export interface OrbitBackendOptions {
  /** Primarily useful for focused tests; defaults to globalThis.fetch. */
  fetchImpl?: typeof fetch;
}

export interface DownloadTicketVerifierConfig {
  appKey: string | AppKey;
  /** Exact protected HTTPS endpoint, without credentials, query or fragment. */
  endpoint: string;
  /** Raw connected-purpose public JWKS JSON; duplicate keys are rejected. */
  trustedKeys: string | Uint8Array;
}

export interface DownloadTicket {
  readonly licenceId: string;
  readonly ticketId: string;
  readonly applicationId: string;
  readonly environmentId: string;
  readonly releaseId: string;
  readonly artifactId: string;
  readonly sha256: string;
  readonly byteLength: number;
  /** RFC3339 UTC timestamps. */
  readonly issuedAt: string;
  readonly expiresAt: string;
}

export class OrbitDownloadTicketError extends Error {
  readonly code: "invalid_download_ticket";
}

export class DownloadTicketVerifier {
  constructor(config: DownloadTicketVerifierConfig);
  /** No network request. Match returned metadata against your artifact registry. */
  verify(ticket: string): DownloadTicket;
}

export interface CurrentCustomerSession {
  readonly customer_id: string;
  readonly application_id: string;
  readonly environment_id: string;
  readonly expires_at: string;
}

export type LicenceDecisionReason = "allowed" | "licence_unavailable" | "entitlement_denied";

export interface LicenceDecision {
  readonly allowed: boolean;
  readonly reason: LicenceDecisionReason;
  readonly checked_at: string;
  /** Customer identity verified online for this decision, never caller input. */
  readonly customer_id: string;
}

export interface DecideFeatureInput {
  customerSession: string;
  licenceId: string;
  activationId: string;
  entitlement: string;
}

export interface LicenceSearchInput {
  query?: string;
  after?: string | null;
  status?: "active" | "revoked" | "all";
}

export interface IssueLicencesInput {
  policyId: string;
  quantity: number;
  reference: string;
  note: string;
  /** Generated with crypto.randomUUID()-strength randomness when omitted. */
  idempotencyKey?: string;
}

export interface ReplaceLicenceKeyInput {
  reason: string;
  /** Generated with crypto.randomUUID()-strength randomness when omitted. */
  idempotencyKey?: string;
}

export type LicenceStatus = "enabled" | "suspended" | "revoked";
export type LicenceState = "unused" | "active" | "expired" | "suspended" | "revoked";
export type LicenceExpiryMode = "perpetual" | "fixed" | "first_activation" | "payment";

export interface OrbitLicence {
  readonly usage_limits: Readonly<Record<string, Online.UsageLimit>>;
  readonly resource_limits: Readonly<Record<string, Online.ResourceLimit>>;
  readonly id: string;
  readonly policy_id: string;
  readonly policy_name: string;
  readonly policy_version: number;
  readonly key_suffix: string;
  readonly status: LicenceStatus;
  readonly state: LicenceState;
  readonly expiry_mode: LicenceExpiryMode;
  readonly duration_seconds: number | null;
  readonly first_used_at: string | null;
  readonly expires_at: string | null;
  readonly device_limit: number;
  /** Concurrent sessions per licence; zero means sessions are not required. */
  readonly concurrent_session_limit: number;
  readonly hwid_locked: boolean;
  readonly offline_allowed: boolean;
  readonly offline_seconds: number;
  readonly offline_file_seconds: number;
  readonly entitlements: Readonly<Record<string, boolean>>;
  readonly reference: string;
  readonly note: string;
  readonly created_at: string;
  readonly reset_cooldown_until: string | null;
  readonly customer_id: string | null;
  readonly key_generation: number;
}

export interface LicencePage {
  readonly items: readonly OrbitLicence[];
  readonly next_cursor: string | null;
}

export interface IssuedLicences {
  readonly licences: readonly OrbitLicence[];
  readonly keys: readonly { readonly licence_id: string; readonly key: string }[];
  readonly secret_replay_expired: boolean;
  /** The idempotency key actually used for this request; keep it to retry deliberately. */
  readonly idempotencyKey: string;
}

export class OrbitApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId: string | null;
}
export class OrbitLimitReachedError extends OrbitApiError {
  readonly counter: Online.UsageCounter | Online.ResourceCounter;
  readonly idempotencyKey: string;
  readonly requestedUnits: number;
}

export class OrbitTransportError extends Error {
  readonly status: null;
  readonly code: string;
  readonly requestId: null;
}

/** A mutation may have completed despite a lost or unusable response. */
export class OrbitMutationUncertainError extends Error {
  readonly idempotencyKey: string;
  readonly code: string;
  readonly status: number | null;
  readonly requestId: string | null;
  readonly cause: unknown;
}

/** Thrown by requireFeature when Orbit denies the requested access. */
export class OrbitAccessDeniedError extends Error {
  readonly reason: LicenceDecisionReason;
}

export class OrbitBackendClient {
  checkForUpdate(licenceId: string, installedReleaseNumber: number, options?: Online.UpdateCheckOptions): Promise<Online.Update | null>;
  authorizeDownload(licenceId: string, releaseId: string, artifactId: string, options?: Online.OnlineOptions): Promise<Online.DownloadAuthorization>;
  usage(licenceId: string, name: string, options?: Online.OnlineOptions): Promise<Online.UsageCounter>;
  consume(licenceId: string, name: string, units?: number, options?: Online.MutationOptions): Promise<Online.UsageConsumption>;
  resources(licenceId: string, name: string, options?: Online.OnlineOptions): Promise<Online.ResourceCounter>;
  acquireResource(licenceId: string, name: string, resourceId: string, units?: number, options?: Online.MutationOptions): Promise<Online.ResourceAllocation>;
  releaseResource(licenceId: string, name: string, allocationId: string, options?: Online.MutationOptions): Promise<Online.ResourceAllocation>;
  listResourceAllocations(licenceId: string, name: string, options?: Online.AllocationListOptions): Promise<Online.AllocationPage>;
  listReleases(options?: Online.ReleaseListOptions): Promise<Online.ReleasePage>;
  getRelease(releaseId: string, options?: Online.OnlineOptions): Promise<Online.Release>;
  createRelease(input: Online.ReleaseInput, options?: Online.MutationOptions): Promise<Online.Release & Online.MutationReceipt>;
  updateRelease(releaseId: string, input: Online.ReleaseInput, options?: Online.MutationOptions): Promise<Online.Release & Online.MutationReceipt>;
  createArtifact(releaseId: string, input: Online.ArtifactInput, options?: Online.MutationOptions): Promise<Online.Artifact & Online.MutationReceipt>;
  updateArtifact(releaseId: string, artifactId: string, input: Online.ArtifactInput, options?: Online.MutationOptions): Promise<Online.Artifact & Online.MutationReceipt>;
  deleteArtifact(releaseId: string, artifactId: string, options?: Online.MutationOptions): Promise<Online.MutationReceipt>;
  publishRelease(releaseId: string, options?: Online.MutationOptions): Promise<Online.Release & Online.MutationReceipt>;
  unpublishRelease(releaseId: string, options?: Online.MutationOptions): Promise<Online.Release & Online.MutationReceipt>;
  constructor(config: OrbitBackendConfig, options?: OrbitBackendOptions);

  verifyCurrentCustomerSession(customerSession: string): Promise<CurrentCustomerSession>;

  decideFeature(input: DecideFeatureInput): Promise<LicenceDecision>;

  /**
   * Call decideFeature and throw OrbitAccessDeniedError when access is not
   * allowed, so callers do not need an if-check. Returns the allowed decision.
   */
  requireFeature(input: DecideFeatureInput): Promise<LicenceDecision>;

  searchLicences(input?: LicenceSearchInput): Promise<LicencePage>;
  issueLicences(input: IssueLicencesInput): Promise<IssuedLicences>;
  getLicence(id: string): Promise<OrbitLicence>;
  replaceLicenceKey(id: string, input: ReplaceLicenceKeyInput): Promise<IssuedLicences>;
  revokeLicence(id: string, reason: string): Promise<OrbitLicence>;
}
