export interface OrbitBackendConfig {
  /** HTTPS origin only, for example https://orbit.example.com. */
  apiOrigin: string;
  applicationId: string;
  environmentId: string;
  /** Scoped management Bearer token. Keep it on your backend. */
  managementToken: string;
}

export interface OrbitBackendOptions {
  /** Primarily useful for focused tests; defaults to globalThis.fetch. */
  fetchImpl?: typeof fetch;
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
  idempotencyKey: string;
}

export interface ReplaceLicenceKeyInput {
  reason: string;
  idempotencyKey: string;
}

export type OrbitLicence = Record<string, unknown> & { id: string };

export interface LicencePage {
  items: OrbitLicence[];
  next_cursor: string | null;
}

export interface IssuedLicences {
  licences: OrbitLicence[];
  keys: Array<{ licence_id: string; key: string }>;
  secret_replay_expired: boolean;
}

export class OrbitApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId: string | null;
}

export class OrbitTransportError extends Error {
  readonly status: null;
  readonly code: string;
  readonly requestId: null;
}

export class OrbitBackendClient {
  constructor(config: OrbitBackendConfig, options?: OrbitBackendOptions);

  verifyCurrentCustomerSession(customerSession: string): Promise<CurrentCustomerSession>;

  decideFeature(input: {
    customerSession: string;
    licenceId: string;
    activationId: string;
    entitlement: string;
  }): Promise<LicenceDecision>;

  searchLicences(input?: LicenceSearchInput): Promise<LicencePage>;
  issueLicences(input: IssueLicencesInput): Promise<IssuedLicences>;
  getLicence(id: string): Promise<OrbitLicence>;
  replaceLicenceKey(id: string, input: ReplaceLicenceKeyInput): Promise<IssuedLicences>;
  revokeLicence(id: string, reason: string): Promise<OrbitLicence>;
}
