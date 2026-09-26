export type ErrorKindName =
  | "configuration" | "cancelled" | "denied" | "invalid_response"
  | "reauthentication_required" | "stale_response" | "storage"
  | "clock_uncertain" | "transient" | "transport_security" | "internal";

export declare const ErrorKind: Readonly<Record<string, ErrorKindName>>;
export declare class OrbitError extends Error {
  readonly kind: ErrorKindName;
  readonly code: string;
  readonly requestId?: string;
  readonly status: number;
}
export declare class NotActivatedError extends OrbitError {}
export declare class FeatureUnavailableError extends OrbitError {}

export declare class AppKey {
  readonly api_origin: string;
  readonly issuer: string;
  readonly application_id: string;
  readonly environment_id: string;
  readonly environment: "test" | "live";
  private constructor(apiOrigin: string, applicationId: string, environmentId: string, environment: "test" | "live");
  static parse(value: string): AppKey;
}

export interface DeviceBindingLike {
  readonly fingerprint: string;
  readonly provider: "machine_v1" | `custom:${string}`;
}
export declare class DeviceBinding implements DeviceBindingLike {
  readonly fingerprint: string;
  readonly provider: "machine_v1" | `custom:${string}`;
  constructor(fingerprint: string, provider: "machine_v1" | `custom:${string}`);
}

export type AccessState = "online" | "offline" | "refresh_required" | "expired" | "denied";
export interface ImmutableDate extends Omit<Date,
  "setDate" | "setFullYear" | "setHours" | "setMilliseconds" | "setMinutes" | "setMonth" |
  "setSeconds" | "setTime" | "setUTCDate" | "setUTCFullYear" | "setUTCHours" |
  "setUTCMilliseconds" | "setUTCMinutes" | "setUTCMonth" | "setUTCSeconds" | "setYear"> {}
export interface Snapshot {
  readonly access: AccessState;
  readonly entitlements: Readonly<Record<string, boolean>>;
  readonly expiresAt: ImmutableDate | null;
  readonly nextCheckAt: ImmutableDate | null;
  readonly credentialExpiresAt: ImmutableDate | null;
  readonly reauthenticationRequired: boolean;
  readonly offlineAllowed: boolean;
  readonly remainingOffline: Readonly<{ seconds: number }>;
  readonly remainingOfflineSeconds: number;
  has(feature: string): boolean;
}

export interface OperationOptions { readonly signal?: AbortSignal }
export interface ActivationOptions extends OperationOptions {
  readonly idempotencyKey?: string;
  /** Credential proving replacement of an existing locked activation. The SDK persists only its digest. */
  readonly previousCredential?: string;
}
export interface ClientOptions {
  readonly statePath?: string;
  readonly machineBinding?: boolean;
  readonly deviceBinding?: DeviceBindingLike;
}
export interface Account {
  readonly id: string;
  readonly username: string;
  readonly email: string;
  readonly suspended: boolean;
  readonly createdAt: ImmutableDate;
  readonly sessionExpiresAt: ImmutableDate;
}
export interface OwnedLicence {
  readonly id: string;
  readonly policyName: string;
  readonly state: "active" | "unused" | "expired" | "suspended" | "revoked";
  readonly expiryMode: "perpetual" | "payment" | "fixed" | "first_activation";
  readonly firstUsedAt: ImmutableDate | null;
  readonly expiresAt: ImmutableDate | null;
  readonly duration: Readonly<{ seconds: number }> | null;
  readonly deviceLimit: number;
  readonly hwidLocked: boolean;
  readonly offlineAllowed: boolean;
  readonly offlineDuration: Readonly<{ seconds: number }>;
  readonly offlineFileDuration: Readonly<{ seconds: number }>;
  readonly entitlements: Readonly<Record<string, boolean>>;
}
export interface OwnedLicencePage {
  readonly items: readonly OwnedLicence[];
  readonly nextCursor: string | null;
}
export declare class PendingRegistration {
  private constructor();
  close(): void;
  toJSON(): string;
  toString(): string;
}
export interface RegistrationResult {
  readonly accepted: true;
  readonly expiresAt: ImmutableDate;
  readonly pending: PendingRegistration;
}

export declare const Access: Readonly<{
  ONLINE: "online"; OFFLINE: "offline"; REFRESH_REQUIRED: "refresh_required";
  EXPIRED: "expired"; DENIED: "denied";
}>;

export declare class Client {
  private constructor();
  static open(appKey: string | AppKey, options?: ClientOptions): Promise<Client>;
  readonly installationId: string;
  on(event: "state", listener: (snapshot: Snapshot) => void): this;
  on(event: "error", listener: (error: Readonly<{ kind: ErrorKindName; code: string; requestId?: string }>) => void): this;
  off(event: "state" | "error", listener: (...args: never[]) => void): this;
  snapshot(): Snapshot;
  requireAccess(feature: string, options?: OperationOptions): Promise<Snapshot>;
  ensureAccess(feature: string, askForKey: () => string | null | undefined | Promise<string | null | undefined>, options?: OperationOptions): Promise<Snapshot>;
  activate(licenceKey: string, options?: ActivationOptions): Promise<Snapshot>;
  activateAccount(licenceId: string, options?: ActivationOptions): Promise<Snapshot>;
  refresh(options?: OperationOptions): Promise<Snapshot>;
  deactivate(options?: ActivationOptions): Promise<void>;
  logout(options?: OperationOptions): Promise<void>;
  account(): Account | null;
  login(username: string, password: string, options?: OperationOptions): Promise<Account>;
  ownedLicences(cursor?: string | null, options?: OperationOptions): Promise<OwnedLicencePage>;
  claimLicence(licenceKey: string, options?: ActivationOptions): Promise<OwnedLicence>;
  requestEmailChange(password: string, email: string, options?: OperationOptions): Promise<void>;
  requestPasswordRecovery(email: string, options?: OperationOptions): Promise<void>;
  register(licenceKey: string, username: string, email: string, password: string, options?: OperationOptions): Promise<RegistrationResult>;
  resendRegistration(pending: PendingRegistration, options?: OperationOptions): Promise<void>;
  logoutAccount(options?: OperationOptions): Promise<void>;
  close(): Promise<void>;
}
