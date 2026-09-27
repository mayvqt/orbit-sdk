export interface ImmutableDate extends Omit<Date,
  "setDate" | "setFullYear" | "setHours" | "setMilliseconds" | "setMinutes" | "setMonth" |
  "setSeconds" | "setTime" | "setUTCDate" | "setUTCFullYear" | "setUTCHours" |
  "setUTCMilliseconds" | "setUTCMinutes" | "setUTCMonth" | "setUTCSeconds" | "setYear"> {}
export interface UpdateTarget { readonly platform: string; readonly architecture: string }
export interface OnlineOptions { readonly signal?: AbortSignal }
export interface MutationOptions extends OnlineOptions { readonly idempotencyKey?: string }
export interface UpdateCheckOptions extends OnlineOptions { readonly channel?: string; readonly target?: UpdateTarget }
export interface PageOptions extends OnlineOptions { readonly after?: string; readonly limit?: number }
export interface ReleaseListOptions extends PageOptions { readonly channel?: string }
export interface AllocationListOptions extends PageOptions { readonly state?: "active" | "released" }
export interface ReleaseInput { readonly channel: string; readonly version: string; readonly notes: string }
export interface ArtifactInput {
  readonly platform: string;
  readonly architecture: string;
  readonly filename: string;
  readonly byteLength: number;
  readonly sha256: string;
  readonly deliveryMode: "public" | "protected";
  readonly url: string;
  readonly requiredFeature?: string | null;
}
export interface Artifact extends ArtifactInput {
  readonly id: string;
  readonly releaseId: string;
  readonly requiredFeature: string | null;
}
export interface Release extends ReleaseInput {
  readonly id: string;
  readonly releaseNumber: number | null;
  readonly state: "draft" | "published" | "unpublished";
  readonly createdAt: ImmutableDate;
  readonly publishedAt: ImmutableDate | null;
  readonly artifacts: readonly Artifact[];
}
export interface Update { readonly release: Release; readonly artifact: Artifact }
export interface DownloadAuthorization {
  readonly artifact: Artifact;
  readonly ticket: string | null;
  readonly expiresAt: ImmutableDate | null;
}
export interface DownloadOptions extends OnlineOptions { readonly maxBytes: number; readonly replace?: boolean }
export interface UsageLimit { readonly limit: number; readonly period: "day" | "month" | "lifetime"; readonly requiredFeature: string | null }
export interface ResourceLimit { readonly limit: number; readonly requiredFeature: string | null }
export interface ResourceCounter { readonly name: string; readonly limit: number; readonly used: number; readonly remaining: number }
export interface UsageCounter extends ResourceCounter {
  readonly period: "day" | "month" | "lifetime";
  readonly periodStartedAt: ImmutableDate | null;
  readonly resetsAt: ImmutableDate | null;
}
export interface UsageConsumption extends UsageCounter { readonly idempotencyKey: string; readonly consumedUnits: number }
export interface ResourceAllocation extends ResourceCounter {
  readonly allocationId: string;
  readonly resourceId: string;
  readonly units: number;
  readonly state: "active" | "released";
  readonly idempotencyKey: string;
}
export interface AllocationRecord {
  readonly allocationId: string;
  readonly resourceId: string;
  readonly units: number;
  readonly state: "active" | "released";
  readonly createdAt: ImmutableDate;
  readonly releasedAt: ImmutableDate | null;
}
export interface AllocationPage { readonly items: readonly AllocationRecord[]; readonly nextCursor: string | null }
export interface ReleasePage { readonly items: readonly Release[]; readonly nextCursor: string | null }
export interface MutationReceipt { readonly idempotencyKey: string }
