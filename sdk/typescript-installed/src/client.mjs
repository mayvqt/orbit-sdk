import { randomBytes, createHash, randomInt } from "node:crypto";
import { EventEmitter } from "node:events";
import { validateAppKey, canonicalScope, isOpaqueId, validProvider } from "./app-key.mjs";
import { configuredAppVersion, updateHint } from "./app-version.mjs";
import { fail, ErrorKind, discardsCredential, AppVersionUnsupportedError, NotActivatedError, FeatureUnavailableError, MutationUncertainError } from "./errors.mjs";
import * as online from "./online.mjs";
import { downloadFile } from "./download-file.mjs";
import { validEntitlements, parseJwks, verifyGrant } from "./grants.mjs";
import { isInteger, isText, stableJson, uniqueJson } from "./json.mjs";
import { makeOfflineRequest, parseOfflineKeys, verifyOfflineFile } from "./offline.mjs";
import { parseSessionKeys, verifySessionGrant } from "./sessions.mjs";
import { PrivateFileStore } from "./storage/private-files.mjs";
import { elapsedNs, machineFingerprint, wallSeconds } from "./platform/native.mjs";
import { HttpTransport } from "./transport.mjs";

const CLIENT_PREFIX = "/api/client/v1/";
const JWKS_PATH = "/.well-known/orbit-jwks.json";
const MAX_GENERATION = Number.MAX_SAFE_INTEGER - 1;
const CLIENT_TOKEN = Symbol("Client.open");
const PENDING_REGISTRATION_TOKEN = Symbol("PendingRegistration");
const pendingRegistrationState = new WeakMap();
let clockOverride;

export function setClockForTesting(source) {
  if (!source || typeof source.elapsedNs !== "function" || typeof source.wallSeconds !== "function") {
    throw new TypeError("clock source must provide elapsedNs and wallSeconds");
  }
  const previous = clockOverride;
  clockOverride = source;
  return () => { clockOverride = previous; };
}

function readElapsedNs() {
  return clockOverride ? clockOverride.elapsedNs() : elapsedNs();
}

function readWallSeconds() {
  return clockOverride ? clockOverride.wallSeconds() : wallSeconds();
}

export class DeviceBinding {
  constructor(fingerprint, provider) {
    if (!/^[0-9a-f]{64}$/.test(fingerprint) || !validProvider(provider)) {
      throw new TypeError("deviceBinding must contain a lowercase SHA-256 fingerprint and valid provider");
    }
    this.fingerprint = fingerprint;
    this.provider = provider;
    Object.freeze(this);
  }
}

export class Client extends EventEmitter {
  #key;
  #binding;
  #state;
  #store;
  #transport;
  #session;
  #sessionRequired;
  #sessionKeys;
  #floating;
  #pendingSessionId;
  #sessionDisabled;
  #sessionController;
  #sessionRetryAt;
  #sessionLicenceExpiry;
  #sessionBindingMode;
  #keys;
  #offlineKeys;
  #generation;
  #intentEpoch;
  #claims;
  #anchor;
  #offlineFile;
  #offlineAnchor;
  #transient;
  #retryAt;
  #retryTimer;
  #refreshTimer;
  #closed;
  #closing;
  #closeController;
  #active;
  #lastCheckpoint;
  #lifecycle;
  #appVersion = null;
  #updateAvailable = null;
  #versionDenial = null;
  #queues = new Map();
  #background = new Set();
  #pendingRegistrations = new Set();
  static async open(appKey, options = {}, capability = undefined, internal = undefined) {
    if (capability !== CLIENT_TOKEN) {
      if (capability !== undefined || internal !== undefined) throw new TypeError("internal Client.open arguments are unavailable");
      validateClientOptions(options);
    }
    const key = validateAppKey(appKey);
    const appVersion = configuredAppVersion(options.appVersion);
    const offlineKeys = options.offlineKeys === undefined ? null : parseOfflineKeys(options.offlineKeys, key.environment);
    const binding = await resolveBinding(key, options);
    const client = new Client(CLIENT_TOKEN, key, binding, options);
    client.#appVersion = appVersion;
    client.#lifecycle = internal?.lifecycle !== false;
    try {
      client.#store = await PrivateFileStore.open(key, options.statePath, binding, internal?.storageCodec);
      client.#state = client.#store.state;
      client.#generation = client.#state.generation;
      client.#offlineKeys = offlineKeys;
      client.#transport = internal?.transport ?? new HttpTransport(key.api_origin);
      await client.#restoreCache();
      if (!internal?.skipInitialRefresh && client.#state.pending_activation === null && client.#state.offline.jws === null) {
        try {
          await client.refresh();
        } catch (error) {
          // An unsupported application version still opens, so the application
          // can report the denial and use update checks.
          if (![ErrorKind.TRANSIENT, ErrorKind.REAUTHENTICATION_REQUIRED].includes(error?.kind) &&
              !(error instanceof AppVersionUnsupportedError) &&
              !(error?.kind === ErrorKind.DENIED && error?.code === "concurrent_session_limit_reached")) throw error;
        }
      }
      if (client.#lifecycle) client.#scheduleRefresh();
      return client;
    } catch (error) {
      await client.#store?.close().catch(() => {});
      client.#clearMemory();
      throw error;
    }
  }

  constructor(token, key, binding, options = {}) {
    super();
    if (token !== CLIENT_TOKEN) throw new TypeError("use Client.open() to create a client");
    this.#key = key;
    this.#binding = binding;
    this.#state = null;
    this.#store = null;
    this.#transport = null;
    this.#session = null;
    this.#sessionRequired = false;
    this.#sessionKeys = null;
    this.#floating = null;
    this.#pendingSessionId = null;
    this.#sessionDisabled = false;
    this.#sessionController = null;
    this.#sessionRetryAt = 0;
    this.#sessionLicenceExpiry = null;
    this.#sessionBindingMode = null;
    this.#generation = 0;
    this.#intentEpoch = Symbol("intent");
    this.#claims = null;
    this.#anchor = null;
    this.#offlineFile = null;
    this.#offlineAnchor = null;
    this.#transient = false;
    this.#retryAt = 0;
    this.#retryTimer = null;
    this.#refreshTimer = null;
    this.#closed = false;
    this.#closing = null;
    this.#closeController = new AbortController();
    this.#active = new Set();
    this.#keys = null;
    this.#offlineKeys = null;
    this.#lastCheckpoint = readElapsedNs();
    this.#lifecycle = true;
  }

  get installationId() {
    this.#assertOpen();
    this.#assertStorageHealthy();
    return this.#state.installation.id;
  }

  snapshot() {
    this.#assertOpen();
    this.#assertStorageHealthy();
    const state = this.#store.state;
    this.#state = state;
    this.#queueCheckpoint(false);
    if (state.offline?.jws !== null) return this.#offlineSnapshot(state);
    if (this.#sessionRequired) return this.#sessionSnapshot(state);
    const now = this.#nowOrNull();
    let access = state.credential ? "refresh_required" : "denied";
    let entitlements = Object.create(null);
    let expiresAt = null;
    let nextCheckAt = null;
    let credentialExpiresAt = state.credential?.expires_at ?? null;
    let offlineAllowed = false;
    if (this.#claims && this.#anchor && now !== null) {
      expiresAt = this.#claims.exp;
      nextCheckAt = this.#claims.refresh_after;
      offlineAllowed = this.#claims.offline_allowed;
      if (this.#claims.exp <= now) access = "expired";
      else if (this.#transient) access = this.#claims.offline_allowed ? "offline" : "refresh_required";
      else if (this.#claims.refresh_after <= now) access = "refresh_required";
      else access = "online";
      if (access === "online" || access === "offline") entitlements = this.#claims.entitlements;
    }
    if (!this.#claims && state.credential) access = "refresh_required";
    const remaining = this.#claims && now !== null && (access === "online" || access === "offline") && this.#claims.offline_allowed
      ? Math.max(0, this.#claims.exp - now) : 0;
    return freezeSnapshot({
      access,
      entitlements,
      expiresAt: expiresAt === null ? null : dateFromSeconds(expiresAt),
      nextCheckAt: nextCheckAt === null ? null : dateFromSeconds(nextCheckAt),
      credentialExpiresAt: credentialExpiresAt === null ? null : dateFromSeconds(credentialExpiresAt),
      reauthenticationRequired: !state.credential || credentialExpiresAt !== null && now !== null && credentialExpiresAt <= now + 86400,
      offlineAllowed,
      remainingOfflineSeconds: remaining,
      updateAvailable: this.#updateAvailable,
    });
  }

  async requireAccess(feature, { signal } = {}) {
    validateFeature(feature);
    return this.#run(signal, async (combined) => {
      let snapshot = this.snapshot();
      if (this.#state.offline?.jws !== null) {
        throwIfAborted(combined);
        if (snapshot.access === "expired") throw fail(ErrorKind.DENIED, "offline_file_expired");
        if (snapshot.access !== "offline") throw fail(ErrorKind.CLOCK_UNCERTAIN, "clock_uncertain");
        if (!snapshot.has(feature)) throw new FeatureUnavailableError();
        return snapshot;
      }
      if (this.#sessionRequired) {
        if (this.#floating) {
          const now = this.#sessionNow();
          if (now < this.#floating.grant.expiresAt) {
            if (!this.#floating.grant.entitlements[feature]) throw new FeatureUnavailableError();
            const final = this.snapshot();
            throwIfAborted(combined);
            if (final.access !== "online") throw fail(ErrorKind.DENIED, "session_access_unavailable");
            if (!final.has(feature)) throw new FeatureUnavailableError();
            return final;
          }
        }
        await this.#startFloating(combined, false);
        snapshot = this.snapshot();
        throwIfAborted(combined);
        if (snapshot.access === "online" && snapshot.has(feature)) {
          const final = this.snapshot();
          throwIfAborted(combined);
          if (final.access === "online" && final.has(feature)) return final;
          if (final.access === "online") throw new FeatureUnavailableError();
          throw fail(ErrorKind.DENIED, "session_access_unavailable");
        }
        if (snapshot.access === "online") throw new FeatureUnavailableError();
        throw fail(ErrorKind.DENIED, "session_access_unavailable");
      }
      if (["refresh_required", "expired", "offline"].includes(snapshot.access)) {
        try {
          await this.#refresh(combined, true);
        } catch (error) {
          if (error?.kind !== ErrorKind.TRANSIENT) throw error;
        }
        snapshot = this.snapshot();
      }
      throwIfAborted(combined);
      if (snapshot.access !== "online" && snapshot.access !== "offline") {
        if (this.#state.pending_activation) throw fail(ErrorKind.CONFIGURATION, "pending_activation_recovery_required");
        if (this.#state.credential && this.#transient) throw fail(ErrorKind.TRANSIENT, "network_unavailable");
        if (this.#state.credential && this.#versionDenial) throw new AppVersionUnsupportedError(this.#versionDenial.requestId);
        throw new NotActivatedError();
      }
      if (!snapshot.has(feature)) throw new FeatureUnavailableError();
      return snapshot;
    });
  }

  async ensureAccess(feature, askForKey, { signal } = {}) {
    if (typeof askForKey !== "function") throw new TypeError("askForKey must be a function");
    try {
      return await this.requireAccess(feature, { signal });
    } catch (error) {
      if (!(error instanceof NotActivatedError)) throw error;
      throwIfAborted(signal);
      const key = await askForKey();
      throwIfAborted(signal);
      if (typeof key !== "string" || !key) throw error;
      await this.activate(key, { signal });
      return this.requireAccess(feature, { signal });
    }
  }

  async activate(licenceKey, { idempotencyKey, previousCredential, signal } = {}) {
    if (!validInput(licenceKey, 256, false)) throw fail(ErrorKind.CONFIGURATION, "invalid_request");
    validateOperationId(idempotencyKey);
    validatePreviousCredential(previousCredential);
    return this.#run(signal, (combined) => this.#activate("key", licenceKey, null, idempotencyKey, previousCredential, combined));
  }

  async activateAccount(licenceId, { idempotencyKey, previousCredential, signal } = {}) {
    if (!isOpaqueId(licenceId)) throw fail(ErrorKind.CONFIGURATION, "invalid_request");
    validateOperationId(idempotencyKey);
    validatePreviousCredential(previousCredential);
    return this.#run(signal, (combined) => this.#activate("account", null, licenceId, idempotencyKey, previousCredential, combined));
  }

  async #activate(principal, licenceKey, licenceId, requestedOperationId, previousCredential, signal) {
    this.#advanceIntent();
    const intentEpoch = this.#intentEpoch;
    const operation = await this.#activationMutex(signal);
    try {
      if (intentEpoch !== this.#intentEpoch) throw fail(ErrorKind.STALE_RESPONSE, "stale_response");
      const customerId = principal === "account" ? this.#session?.customer.id : null;
      if (principal === "account" && !this.#session) throw fail(ErrorKind.REAUTHENTICATION_REQUIRED, "reauthentication_required");
      const checkpointContext = { claims: this.#claims, anchor: this.#anchor, offlineAnchor: this.#offlineAnchor };
      const generation = this.#fence();
      this.#claims = null;
      this.#anchor = null;
      this.#offlineFile = null;
      await this.#checkpointForTransition(checkpointContext);
      this.#transient = false;
      if (principal === "key") this.#session = null;
      let pending;
      const current = await this.#store.updateState((state) => {
        const prior = state.pending_activation;
        const digest = activationDigest(this.#key, state.installation, principal, licenceKey, licenceId, customerId, previousCredential);
        if (prior) {
          if (readWallSeconds() < prior.created_at || readWallSeconds() - prior.created_at > 86400) {
            throw fail(ErrorKind.CONFIGURATION, "pending_activation_recovery_required");
          }
          if (prior.principal_kind !== principal || prior.input_digest !== digest ||
              requestedOperationId && requestedOperationId !== prior.operation_id) {
            throw fail(ErrorKind.CONFIGURATION, "pending_activation_conflict");
          }
          pending = prior;
        } else {
          pending = {
            operation_id: requestedOperationId ?? randomBytes(24).toString("base64url"),
            principal_kind: principal,
            input_digest: digest,
            created_at: readWallSeconds(),
          };
        }
        return {
          ...state,
          generation: nextGeneration(state.generation),
          credential: null,
          access: null,
          pending_activation: pending,
          offline: state.offline.jws === null ? state.offline : { ...state.offline, jws: null },
        };
      }, () => generation === this.#generation && !this.#closed && !signal.aborted);
      this.#state = current;
      const body = {
        application_id: this.#key.application_id,
        environment_id: this.#key.environment_id,
        installation_id: this.#state.installation.id,
        fingerprint: this.#binding.fingerprint,
        fingerprint_provider: this.#binding.provider,
        previous_credential: previousCredential ?? null,
        idempotency_key: pending.operation_id,
        credential_mode: "persistent",
        ...(this.#appVersion === null ? {} : { app_version: this.#appVersion }),
        ...(principal === "key" ? { licence_key: licenceKey } : {
          customer_session: this.#session.token,
          licence_id: licenceId,
        }),
      };
      const started = startClock();
      let result;
      try {
        const response = await this.#transport.post(`${CLIENT_PREFIX}activations`, body, true, signal);
        if (!response) throw fail(ErrorKind.INVALID_RESPONSE, "missing_activation_response");
        result = await this.#verifyActivation(response, null, principal === "account" ? licenceId : null, started, signal);
      } catch (error) {
        this.#checkGeneration(generation);
        if (error?.kind === ErrorKind.CANCELLED) throw error;
        if (error?.kind === ErrorKind.TRANSIENT) {
          this.#transient = true;
          this.#retryAt = Date.now() + randomInt(15000, 45001);
          this.#scheduleRefresh();
          throw error;
        }
        await this.#invalidate({ preservePending: error?.kind !== ErrorKind.DENIED && error?.kind !== ErrorKind.REAUTHENTICATION_REQUIRED });
        throw error;
      }
      this.#checkGeneration(generation);
      throwIfAborted(signal);
      this.#state = await this.#store.updateState((state) => {
        if (state.pending_activation?.operation_id !== pending.operation_id) {
          throw fail(ErrorKind.STALE_RESPONSE, "stale_response");
        }
        return { ...state, credential: result.credential, access: result.access, pending_activation: null };
      }, () => generation === this.#generation && !this.#closed && !signal.aborted);
      this.#checkGeneration(generation);
      this.#sessionRequired = result.sessionRequired;
      if (result.sessionRequired) {
        this.#claims = null;
        this.#anchor = null;
        this.#sessionLicenceExpiry = result.licenceExpiry;
        this.#sessionBindingMode = result.bindingMode;
        if (!this.#sessionDisabled) await this.#startFloating(signal, false);
      } else {
        this.#dropFloating({ release: true });
        this.#sessionRequired = false;
        this.#claims = result.claims;
        this.#anchor = result.anchor;
        this.#sessionLicenceExpiry = null;
        this.#sessionBindingMode = null;
      }
      this.#transient = false;
      this.#retryAt = 0;
      this.#updateAvailable = result.updateAvailable;
      this.#versionDenial = null;
      this.#scheduleRefresh();
      this.#safeEmit("state", this.snapshot());
      return this.snapshot();
    } finally {
      operation.release();
    }
  }

  async refresh({ signal } = {}) {
    return this.#run(signal, (combined) => this.#refresh(combined, false));
  }

  async startSession({ signal } = {}) {
    return this.#run(signal, async (combined) => {
      if (this.#state.offline?.jws !== null) return this.snapshot();
      await this.#store.sync();
      this.#state = this.#store.state;
      if (!this.#state.credential) throw new NotActivatedError();
      this.#sessionDisabled = false;
      if (!this.#sessionRequired) {
        if (!this.#claims) await this.#refresh(combined, false);
        if (!this.#sessionRequired) return this.snapshot();
      }
      return this.#startFloating(combined, true);
    });
  }

  async endSession({ signal } = {}) {
    return this.#run(signal, async (combined) => {
      if (this.#state.offline?.jws !== null) return this.snapshot();
      await this.#store.sync();
      this.#state = this.#store.state;
      if (this.#claims && !this.#sessionRequired) return this.snapshot();
      this.#advanceIntent();
      this.#sessionDisabled = true;
      if (!this.#state.credential) return this.snapshot();
      if (!this.#sessionRequired) {
        if (!this.#claims) await this.#refresh(combined, false);
        if (!this.#sessionRequired) return this.snapshot();
      }
      this.#generation = Symbol("generation");
      this.#dropFloating({ release: true, clearProfile: false });
      return this.snapshot();
    });
  }

  offlineRequest() {
    this.#assertOpen();
    this.#assertStorageHealthy();
    return makeOfflineRequest(this.#key, this.#state.installation.id, this.#binding);
  }

  async importOfflineFile(file, { signal } = {}) {
    if (this.#offlineKeys === null) throw fail(ErrorKind.CONFIGURATION, "offline_keys_required");
    return this.#run(signal, async (combined) => {
      const intentEpoch = this.#intentEpoch;
      const operation = await this.#activationMutex(combined);
      let committed = false;
      try {
        if (intentEpoch !== this.#intentEpoch) throw fail(ErrorKind.STALE_RESPONSE, "stale_response");
        const checkpointContext = { claims: this.#claims, anchor: this.#anchor, offlineAnchor: this.#offlineAnchor };
        const generation = this.#fence();
        await this.#checkpoint(true, false, checkpointContext);
        await this.#store.sync();
        this.#state = this.#store.state;
        this.#checkGeneration(generation);
        const prior = this.#store.state.offline;
        const { started, now: untrustedNow } = this.#offlineNowAndStart(prior, checkpointContext.anchor);
        const now = Math.max(untrustedNow, prior.time_high_water);
        const verified = verifyOfflineFile(file, this.#key, this.#binding, this.#state.installation.id,
          this.#offlineKeys, now, prior.sequence > 0 ? prior.sequence : 1);
        if (verified.sequence === prior.sequence && prior.sequence > 0 &&
            (verified.issuanceId !== prior.issuance_id || verified.contentDigest !== prior.content_digest)) {
          throw fail(ErrorKind.INVALID_RESPONSE, "offline_sequence_conflict");
        }
        const sameIssuance = verified.sequence === prior.sequence && prior.sequence > 0 &&
          verified.issuanceId === prior.issuance_id && verified.contentDigest === prior.content_digest;
        const saved = sameIssuance ? {
          ...prior,
          jws: verified.token,
          wall_high_water: Math.max(prior.wall_high_water, started.wall),
        } : {
          jws: verified.token,
          sequence: verified.sequence,
          issuance_id: verified.issuanceId,
          content_digest: verified.contentDigest,
          verified_at: now,
          time_high_water: Math.max(now, verified.issuedAt, prior.time_high_water),
          wall_high_water: Math.max(started.wall, prior.wall_high_water),
        };
        this.#state = await this.#store.updateState((state) => ({
          ...state,
          generation: nextGeneration(state.generation),
          credential: null,
          access: null,
          pending_activation: null,
          offline: saved,
        }), () => generation === this.#generation && !this.#closed && !combined.aborted);
        committed = true;
        this.#claims = null;
        this.#anchor = null;
        this.#offlineFile = null;
        this.#transient = false;
        this.#retryAt = 0;
        this.#keys = null;
        this.#session = null;
        if (combined.aborted || this.#closed || generation !== this.#generation) {
          await this.#discardOfflineAuthority();
          throw fail(ErrorKind.CANCELLED, "operation_cancelled");
        }
        this.#assertStorageHealthy();
        const priorAnchor = this.#offlineAnchor;
        const anchor = priorAnchor
          ? priorAnchor
          : { server: saved.time_high_water, ...started };
        anchorNow(anchor);
        const elapsed = readElapsedNs();
        if (elapsed < anchor.elapsed) throw fail(ErrorKind.CLOCK_UNCERTAIN, "clock_uncertain");
        const wholeElapsed = ((elapsed - anchor.elapsed) / 1000000000n) * 1000000000n;
        const wholeSeconds = Number(wholeElapsed / 1000000000n);
        const anchoredWall = anchor.wall + wholeSeconds;
        if (!isInteger(anchoredWall) || Math.abs(readWallSeconds() - anchoredWall) > 30) {
          throw fail(ErrorKind.CLOCK_UNCERTAIN, "clock_uncertain");
        }
        const rebasedAnchor = {
          server: Math.max(anchor.server + wholeSeconds, saved.time_high_water),
          elapsed: anchor.elapsed + wholeElapsed,
          wall: anchoredWall,
        };
        anchorNow(rebasedAnchor);
        this.#assertStorageHealthy();
        if (combined.aborted || this.#closed || generation !== this.#generation) {
          await this.#discardOfflineAuthority();
          throw fail(ErrorKind.CANCELLED, "operation_cancelled");
        }
        this.#offlineAnchor = rebasedAnchor;
        this.#offlineFile = verified;
        this.#state = this.#store.state;
        const snapshot = this.snapshot();
        this.#safeEmit("state", snapshot);
        return snapshot;
      } finally {
        operation.release();
        if (!committed) this.#scheduleRefresh();
      }
    });
  }

  async #refresh(signal, respectRetry) {
    const operation = await this.#mutex("refreshQueue", signal);
    try {
      return await this.#refreshUnlocked(signal, respectRetry);
    } finally {
      operation.release();
    }
  }

  async #refreshUnlocked(signal, respectRetry) {
    const generation = this.#generation;
    const currentState = await this.#store.sync();
    this.#checkGeneration(generation);
    this.#state = currentState;
    if (currentState.offline.jws !== null) return this.snapshot();
    if (currentState.pending_activation) throw fail(ErrorKind.CONFIGURATION, "pending_activation_recovery_required");
    const credential = currentState.credential;
    if (!credential) throw fail(ErrorKind.REAUTHENTICATION_REQUIRED, "reauthentication_required");
    if (respectRetry && this.#retryAt > Date.now()) return this.snapshot();
    const started = startClock();
    const body = {
      application_id: this.#key.application_id,
      environment_id: this.#key.environment_id,
      credential: credential.bearer,
      installation_id: this.#state.installation.id,
      fingerprint: this.#binding.fingerprint,
      fingerprint_provider: this.#binding.provider,
      ...(this.#appVersion === null ? {} : { app_version: this.#appVersion }),
    };
    try {
      const response = await this.#transport.post(`${CLIENT_PREFIX}activations/${credential.activation_id}/validate`, body, true, signal);
      if (!response) throw fail(ErrorKind.INVALID_RESPONSE, "missing_activation_response");
      const result = await this.#verifyActivation(response, credential, null, started, signal);
      this.#checkGeneration(generation);
      throwIfAborted(signal);
      this.#state = await this.#store.updateState((state) => {
        if (state.credential?.bearer !== credential.bearer) throw fail(ErrorKind.STALE_RESPONSE, "stale_response");
        return { ...state, credential: result.credential, access: result.access };
      }, () => generation === this.#generation && !this.#closed && !signal.aborted);
      this.#checkGeneration(generation);
      if (result.sessionRequired) {
        this.#sessionRequired = true;
        this.#claims = null;
        this.#anchor = null;
        this.#sessionLicenceExpiry = result.licenceExpiry;
        this.#sessionBindingMode = result.bindingMode;
      } else {
        if (this.#sessionRequired || this.#floating || this.#pendingSessionId) this.#dropFloating({ release: true });
        this.#sessionRequired = false;
        this.#claims = result.claims;
        this.#anchor = result.anchor;
        this.#sessionLicenceExpiry = null;
        this.#sessionBindingMode = null;
      }
      this.#updateAvailable = result.updateAvailable;
      this.#versionDenial = null;
    } catch (error) {
      this.#checkGeneration(generation);
      if (signal.aborted) throw fail(ErrorKind.CANCELLED, "operation_cancelled");
      if (error?.kind === ErrorKind.CANCELLED) throw error;
      if (error instanceof AppVersionUnsupportedError) {
        // Keep the activation for an updated application, but drop cached
        // access without offline fallback and pace further validation.
        this.#state = await this.#store.updateState((state) => ({ ...state, access: null }),
          () => generation === this.#generation && !this.#closed);
        this.#dropFloating({ release: true });
        this.#claims = null;
        this.#anchor = null;
        this.#transient = false;
        this.#updateAvailable = null;
        this.#versionDenial = error;
        this.#retryAt = Date.now() + randomInt(15000, 45001);
        this.#scheduleRefresh();
        throw error;
      }
      if (error?.kind === ErrorKind.TRANSIENT) {
        this.#transient = true;
        this.#retryAt = Date.now() + randomInt(15000, 45001);
        this.#scheduleRefresh();
        const snapshot = this.snapshot();
        if (snapshot.access === "offline" || snapshot.access === "online" && this.#sessionRequired) return snapshot;
        throw error;
      }
      // A suspension, expiry or similar denial only withholds access; keep the
      // credential so the device resumes when access returns.
      await this.#invalidate({ preservePending: Boolean(this.#store.state.pending_activation) &&
        error?.kind !== ErrorKind.DENIED && error?.kind !== ErrorKind.REAUTHENTICATION_REQUIRED,
      keepCredential: error?.kind === ErrorKind.DENIED && !discardsCredential(error) });
      throw error;
    }
    this.#transient = false;
    this.#retryAt = 0;
    if (this.#sessionRequired && !this.#sessionDisabled) await this.#startFloating(signal, false);
    this.#scheduleRefresh();
    this.#safeEmit("state", this.snapshot());
    return this.snapshot();
  }

  async #startFloating(signal, explicit) {
    if (this.#state.offline?.jws !== null) return this.snapshot();
    if (!this.#sessionRequired) return this.snapshot();
    if (this.#sessionDisabled && !explicit) throw fail(ErrorKind.DENIED, "session_explicitly_ended");
    const intentEpoch = this.#intentEpoch;
    const operation = await this.#mutex("sessionQueue", signal);
    let sent = false;
    let sessionId;
    let credential;
    const generation = this.#generation;
    const controller = new AbortController();
    try {
      this.#checkGeneration(generation);
      if (intentEpoch !== this.#intentEpoch) throw fail(ErrorKind.STALE_RESPONSE, "stale_response");
      throwIfAborted(signal);
      await this.#store.sync();
      this.#state = this.#store.state;
      credential = this.#state.credential;
      if (!credential) throw new NotActivatedError();
      if (!this.#sessionRequired) return this.snapshot();
      if (this.#sessionDisabled && !explicit) throw fail(ErrorKind.DENIED, "session_explicitly_ended");
      if (this.#floating) {
        if (this.#sessionNow() < this.#floating.grant.expiresAt) return this.snapshot();
        this.#dropFloating({ release: false, clearProfile: false });
      }
      this.#pendingSessionId ??= randomBytes(24).toString("base64url");
      sessionId = this.#pendingSessionId;
      this.#sessionController = controller;
      const requestSignal = AbortSignal.any([signal, controller.signal]);
      const started = startClock();
      sent = true;
      const response = await this.#transport.post(`${CLIENT_PREFIX}activations/${credential.activation_id}/sessions`,
        { ...this.#credentialBody(credential), session_id: sessionId }, true, requestSignal);
      const verified = await this.#verifySessionReply(response, sessionId, 1, credential, started, requestSignal);
      this.#checkGeneration(generation);
      throwIfAborted(requestSignal);
      this.#floating = verified;
      this.#pendingSessionId = null;
      this.#sessionRetryAt = 0;
      this.#scheduleRefresh();
      const snapshot = this.snapshot();
      this.#safeEmit("state", snapshot);
      return snapshot;
    } catch (error) {
      if (generation !== this.#generation || sent && this.#state?.credential?.bearer !== credential?.bearer) {
        if (sent && sessionId && credential) this.#scheduleSessionRelease(sessionId, credential);
        if (error?.kind === ErrorKind.CANCELLED) throw error;
        throw fail(ErrorKind.STALE_RESPONSE, "stale_response");
      }
      if (sent && sessionId && credential) {
        if (error?.kind === ErrorKind.TRANSIENT ||
            error?.kind === ErrorKind.DENIED && error?.code === "concurrent_session_limit_reached") {
          this.#sessionRetryAt = Date.now() + randomInt(15000, 45001);
          this.#scheduleRefresh();
        } else {
          if (this.#pendingSessionId === sessionId) this.#pendingSessionId = null;
          this.#scheduleSessionRelease(sessionId, credential);
          if (discardsCredential(error)) {
            await this.#invalidate();
          } else if (![ErrorKind.CANCELLED, ErrorKind.STALE_RESPONSE].includes(error?.kind)) {
            this.#sessionDisabled = true;
            this.#sessionRetryAt = 0;
            clearTimeout(this.#refreshTimer);
          }
        }
      }
      throw error;
    } finally {
      if (this.#sessionController === controller) this.#sessionController = null;
      operation.release();
    }
  }

  async #renewFloating(signal) {
    const current = this.#floating;
    if (!current) return this.#startFloating(signal, false);
    const operation = await this.#mutex("sessionQueue", signal);
    const generation = this.#generation;
    let sent = false;
    let credential;
    const controller = new AbortController();
    try {
      this.#checkGeneration(generation);
      throwIfAborted(signal);
      await this.#store.sync();
      this.#state = this.#store.state;
      credential = this.#state.credential;
      if (!credential || !this.#sessionRequired || this.#sessionDisabled || this.#floating !== current) {
        throw fail(ErrorKind.STALE_RESPONSE, "stale_response");
      }
      const now = this.#sessionNow();
      if (now >= current.grant.expiresAt) {
        this.#dropFloating({ release: false, clearProfile: false });
        operation.release();
        return this.#startFloating(signal, false);
      }
      const sequence = current.grant.sequence + 1;
      if (!isInteger(sequence, 1)) throw fail(ErrorKind.STORAGE, "storage_failed");
      this.#sessionController = controller;
      const requestSignal = AbortSignal.any([signal, controller.signal]);
      const started = startClock();
      sent = true;
      const route = `${CLIENT_PREFIX}activations/${credential.activation_id}/sessions/${current.grant.sessionId}/renew`;
      const response = await this.#transport.post(route, { ...this.#credentialBody(credential), sequence }, true, requestSignal);
      const verified = await this.#verifySessionReply(response, current.grant.sessionId, sequence, credential, started, requestSignal);
      this.#checkGeneration(generation);
      throwIfAborted(requestSignal);
      if (this.#floating !== current) throw fail(ErrorKind.STALE_RESPONSE, "stale_response");
      this.#floating = verified;
      this.#sessionRetryAt = 0;
      this.#scheduleRefresh();
      const snapshot = this.snapshot();
      this.#safeEmit("state", snapshot);
      return snapshot;
    } catch (error) {
      if (sent && [ErrorKind.CANCELLED, ErrorKind.STALE_RESPONSE].includes(error?.kind)) {
        this.#scheduleSessionRelease(current.grant.sessionId, credential);
      }
      const stillCurrent = generation === this.#generation && this.#floating === current &&
        this.#state?.credential?.bearer === credential?.bearer && this.#sessionRequired;
      if (!stillCurrent) {
        if (error?.kind === ErrorKind.CANCELLED) throw error;
        throw fail(ErrorKind.STALE_RESPONSE, "stale_response");
      }
      if (discardsCredential(error)) {
        await this.#invalidate();
        throw error;
      }
      if (error?.kind === ErrorKind.TRANSIENT) {
        this.#sessionRetryAt = Date.now() + randomInt(15000, 45001);
        this.#scheduleRefresh();
        const snapshot = this.snapshot();
        if (snapshot.access === "online" && snapshot.session?.sessionId === current.grant.sessionId &&
            snapshot.session.sequence === current.grant.sequence) return snapshot;
        throw error;
      }
      if (error?.kind !== ErrorKind.CANCELLED && error?.kind !== ErrorKind.STALE_RESPONSE) {
        this.#dropFloating({ release: false, clearProfile: false });
        this.#sessionDisabled = true;
        this.#sessionRetryAt = 0;
      }
      throw error;
    } finally {
      if (this.#sessionController === controller) this.#sessionController = null;
      operation.release();
    }
  }

  async #verifySessionReply(bytes, sessionId, sequence, credential, started, signal) {
    const reply = checkFields(uniqueJson(bytes ?? Buffer.alloc(0)), {
      session_id: isString, sequence: Number.isSafeInteger, expires_at: isString, server_time: isString, grant: isString,
    });
    if (reply.session_id !== sessionId || reply.sequence !== sequence || !/^[A-Za-z0-9_-]{16,128}$/.test(sessionId)) {
      invalid("invalid_session_response");
    }
    const expiresAt = parseTimestamp(reply.expires_at);
    const serverTime = parseTimestamp(reply.server_time);
    const anchor = { server: serverTime, ...started };
    if (!this.#sessionKeys || !this.#sessionKeys.keys.has(parseTokenKid(reply.grant))) {
      throwIfAborted(signal);
      const suffix = `application_id=${this.#key.application_id}&environment_id=${this.#key.environment_id}`;
      const jwksBytes = await this.#transport.get(`${JWKS_PATH}?${suffix}`, signal);
      if (!jwksBytes) invalid("missing_session_jwks");
      this.#sessionKeys = parseSessionKeys(jwksBytes, this.#key.environment);
    }
    const grant = verifySessionGrant(reply.grant, this.#sessionKeys, {
      issuer: this.#key.issuer,
      application: this.#key.application_id,
      environment: this.#key.environment_id,
      licence: credential.licence_id,
      activation: credential.activation_id,
      installation: this.#state.installation.id,
      fingerprint: this.#binding.fingerprint,
      fingerprintProvider: this.#binding.provider,
      credentialExpiresAt: credential.expires_at,
      licenceExpiresAt: this.#sessionLicenceExpiry,
      now: anchorNow(anchor),
      sessionId,
      sequence,
      keyEnvironment: this.#key.environment,
      allowUnboundFingerprint: true,
    });
    if (grant.expiresAt !== expiresAt || grant.bindingMode !== this.#sessionBindingMode) invalid("invalid_session_response");
    return Object.freeze({ grant, anchor });
  }

  async #sendSessionEnd(sessionId, credential, signal) {
    const route = `${CLIENT_PREFIX}activations/${credential.activation_id}/sessions/${sessionId}/end`;
    const response = await this.#transport.post(route, { ...this.#credentialBody(credential) }, true, signal);
    if (response !== null) invalid("invalid_session_response");
  }

  #credentialBody(credential) {
    return {
      application_id: this.#key.application_id,
      environment_id: this.#key.environment_id,
      credential: credential.bearer,
      installation_id: this.#state.installation.id,
      fingerprint: this.#binding.fingerprint,
      fingerprint_provider: this.#binding.provider,
    };
  }

  #sessionSnapshot(state) {
    const credential = state.credential;
    const current = this.#floating;
    let now = null;
    if (current) {
      try { now = anchorNow(current.anchor); }
      catch { now = null; }
    }
    let access = credential ? "refresh_required" : "denied";
    let entitlements = Object.create(null);
    const grant = current?.grant;
    if (grant && now !== null) {
      access = grant.expiresAt > now ? "online" : "expired";
      if (access === "online") entitlements = grant.entitlements;
    }
    const session = grant ? Object.freeze({
      sessionId: grant.sessionId,
      sequence: grant.sequence,
      expiresAt: dateFromSeconds(grant.expiresAt),
      refreshAfter: dateFromSeconds(grant.refreshAfter),
    }) : null;
    return freezeSnapshot({
      access,
      entitlements,
      expiresAt: grant ? dateFromSeconds(grant.expiresAt) : null,
      nextCheckAt: grant ? dateFromSeconds(grant.refreshAfter) : null,
      credentialExpiresAt: credential?.expires_at === null || credential?.expires_at === undefined ? null : dateFromSeconds(credential.expires_at),
      reauthenticationRequired: !credential || credential.expires_at !== null && now !== null && credential.expires_at <= now + 86400,
      offlineAllowed: false,
      remainingOfflineSeconds: 0,
      session,
    });
  }

  #sessionNow() {
    if (!this.#floating) throw fail(ErrorKind.CLOCK_UNCERTAIN, "clock_uncertain");
    return anchorNow(this.#floating.anchor);
  }

  #dropFloating({ release = true, clearProfile = true } = {}) {
    clearTimeout(this.#refreshTimer);
    const current = this.#floating;
    const sessionId = current?.grant.sessionId ?? this.#pendingSessionId;
    const credential = this.#state?.credential;
    this.#sessionController?.abort();
    this.#sessionController = null;
    this.#floating = null;
    this.#pendingSessionId = null;
    this.#sessionRetryAt = 0;
    if (clearProfile) {
      this.#sessionRequired = false;
      this.#sessionDisabled = false;
      this.#sessionKeys = null;
      this.#sessionLicenceExpiry = null;
      this.#sessionBindingMode = null;
    }
    if (release && sessionId && credential) this.#scheduleSessionRelease(sessionId, credential);
  }

  #scheduleSessionRelease(sessionId, credential) {
    if (!credential || !sessionId || !this.#transport) return;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2000);
    const task = this.#sendSessionEnd(sessionId, credential, controller.signal).catch(() => {}).finally(() => clearTimeout(timer));
    this.#background.add(task);
    void task.finally(() => this.#background.delete(task));
  }

  async #verifyActivation(bytes, previous, expectedLicence, started, signal) {
    const reply = uniqueJson(bytes);
    const fields = {
      activation_id: isString, installation_id: isString,
      licence_id: (v) => v === null || isString(v),
      credential: (v) => v === null || isString(v), credential_expires_at: (v) => v === null || isString(v),
      grant: (v) => v === null || isString(v), server_time: isString, binding_mode: isString,
      fingerprint_provider: (v) => v === null || isString(v), licence_expires_at: (v) => v === null || isString(v),
      secret_replay_expired: (v) => typeof v === "boolean", session_required: (v) => v === null || typeof v === "boolean",
      update_available: () => true,
    };
    const value = checkFields(reply, fields, ["credential", "grant", "fingerprint_provider", "licence_expires_at", "session_required", "licence_id", "update_available"]);
    const updateAvailable = updateHint(reply);
    const sessionRequired = value.session_required === true;
    if (value.secret_replay_expired) throw fail(ErrorKind.REAUTHENTICATION_REQUIRED, "secret_replay_expired");
    if (!isOpaqueId(value.activation_id) || value.installation_id !== this.#state.installation.id ||
        value.fingerprint_provider !== this.#binding.provider || !["hwid", "none"].includes(value.binding_mode) ||
        value.session_required !== null && !sessionRequired || (sessionRequired ? value.grant !== null : value.grant === null)) {
      throw fail(ErrorKind.INVALID_RESPONSE, "invalid_activation_response");
    }
    if (sessionRequired && (!isOpaqueId(value.licence_id) ||
        expectedLicence !== null && value.licence_id !== expectedLicence ||
        previous !== null && value.licence_id !== previous.licence_id)) {
      throw fail(ErrorKind.INVALID_RESPONSE, "invalid_activation_response");
    }
    const serverTime = parseTimestamp(value.server_time);
    const anchor = { server: serverTime, ...started };
    let now = anchorNow(anchor);
    const credentialExpiry = value.credential_expires_at === null ? null : parseTimestamp(value.credential_expires_at);
    const licenceExpiry = value.licence_expires_at === null ? null : parseTimestamp(value.licence_expires_at);
    if (credentialExpiry !== null && (credentialExpiry <= now || credentialExpiry > now + 30 * 86400) ||
        previous === null && credentialExpiry !== null || previous && (value.activation_id !== previous.activation_id ||
          credentialExpiry !== previous.expires_at || value.credential !== null)) {
      throw fail(ErrorKind.INVALID_RESPONSE, "invalid_activation_response");
    }
    if (sessionRequired) {
      const licenceId = value.licence_id;
      const bearer = value.credential ?? previous?.bearer ?? null;
      if (!isOpaqueId(licenceId) || !validBearer(bearer)) throw fail(ErrorKind.INVALID_RESPONSE, "invalid_activation_response");
      const credential = { activation_id: value.activation_id, licence_id: licenceId, bearer, expires_at: credentialExpiry };
      return { credential, claims: null, anchor: null, access: null, sessionRequired: true, licenceExpiry, bindingMode: value.binding_mode, updateAvailable };
    }
    const token = value.grant;
    if (!this.#keys || !this.#keys.has(parseTokenKid(token))) {
      throwIfAborted(signal);
      const suffix = `application_id=${this.#key.application_id}&environment_id=${this.#key.environment_id}`;
      const jwksBytes = await this.#transport.get(`${JWKS_PATH}?${suffix}`, signal);
      if (!jwksBytes) throw fail(ErrorKind.INVALID_RESPONSE, "missing_jwks");
      this.#keys = parseJwks(jwksBytes);
    }
    const claims = verifyGrant(token, this.#keys, {
      issuer: this.#key.issuer,
      application: this.#key.application_id,
      environment: this.#key.environment_id,
      licence: expectedLicence ?? previous?.licence_id ?? null,
      activation: value.activation_id,
      installation: this.#state.installation.id,
      fingerprint: this.#binding.fingerprint,
      fingerprint_provider: this.#binding.provider,
      credential_expires_at: credentialExpiry,
      licence_expires_at: licenceExpiry,
      now: anchorNow(anchor),
      allow_unbound_fingerprint: true,
    });
    if (claims.binding_mode !== value.binding_mode) throw fail(ErrorKind.INVALID_RESPONSE, "invalid_activation_response");
    const bearer = value.credential ?? previous?.bearer ?? null;
    if (!validBearer(bearer)) throw fail(ErrorKind.INVALID_RESPONSE, "invalid_activation_response");
    const credential = {
      activation_id: value.activation_id,
      licence_id: claims.sub,
      bearer,
      expires_at: credentialExpiry,
    };
    const receivedWall = started.wall;
    const access = {
      jws: token,
      jwks: singleJwks(this.#keys, token),
      licence_expires_at: licenceExpiry,
      received_server_time: serverTime,
      received_wall_time: receivedWall,
      server_high_water: anchorNow(anchor),
      wall_high_water: readWallSeconds(),
    };
    now = anchorNow(anchor);
    return { credential, claims, anchor, access, sessionRequired: false, licenceExpiry: null, bindingMode: value.binding_mode, updateAvailable };
  }

  async deactivate({ idempotencyKey, signal } = {}) {
    validateOperationId(idempotencyKey);
    return this.#run(signal, async (combined) => {
      await this.#store.sync();
      const credential = this.#store.state.credential;
      const generation = await this.#invalidate();
      if (!credential) throw fail(ErrorKind.REAUTHENTICATION_REQUIRED, "reauthentication_required");
      const body = {
        application_id: this.#key.application_id,
        environment_id: this.#key.environment_id,
        credential: credential.bearer,
        installation_id: this.#state.installation.id,
        fingerprint: this.#binding.fingerprint,
        fingerprint_provider: this.#binding.provider,
        idempotency_key: idempotencyKey ?? randomBytes(24).toString("base64url"),
      };
      const response = await this.#transport.post(`${CLIENT_PREFIX}activations/${credential.activation_id}/deactivate`, body, true, combined);
      this.#checkGeneration(generation);
      if (response !== null) throw fail(ErrorKind.INVALID_RESPONSE, "unexpected_response_body");
    });
  }

  async logout({ signal } = {}) {
    return this.#run(signal, async () => {
      await this.#invalidate();
    });
  }

  async checkForUpdate(installedReleaseNumber, { channel, target, signal } = {}) {
    const body = online.updateInput(installedReleaseNumber, { channel, target });
    return this.#online("updates", body, (v) => online.parseUpdate(v, body), signal);
  }

  async authorizeDownload(releaseId, artifactId, { signal } = {}) {
    online.requireInput(releaseId, online.identifier);
    online.requireInput(artifactId, online.identifier);
    return this.#online("downloads/authorize", { release_id: releaseId, artifact_id: artifactId },
      (v) => online.parseAuthorization(v, releaseId, artifactId), signal);
  }

  async download(authorization, destination, { maxBytes, replace, signal } = {}) {
    return this.#run(signal, (inner) => downloadFile(authorization, destination, { maxBytes, replace, signal: inner }));
  }

  async usage(name, { signal } = {}) {
    online.requireInput(name, online.limitName);
    return this.#online(`usage/${name}`, {}, (v) => online.parseCounter(v, name, true), signal);
  }

  async consume(name, units = 1, { idempotencyKey, signal } = {}) {
    online.requireInput(name, online.limitName);
    online.requireInput(units, (v) => online.integer(v, 1));
    const key = onlineOperationId(idempotencyKey);
    return this.#online(`usage/${name}/consume`, { units, idempotency_key: key },
      (v) => online.parseConsumption(v, name, key, units), signal, key);
  }

  async resources(name, { signal } = {}) {
    online.requireInput(name, online.limitName);
    return this.#online(`resources/${name}`, {}, (v) => online.parseCounter(v, name, false), signal);
  }

  async acquireResource(name, resourceId, units = 1, { idempotencyKey, signal } = {}) {
    online.requireInput(name, online.limitName);
    online.requireInput(resourceId, online.identifier);
    online.requireInput(units, (v) => online.integer(v, 1));
    const key = onlineOperationId(idempotencyKey);
    return this.#online(`resources/${name}/acquire`, { resource_id: resourceId, units, idempotency_key: key },
      (v) => online.parseAllocation(v, name, key, { resourceId, units }), signal, key);
  }

  async releaseResource(name, allocationId, { idempotencyKey, signal } = {}) {
    online.requireInput(name, online.limitName);
    online.requireInput(allocationId, online.identifier);
    const key = onlineOperationId(idempotencyKey);
    return this.#online(`resources/${name}/allocations/${allocationId}/release`, { idempotency_key: key },
      (v) => online.parseAllocation(v, name, key, { allocationId }), signal, key);
  }

  async #online(route, extra, parse, externalSignal, key = undefined) {
    // Catch outside #run so cancellation after a sent mutation retains its ID.
    let sent = false;
    try {
      return await this.#run(externalSignal, async (signal) => {
        await this.#store.sync();
        this.#state = this.#store.state;
        const generation = this.#generation;
        const credential = this.#state.credential;
        if (!credential || this.#offlineFile) throw new NotActivatedError();
        throwIfAborted(signal);
        sent = true;
        let bytes;
        try {
          bytes = await this.#transport.post(`${CLIENT_PREFIX}activations/${credential.activation_id}/${route}`,
            { ...this.#credentialBody(credential), ...extra }, true, signal);
        } catch (error) {
          throwIfAborted(signal);
          this.#checkGeneration(generation);
          throw error;
        }
        throwIfAborted(signal);
        this.#checkGeneration(generation);
        try { return parse(uniqueJson(bytes)); }
        catch (error) { if (error?.kind) throw error; invalid("invalid_online_response"); }
      });
    } catch (error) {
      if (key && sent && (error?.kind !== ErrorKind.DENIED || error.status >= 500)) throw new MutationUncertainError(key, error);
      throw error;
    }
  }

  account() {
    this.#assertOpen();
    this.#assertStorageHealthy();
    return this.#session ? accountResult(this.#session.metadata) : null;
  }

  async login(username, password, { signal } = {}) {
    if (!validInput(username, 128, false) || !username || !validInput(password, 256, false) ||
        !/^[a-z0-9_]{3,32}$/.test(username)) throw fail(ErrorKind.CONFIGURATION, "invalid_request");
    return this.#run(signal, async (combined) => {
      const generation = await this.#invalidate({ preservePending: true, clearAccount: true });
      const body = this.#scopeBody({ username, password });
      try {
        const response = await this.#transport.post(`${CLIENT_PREFIX}sessions`, body, false, combined);
        const parsed = parseLogin(uniqueJson(response ?? Buffer.alloc(0)));
        this.#checkGeneration(generation);
        throwIfAborted(combined);
        this.#session = { token: parsed.token, customer: parsed.account.customer, metadata: parsed.account };
        return accountResult(parsed.account);
      } catch (error) {
        await this.#finishAccount(generation, error, combined);
        throw error;
      }
    });
  }

  async ownedLicences(cursor = undefined, { signal } = {}) {
    if (cursor !== undefined && cursor !== null && !isOpaqueId(cursor)) throw fail(ErrorKind.CONFIGURATION, "invalid_cursor");
    return this.#accountRequest(signal, async (session, generation, combined) => {
      const suffix = `application_id=${this.#key.application_id}&environment_id=${this.#key.environment_id}` + (cursor ? `&after=${cursor}` : "");
      try {
        const bytes = await this.#transport.getBearer(`${CLIENT_PREFIX}licences?${suffix}`, session.token, combined);
        const page = checkFields(uniqueJson(bytes), { items: Array.isArray, next_cursor: (v) => v === null || typeof v === "string" }, ["next_cursor"]);
        if (page.items.length > 100 || page.next_cursor !== null && !isOpaqueId(page.next_cursor)) invalid("invalid_licences");
        const items = page.items.map((item) => ownedLicence(parseLicence(item)));
        await this.#finishAccount(generation, null, combined);
        return Object.freeze({ items: Object.freeze(items), nextCursor: page.next_cursor });
      } catch (error) {
        await this.#finishAccount(generation, error, combined);
        throw error;
      }
    });
  }

  async claimLicence(licenceKey, { idempotencyKey, signal } = {}) {
    if (!validInput(licenceKey, 256, false) || !licenceKey) throw fail(ErrorKind.CONFIGURATION, "invalid_request");
    validateOperationId(idempotencyKey);
    return this.#accountPost(`${CLIENT_PREFIX}licence-claims`, {
      licence_key: licenceKey,
      idempotency_key: idempotencyKey ?? randomBytes(24).toString("base64url"),
    }, true, signal, parseLicence);
  }

  async requestEmailChange(password, email, { signal } = {}) {
    if (!validInput(password, 256, false) || !validInput(email, 254, false)) throw fail(ErrorKind.CONFIGURATION, "invalid_request");
    return this.#accountPost(`${CLIENT_PREFIX}email-changes`, { password, email }, false, signal, null, true);
  }

  async requestPasswordRecovery(email, { signal } = {}) {
    if (!validInput(email, 254, false) || !email) throw fail(ErrorKind.CONFIGURATION, "invalid_request");
    return this.#run(signal, async (combined) => {
      const generation = this.#generation;
      try {
        const response = await this.#transport.post(`${CLIENT_PREFIX}password-recovery`, this.#scopeBody({ email }), false, combined);
        parseAccepted(response);
        this.#checkGeneration(generation);
      } catch (error) {
        this.#checkGeneration(generation);
        throw error;
      }
    });
  }

  async register(licenceKey, username, email, password, { signal } = {}) {
    if ((licenceKey !== null && !validInput(licenceKey, 256, false)) || !validInput(username, 128, false) ||
        !validInput(email, 254, false) || !validInput(password, 256, false) || password.length < 8 ||
        !/^[a-z0-9_]{3,32}$/.test(username)) throw fail(ErrorKind.CONFIGURATION, "invalid_request");
    return this.#run(signal, async (combined) => {
      const generation = this.#generation;
      try {
        const bytes = await this.#transport.post(`${CLIENT_PREFIX}registrations`, this.#scopeBody({ ...(licenceKey === null ? {} : { licence_key: licenceKey }), username, email, password }), false, combined);
        const reply = checkFields(uniqueJson(bytes ?? Buffer.alloc(0)), {
          accepted: (v) => typeof v === "boolean", expires_at: isString, resend_credential: isString,
        });
        if (!reply.accepted || !validBearer(reply.resend_credential)) invalid("invalid_registration");
        const expiresAt = parseTimestamp(reply.expires_at);
        this.#checkGeneration(generation);
        const pending = new PendingRegistration(PENDING_REGISTRATION_TOKEN, reply.resend_credential, this.#key, this.#pendingRegistrations);
        this.#pendingRegistrations.add(pending);
        return Object.freeze({ accepted: true, expiresAt: dateFromSeconds(expiresAt), pending });
      } catch (error) {
        this.#checkGeneration(generation);
        throw error;
      }
    });
  }

  async resendRegistration(pending, { signal } = {}) {
    if (!(pending instanceof PendingRegistration) || !pending.belongsTo(this.#key)) throw new TypeError("pending registration belongs to another client");
    return this.#run(signal, async (combined) => {
      const generation = this.#generation;
      const credential = borrowPendingRegistration(pending);
      try {
        const bytes = await this.#transport.post(`${CLIENT_PREFIX}registrations/resend`, this.#scopeBody({ resend_credential: credential }), false, combined);
        parseAccepted(bytes);
        this.#checkGeneration(generation);
      } catch (error) {
        this.#checkGeneration(generation);
        throw error;
      }
    });
  }

  async logoutAccount({ signal } = {}) {
    return this.#run(signal, async (combined) => {
      const session = this.#session;
      const generation = await this.#invalidate({ clearAccount: true });
      if (!session) return;
      const query = `application_id=${this.#key.application_id}&environment_id=${this.#key.environment_id}`;
      try {
        await this.#transport.deleteBearer(`${CLIENT_PREFIX}sessions/current?${query}`, session.token, combined);
      } catch (error) {
        this.#checkGeneration(generation);
        throw error;
      }
      this.#checkGeneration(generation);
    });
  }

  async close() {
    if (this.#closing) return this.#closing;
    this.#advanceIntent();
    this.#fence();
    this.#closed = true;
    this.#closeController.abort();
    clearTimeout(this.#refreshTimer);
    clearTimeout(this.#retryTimer);
    this.#closing = (async () => {
      await Promise.allSettled([...this.#active]);
      await Promise.allSettled([...this.#background]);
      try {
        await this.#checkpoint(true, true);
      } finally {
        for (const pending of this.#pendingRegistrations) pending.close();
        this.#pendingRegistrations.clear();
        await this.#store?.drain();
        this.#clearMemory();
        await this.#store?.close();
      }
    })();
    return this.#closing;
  }

  async #accountPost(route, body, retrySafe, externalSignal, validate = undefined, accepted = false) {
    return this.#accountRequest(externalSignal, async (session, generation, combined) => {
      try {
        const bytes = await this.#transport.post(route, this.#scopeBody({ ...body, customer_session: session.token }), retrySafe, combined);
        const value = accepted ? parseAccepted(bytes) : validate ? validate(uniqueJson(bytes ?? Buffer.alloc(0))) : uniqueJson(bytes ?? Buffer.alloc(0));
        await this.#finishAccount(generation, null, combined);
        return validate === parseLicence ? ownedLicence(value) : value;
      } catch (error) {
        await this.#finishAccount(generation, error, combined);
        throw error;
      }
    });
  }

  async #accountRequest(externalSignal, callback) {
    return this.#run(externalSignal, async (combined) => {
      await this.#store.sync();
      const session = this.#session;
      if (!session) throw fail(ErrorKind.REAUTHENTICATION_REQUIRED, "reauthentication_required");
      const generation = this.#generation;
      return callback(session, generation, combined);
    });
  }

  async #finishAccount(generation, failure, signal) {
    this.#checkGeneration(generation);
    throwIfAborted(signal);
    if (!failure || failure.kind === ErrorKind.TRANSIENT || failure.kind === ErrorKind.CANCELLED ||
        failure.kind === ErrorKind.DENIED && failure.code === "session_expired") return;
    await this.#invalidate({ preservePending: true, clearAccount: true });
  }

  async #invalidate({ preservePending = false, clearAccount = false, keepCredential = false } = {}) {
    this.#advanceIntent();
    const checkpointContext = { claims: this.#claims, anchor: this.#anchor, offlineAnchor: this.#offlineAnchor };
    const generation = this.#fence();
    this.#claims = null;
    this.#anchor = null;
    this.#offlineFile = null;
    await this.#checkpointForTransition(checkpointContext);
    this.#transient = false;
    this.#retryAt = 0;
    this.#updateAvailable = null;
    this.#versionDenial = null;
    this.#keys = null;
    if (clearAccount) this.#session = null;
    this.#state = await this.#store.updateState((state) => ({
      ...state,
      generation: nextGeneration(state.generation),
      credential: keepCredential ? state.credential : null,
      access: null,
      pending_activation: preservePending ? state.pending_activation : null,
      offline: state.offline.jws === null ? state.offline : { ...state.offline, jws: null },
    }), () => generation === this.#generation && !this.#closed);
    clearTimeout(this.#refreshTimer);
    clearTimeout(this.#retryTimer);
    this.#safeEmit("state", this.snapshot());
    return generation;
  }

  #fence() {
    this.#generation = Symbol("generation");
    clearTimeout(this.#refreshTimer);
    clearTimeout(this.#retryTimer);
    this.#dropFloating({ release: true, clearProfile: true });
    return this.#generation;
  }

  #advanceIntent() {
    this.#intentEpoch = Symbol("intent");
  }

  async #checkpointForTransition(context) {
    try {
      await this.#checkpoint(true, false, context);
    } catch (error) {
      if (error?.kind !== ErrorKind.CLOCK_UNCERTAIN || this.#store.state.offline?.jws === null) throw error;
      // Explicit mode changes must clear offline authority even when the local clock
      // cannot safely advance the checkpoint. The durable transition below retains
      // the last trusted floors and removes the signed file.
    }
  }

  #scopeBody(body) {
    return { ...body, application_id: this.#key.application_id, environment_id: this.#key.environment_id };
  }

  async #activationMutex(signal) {
    return this.#mutex("activationQueue", signal);
  }

  async #mutex(queueName, signal) {
    throwIfAborted(signal);
    const prior = this.#queues.get(queueName) ?? Promise.resolve();
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    const predecessor = prior.catch(() => {});
    this.#queues.set(queueName, predecessor.then(() => gate));
    try {
      await raceSignal(predecessor, signal);
      throwIfAborted(signal);
      return { release };
    } catch (error) {
      void predecessor.then(release);
      throw error;
    }
  }

  async #run(externalSignal, callback) {
    this.#assertOpen();
    this.#assertStorageHealthy();
    const local = new AbortController();
    const signal = externalSignal ? AbortSignal.any([externalSignal, local.signal, this.#closeController.signal]) :
      AbortSignal.any([local.signal, this.#closeController.signal]);
    let complete;
    const done = new Promise((resolve) => { complete = resolve; });
    this.#active.add(done);
    try {
      throwIfAborted(signal);
      return await callback(signal);
    } catch (error) {
      if (signal.aborted && error?.kind !== ErrorKind.CANCELLED) throw fail(ErrorKind.CANCELLED, "operation_cancelled");
      throw error;
    } finally {
      this.#active.delete(done);
      complete();
    }
  }

  async #restoreCache() {
    if (this.#state.offline.jws !== null) {
      if (!this.#offlineKeys) throw fail(ErrorKind.CONFIGURATION, "offline_keys_required");
      const saved = this.#state.offline;
      const file = verifyOfflineFile(saved.jws, this.#key, this.#binding, this.#state.installation.id,
        this.#offlineKeys, saved.verified_at, saved.sequence);
      if (file.sequence !== saved.sequence || file.issuanceId !== saved.issuance_id || file.contentDigest !== saved.content_digest) {
        throw fail(ErrorKind.STORAGE, "storage_failed");
      }
      const wall = readWallSeconds();
      if (!isInteger(wall, 0, 253402300799) || wall + 30 < saved.wall_high_water) {
        throw fail(ErrorKind.CLOCK_UNCERTAIN, "clock_uncertain");
      }
      const server = Math.max(wall, saved.time_high_water, file.issuedAt);
      this.#offlineAnchor = { server, ...startClock() };
      anchorNow(this.#offlineAnchor);
      this.#offlineFile = file;
      return;
    }
    const access = this.#state.access;
    const credential = this.#state.credential;
    if (!access || !credential) return;
    try {
      const wall = readWallSeconds();
      if (wall < access.wall_high_water || access.server_high_water < access.received_server_time ||
          access.wall_high_water < access.received_wall_time ||
          Math.abs((access.server_high_water - access.received_server_time) - (access.wall_high_water - access.received_wall_time)) > 30) {
        throw fail(ErrorKind.CLOCK_UNCERTAIN, "clock_uncertain");
      }
      const estimated = Math.max(access.server_high_water, access.received_server_time + wall - access.received_wall_time);
      if (!isInteger(estimated, 0)) throw fail(ErrorKind.CLOCK_UNCERTAIN, "clock_uncertain");
      const keys = parseJwks(access.jwks);
      if (keys.size !== 1) invalid("invalid_jwks");
      const claims = verifyGrant(access.jws, keys, {
        issuer: this.#key.issuer,
        application: this.#key.application_id,
        environment: this.#key.environment_id,
        licence: credential.licence_id,
        activation: credential.activation_id,
        installation: this.#state.installation.id,
        fingerprint: this.#binding.fingerprint,
        fingerprint_provider: this.#binding.provider,
        credential_expires_at: credential.expires_at,
        licence_expires_at: access.licence_expires_at,
        now: access.received_server_time,
        allow_unbound_fingerprint: true,
      });
      if (claims.exp <= estimated || credential.expires_at !== null && credential.expires_at <= estimated ||
          access.licence_expires_at !== null && access.licence_expires_at <= estimated) throw fail(ErrorKind.INVALID_RESPONSE, "expired_grant");
      this.#keys = keys;
      this.#claims = claims;
      this.#anchor = { server: estimated, ...startClock() };
      anchorNow(this.#anchor);
    } catch (error) {
      if (error?.kind === ErrorKind.STORAGE) throw error;
      const generation = this.#fence();
      this.#claims = null;
      this.#anchor = null;
      this.#state = await this.#store.updateState((state) => state.access?.jws === access.jws
        ? { ...state, generation: nextGeneration(state.generation), access: null }
        : state, () => generation === this.#generation && !this.#closed);
    }
  }

  #queueCheckpoint(force) {
    if (!this.#store || this.#closed && !force) return;
    const task = this.#checkpoint(force).catch((error) => {
      if (error?.kind !== ErrorKind.STALE_RESPONSE && error?.kind !== ErrorKind.CANCELLED) {
        this.#safeEmit("error", publicError(error));
      }
    });
    this.#background.add(task);
    void task.finally(() => this.#background.delete(task));
  }

  async #checkpoint(force, allowClosing = false, context = undefined) {
    if (!this.#store || this.#closed && !force && !allowClosing) return;
    const elapsed = readElapsedNs();
    if (!force && elapsed - this.#lastCheckpoint < 60_000_000_000n) return;
    const current = this.#store.state;
    const onlineAnchor = context?.anchor ?? this.#anchor;
    const onlineClaims = context?.claims ?? this.#claims;
    const offlineAnchor = context?.offlineAnchor ?? this.#offlineAnchor;
    const haveOnline = Boolean(current.access && onlineAnchor && onlineClaims);
    const haveOffline = Boolean(current.offline?.sequence > 0 && offlineAnchor);
    if (!haveOnline && !haveOffline) {
      this.#lastCheckpoint = elapsed;
      return;
    }
    const generation = this.#generation;
    const jws = current.access?.jws;
    const offlineSequence = current.offline?.sequence ?? 0;
    try {
      let onlineCheckpoint = null;
      if (haveOnline) {
        const now = anchorNow(onlineAnchor);
        const wall = readWallSeconds();
        const serverDelta = now - current.access.server_high_water;
        const wallDelta = wall - current.access.wall_high_water;
        if (serverDelta < 0 || wallDelta < 0 || Math.abs(serverDelta - wallDelta) > 30) throw fail(ErrorKind.CLOCK_UNCERTAIN, "clock_uncertain");
        onlineCheckpoint = { now, wall };
      }
      let offlineCheckpoint = null;
      if (haveOffline) {
        const now = anchorNow(offlineAnchor);
        const wall = readWallSeconds();
        const serverDelta = now - current.offline.time_high_water;
        const wallDelta = wall - current.offline.wall_high_water;
        if (serverDelta < 0 || wallDelta < 0 || Math.abs(serverDelta - wallDelta) > 30) throw fail(ErrorKind.CLOCK_UNCERTAIN, "clock_uncertain");
        offlineCheckpoint = { now, wall };
      }
      this.#state = await this.#store.updateState((state) => {
        let next = state;
        if (onlineCheckpoint && state.access?.jws === jws && state.credential) {
          next = { ...next, access: { ...state.access, server_high_water: onlineCheckpoint.now, wall_high_water: onlineCheckpoint.wall } };
        }
        if (offlineCheckpoint && state.offline.sequence === offlineSequence) {
          next = { ...next, offline: { ...next.offline,
            time_high_water: Math.max(next.offline.time_high_water, offlineCheckpoint.now),
            wall_high_water: Math.max(next.offline.wall_high_water, offlineCheckpoint.wall),
          } };
        }
        return next;
      }, () => generation === this.#generation && (!this.#closed || allowClosing));
    } catch (error) {
      if (error?.kind === ErrorKind.STALE_RESPONSE || error?.kind === ErrorKind.CANCELLED) throw error;
      if (error?.kind === ErrorKind.CLOCK_UNCERTAIN && haveOffline) throw error;
      if (error?.kind === ErrorKind.STORAGE) {
        this.#clearMemory();
        throw error;
      }
      const fenced = this.#fence();
      this.#claims = null;
      this.#anchor = null;
      this.#state = await this.#store.updateState((state) => state.access?.jws === jws
        ? { ...state, generation: nextGeneration(state.generation), access: null }
        : state, () => fenced === this.#generation && (!this.#closed || allowClosing));
    }
    this.#lastCheckpoint = elapsed;
  }

  #scheduleRefresh() {
    clearTimeout(this.#refreshTimer);
    clearTimeout(this.#retryTimer);
    if (this.#closed || !this.#lifecycle || !this.#state?.credential || this.#state?.offline?.jws !== null) return;
    if (this.#sessionRequired) {
      if (this.#sessionDisabled) return;
      let due = 0;
      if (this.#sessionRetryAt > Date.now()) due = (this.#sessionRetryAt - Date.now()) / 1000;
      else if (this.#floating) {
        try { due = Math.max(0, this.#floating.grant.refreshAfter - this.#sessionNow()); }
        catch { due = 0; }
      }
      this.#refreshTimer = setTimeout(() => {
        if (this.#closed || this.#sessionDisabled) return;
        this.#run(undefined, (signal) => this.#advanceSession(signal)).catch((error) => {
          if (error?.kind !== ErrorKind.CANCELLED && error?.kind !== ErrorKind.STORAGE && error?.kind !== ErrorKind.STALE_RESPONSE) {
            this.#safeEmit("error", publicError(error));
          }
          if (!this.#closed && this.#sessionRequired) this.#scheduleRefresh();
        });
      }, Math.min(Math.max(250, due * 1000), 0x7fffffff));
      this.#refreshTimer.unref?.();
      return;
    }
    const now = this.#nowOrNull();
    const due = this.#claims && now !== null ? this.#claims.refresh_after - now : 0;
    const delay = this.#transient ? Math.max(1000, this.#retryAt - Date.now()) : Math.max(1000, due * 1000);
    this.#refreshTimer = setTimeout(() => {
      if (this.#closed) return;
      this.refresh().catch((error) => {
        if (error?.kind !== ErrorKind.CANCELLED && error?.kind !== ErrorKind.STORAGE) {
          this.#safeEmit("error", publicError(error));
          if (this.#transient) this.#scheduleRefresh();
        }
      });
    }, Math.min(delay, 0x7fffffff));
    this.#refreshTimer.unref?.();
  }

  #nowOrNull() {
    if (!this.#anchor) return null;
    try {
      return anchorNow(this.#anchor);
    } catch {
      this.#claims = null;
      this.#anchor = null;
      return null;
    }
  }

  async #advanceSession(signal) {
    this.#assertStorageHealthy();
    await this.#store.sync();
    this.#state = this.#store.state;
    if (this.#state.offline?.jws !== null || !this.#sessionRequired || this.#sessionDisabled) return this.snapshot();
    if (!this.#state.credential) throw new NotActivatedError();
    if (!this.#floating) return this.#startFloating(signal, false);
    const now = this.#sessionNow();
    if (now >= this.#floating.grant.refreshAfter) return this.#renewFloating(signal);
    this.#scheduleRefresh();
    return this.snapshot();
  }

  #offlineSnapshot(state) {
    const file = this.#offlineFile;
    const now = this.#offlineNowOrNull();
    let access = "denied";
    if (file && now !== null) access = file.expiresAt > now ? "offline" : "expired";
    const remaining = access === "offline" ? Math.max(0, file.expiresAt - now) : 0;
    return freezeSnapshot({
      access,
      entitlements: access === "offline" ? file.entitlements : Object.create(null),
      expiresAt: file ? dateFromSeconds(file.expiresAt) : null,
      nextCheckAt: null,
      credentialExpiresAt: null,
      reauthenticationRequired: false,
      offlineAllowed: true,
      remainingOfflineSeconds: remaining,
    });
  }

  #offlineNowOrNull() {
    if (!this.#offlineAnchor) return null;
    try { return anchorNow(this.#offlineAnchor); }
    catch { return null; }
  }

  #offlineNowAndStart(prior, transitionAnchor = null) {
    const started = startClock();
    if (!isInteger(started.wall, 0, 253402300799) || started.wall + 30 < prior.wall_high_water) {
      throw fail(ErrorKind.CLOCK_UNCERTAIN, "clock_uncertain");
    }
    let now = started.wall;
    if (this.#offlineAnchor) now = Math.max(now, anchorNow(this.#offlineAnchor));
    else if (transitionAnchor) now = Math.max(now, anchorNow(transitionAnchor));
    else if (this.#anchor) now = Math.max(now, anchorNow(this.#anchor));
    return { started, now: Math.max(now, prior.time_high_water) };
  }

  async #discardOfflineAuthority() {
    try {
      this.#state = await this.#store.updateState((state) => state.offline.jws === null ? state : {
        ...state,
        offline: { ...state.offline, jws: null },
        credential: null,
        access: null,
        pending_activation: null,
      });
    } catch {
      this.#clearMemory();
      throw fail(ErrorKind.STORAGE, "storage_failed");
    }
    this.#offlineFile = null;
  }

  #checkGeneration(generation) {
    if (this.#closed || generation !== this.#generation) throw fail(ErrorKind.STALE_RESPONSE, "stale_response");
  }

  #assertOpen() {
    if (this.#closed) throw fail(ErrorKind.STORAGE, "client_closed");
  }

  #assertStorageHealthy() {
    try {
      this.#store.assertHealthySync();
    } catch (error) {
      this.#clearMemory();
      for (const pending of this.#pendingRegistrations) pending.close();
      this.#pendingRegistrations.clear();
      throw error;
    }
  }

  #clearMemory() {
    this.#sessionController?.abort();
    this.#floating = null;
    this.#pendingSessionId = null;
    this.#sessionRequired = false;
    this.#sessionDisabled = false;
    this.#sessionKeys = null;
    this.#sessionLicenceExpiry = null;
    this.#sessionBindingMode = null;
    this.#sessionRetryAt = 0;
    this.#claims = null;
    this.#anchor = null;
    this.#offlineFile = null;
    this.#offlineAnchor = null;
    this.#transient = false;
    this.#updateAvailable = null;
    this.#versionDenial = null;
    this.#session = null;
    this.#keys = null;
    this.#offlineKeys = null;
    this.#state = null;
  }

  #safeEmit(name, value) {
    try {
      this.emit(name, value);
    } catch {
      // User event listeners cannot change access or lifecycle state.
    }
  }
}

export function openClientWithStorageCodec(appKey, options, storageCodec) {
  return Client.open(appKey, options, CLIENT_TOKEN, { storageCodec });
}

export function openClientForTesting(appKey, options = {}) {
  const { statePath, machineBinding, deviceBinding, offlineKeys, appVersion, transport, storageCodec,
    skipInitialRefresh = true, lifecycle = false } = options;
  return Client.open(appKey, { statePath, machineBinding, deviceBinding, offlineKeys, appVersion }, CLIENT_TOKEN, {
    transport, storageCodec, skipInitialRefresh, lifecycle,
  });
}

export function validateClientOptions(options) {
  if (!options || typeof options !== "object" || Array.isArray(options) ||
      Object.getPrototypeOf(options) !== Object.prototype && Object.getPrototypeOf(options) !== null) {
    throw fail(ErrorKind.CONFIGURATION, "invalid_client_options");
  }
  const allowed = new Set(["statePath", "machineBinding", "deviceBinding", "offlineKeys", "appVersion"]);
  if (Object.keys(options).some((name) => !allowed.has(name)) ||
      options.machineBinding !== undefined && typeof options.machineBinding !== "boolean") {
    throw fail(ErrorKind.CONFIGURATION, "invalid_client_options");
  }
}

export class PendingRegistration {
  constructor(token, credential, key, ownerSet = undefined) {
    if (token !== PENDING_REGISTRATION_TOKEN) throw new TypeError("pending registrations are returned by Client.register()");
    pendingRegistrationState.set(this, {
      credential,
      scope: JSON.stringify(canonicalScope(key)),
      ownerSet,
    });
    Object.freeze(this);
  }

  belongsTo(key) {
    return pendingRegistrationState.get(this)?.scope === JSON.stringify(canonicalScope(key));
  }

  close() {
    const state = pendingRegistrationState.get(this);
    if (state) {
      state.credential = null;
      state.ownerSet?.delete(this);
    }
  }

  toJSON() {
    return "[redacted pending registration]";
  }

  toString() {
    return "PendingRegistration(<redacted>)";
  }
}

function borrowPendingRegistration(pending) {
  const state = pendingRegistrationState.get(pending);
  if (!state?.credential) throw fail(ErrorKind.CONFIGURATION, "pending_registration_closed");
  return state.credential;
}

export const Access = Object.freeze({ ONLINE: "online", OFFLINE: "offline", REFRESH_REQUIRED: "refresh_required", EXPIRED: "expired", DENIED: "denied" });

async function resolveBinding(key, options) {
  if (options.deviceBinding !== undefined && options.deviceBinding !== null) {
    const value = options.deviceBinding;
    return new DeviceBinding(value.fingerprint, value.provider);
  }
  if (options.machineBinding === false) return Object.freeze({ fingerprint: null, provider: null });
  if (options.machineBinding !== undefined && options.machineBinding !== true) throw new TypeError("machineBinding must be a boolean");
  const fingerprint = await machineFingerprint(key.application_id, key.environment_id);
  return Object.freeze({ fingerprint, provider: fingerprint ? "machine_v1" : null });
}

function activationDigest(key, installation, principal, licenceKey, licenceId, customerId, previousCredential) {
  const value = {
    scope: canonicalScope(key),
    installation: {
      id: installation.id,
      fingerprint: installation.fingerprint,
      fingerprint_provider: installation.fingerprint_provider,
    },
    principal_kind: principal,
    credential_mode: "persistent",
    previous_credential_digest: previousCredential ? createHash("sha256").update(previousCredential, "ascii").digest("hex") : null,
  };
  if (principal === "key") value.licence_key = licenceKey;
  else {
    value.licence_id = licenceId;
    value.customer_id = customerId;
  }
  const raw = stableJson(value);
  return createHash("sha256").update(raw, "utf8").digest("hex");
}

function startClock() {
  return { elapsed: readElapsedNs(), wall: readWallSeconds() };
}

function anchorNow(anchor) {
  const elapsed = readElapsedNs();
  if (elapsed < anchor.elapsed) throw fail(ErrorKind.CLOCK_UNCERTAIN, "clock_uncertain");
  const delta = Number((elapsed - anchor.elapsed) / 1000000000n);
  const expectedWall = anchor.wall + delta;
  if (!isInteger(expectedWall) || Math.abs(readWallSeconds() - expectedWall) > 30) throw fail(ErrorKind.CLOCK_UNCERTAIN, "clock_uncertain");
  const now = anchor.server + delta;
  if (!isInteger(now, 0)) throw fail(ErrorKind.CLOCK_UNCERTAIN, "clock_uncertain");
  return now;
}

function parseTimestamp(value) {
  if (typeof value !== "string") invalid("invalid_timestamp");
  const match = /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?(Z|[+-]\d\d:\d\d)$/.exec(value);
  if (!match) invalid("invalid_timestamp");
  const datePart = /^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)$/.exec(match[1]);
  const [, yearText, monthText, dayText, hourText, minuteText, secondText] = datePart ?? [];
  const year = Number(yearText), month = Number(monthText), day = Number(dayText);
  const hour = Number(hourText), minute = Number(minuteText), second = Number(secondText);
  const monthDays = [31, isLeapYear(year) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (year < 1 || month < 1 || month > 12 || day < 1 || day > monthDays[month - 1] ||
      hour > 23 || minute > 59 || second > 59 ||
      match[3] !== "Z" && (Number(match[3].slice(1, 3)) > 23 || Number(match[3].slice(4, 6)) > 59)) invalid("invalid_timestamp");
  const instant = Date.parse(value);
  if (!Number.isFinite(instant)) invalid("invalid_timestamp");
  const seconds = Math.floor(instant / 1000);
  if (!isInteger(seconds)) invalid("invalid_timestamp");
  return seconds;
}

function isLeapYear(year) {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}

function dateFromSeconds(value) {
  if (!isInteger(value)) invalid("invalid_timestamp");
  return immutableDate(value * 1000);
}

function immutableDate(milliseconds) {
  const date = new Date(milliseconds);
  return new Proxy(date, {
    get(target, key) {
      if (typeof key === "string" && key.startsWith("set")) return () => { throw new TypeError("Date is immutable"); };
      const value = Reflect.get(target, key, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function freezeSnapshot(value) {
  const entitlements = Object.freeze(Object.assign(Object.create(null), value.entitlements));
  const remaining = Object.freeze({ seconds: value.remainingOfflineSeconds });
  return Object.freeze({
    access: value.access,
    entitlements,
    expiresAt: value.expiresAt,
    nextCheckAt: value.nextCheckAt,
    credentialExpiresAt: value.credentialExpiresAt,
    reauthenticationRequired: value.reauthenticationRequired,
    offlineAllowed: value.offlineAllowed,
    remainingOffline: remaining,
    remainingOfflineSeconds: value.remainingOfflineSeconds,
    session: value.session ?? null,
    updateAvailable: value.updateAvailable ?? null,
    has(feature) { return entitlements[feature] === true; },
  });
}

function accountResult(value) {
  return Object.freeze({
    id: value.customer.id,
    username: value.customer.username,
    email: value.customer.email,
    suspended: value.customer.suspended,
    createdAt: dateFromSeconds(parseTimestamp(value.customer.created_at)),
    sessionExpiresAt: dateFromSeconds(parseTimestamp(value.expires_at)),
  });
}

function parseLogin(value) {
  if (!value || typeof value !== "object") invalid("invalid_login");
  const reply = checkFields(value, { customer: isObject, session: isString, expires_at: isString });
  const customer = checkFields(reply.customer, { id: isString, username: isString, email: isString, suspended: (v) => typeof v === "boolean", created_at: isString });
  if (!isOpaqueId(customer.id) || customer.suspended || !/^[a-z0-9_]{3,32}$/.test(customer.username) ||
      !isText(customer.email, { min: 1, max: 254 }) || !validBearer(reply.session)) invalid("invalid_login");
  parseTimestamp(customer.created_at);
  parseTimestamp(reply.expires_at);
  return { token: reply.session, account: { customer, expires_at: reply.expires_at } };
}

function parseLicence(value) {
  const licence = checkFields(value, {
    id: isString, policy_name: isString,
    state: (v) => ["active", "unused", "expired", "suspended", "revoked"].includes(v),
    expiry_mode: (v) => ["perpetual", "payment", "fixed", "first_activation"].includes(v),
    first_used_at: (v) => v === null || typeof v === "string", expires_at: (v) => v === null || typeof v === "string",
    duration_seconds: (v) => v === null || Number.isSafeInteger(v), device_limit: Number.isSafeInteger,
    concurrent_session_limit: Number.isSafeInteger,
    hwid_locked: (v) => typeof v === "boolean", offline_allowed: (v) => typeof v === "boolean",
    offline_seconds: Number.isSafeInteger, offline_file_seconds: Number.isSafeInteger, entitlements: isObject,
    usage_limits: isObject, resource_limits: isObject,
  }, ["first_used_at", "expires_at", "duration_seconds"]);
  if (!isOpaqueId(licence.id) || !isInteger(licence.device_limit, 1, 100) || !isInteger(licence.concurrent_session_limit, 0, 65535) ||
      Buffer.byteLength(licence.policy_name) > 80 || !validEntitlements(licence.entitlements) ||
      !isInteger(licence.offline_seconds, -2147483648, 2147483647) ||
      !(licence.offline_file_seconds === 0 || isInteger(licence.offline_file_seconds, 86400, 31_622_400)) ||
      (licence.offline_allowed ? !isInteger(licence.offline_seconds, 300, 86400) : licence.offline_seconds !== 0) ||
      licence.duration_seconds !== null && !isInteger(licence.duration_seconds, 0)) invalid("invalid_licence");
  for (const date of [licence.first_used_at, licence.expires_at]) if (date !== null) parseTimestamp(date);
  try { online.parseDefinitions(licence.usage_limits, true); online.parseDefinitions(licence.resource_limits, false); }
  catch { invalid("invalid_licence"); }
  return licence;
}

function ownedLicence(value) {
  return Object.freeze({
    id: value.id,
    policyName: value.policy_name,
    state: value.state,
    expiryMode: value.expiry_mode,
    firstUsedAt: value.first_used_at === null ? null : dateFromSeconds(parseTimestamp(value.first_used_at)),
    expiresAt: value.expires_at === null ? null : dateFromSeconds(parseTimestamp(value.expires_at)),
    duration: value.duration_seconds === null ? null : Object.freeze({ seconds: value.duration_seconds }),
    deviceLimit: value.device_limit,
    concurrentSessionLimit: value.concurrent_session_limit,
    hwidLocked: value.hwid_locked,
    offlineAllowed: value.offline_allowed,
    offlineDuration: Object.freeze({ seconds: value.offline_seconds }),
    offlineFileDuration: Object.freeze({ seconds: value.offline_file_seconds }),
    entitlements: Object.freeze(Object.assign(Object.create(null), value.entitlements)),
    usageLimits: online.parseDefinitions(value.usage_limits, true),
    resourceLimits: online.parseDefinitions(value.resource_limits, false),
  });
}

function parseAccepted(value) {
  const reply = checkFields(value ? uniqueJson(value) : null, { accepted: (v) => typeof v === "boolean" });
  if (!reply.accepted) invalid("invalid_response");
  return reply;
}

function onlineOperationId(value) {
  return value === undefined ? randomBytes(24).toString("base64url") :
    online.requireInput(value, (v) => typeof v === "string" && /^[!-~]{16,128}$/.test(v));
}

function checkFields(value, fields, optional = []) {
  if (!isObject(value)) invalid("invalid_json");
  for (const name of Object.keys(value)) {
    if (!Object.hasOwn(fields, name) && !optional.includes(name)) invalid("invalid_json");
    if (Object.keys(fields).some((key) => key !== name && key.toLowerCase() === name.toLowerCase())) invalid("invalid_json");
  }
  const result = Object.create(null);
  for (const [name, predicate] of Object.entries(fields)) {
    if (!Object.hasOwn(value, name) && !optional.includes(name)) invalid("invalid_json");
    const item = Object.hasOwn(value, name) ? value[name] : null;
    if (!predicate(item)) invalid("invalid_json");
    result[name] = item;
  }
  return result;
}

function validBearer(value) {
  return typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value);
}

function validatePreviousCredential(value) {
  if (value !== undefined && value !== null && !validBearer(value)) {
    throw fail(ErrorKind.CONFIGURATION, "invalid_request");
  }
}

function validateOperationId(value) {
  if (value !== undefined && value !== null && (!isText(value, { min: 16, max: 128 }) || !value.isWellFormed())) {
    throw fail(ErrorKind.CONFIGURATION, "invalid_request");
  }
}

function validInput(value, max, empty) {
  return typeof value === "string" && value.isWellFormed() && Buffer.byteLength(value, "utf8") <= max && (empty || value.length > 0);
}

function validateFeature(value) {
  if (typeof value !== "string" || !/^[a-z][a-z0-9_]{0,63}$/.test(value)) throw fail(ErrorKind.CONFIGURATION, "invalid_feature");
}

function isString(value) {
  return typeof value === "string";
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function nextGeneration(value) {
  if (!isInteger(value, 0, MAX_GENERATION)) throw fail(ErrorKind.STORAGE, "storage_failed");
  return value + 1;
}

function throwIfAborted(signal) {
  if (signal?.aborted) throw fail(ErrorKind.CANCELLED, "operation_cancelled");
}

async function raceSignal(promise, signal) {
  throwIfAborted(signal);
  if (!signal) return promise;
  let abort;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      abort = () => reject(fail(ErrorKind.CANCELLED, "operation_cancelled"));
      signal.addEventListener("abort", abort, { once: true });
    })]);
  } finally {
    if (abort) signal.removeEventListener("abort", abort);
  }
}

function parseTokenKid(token) {
  const parts = token.split(".");
  if (parts.length !== 3) invalid();
  try {
    const header = uniqueJson(Buffer.from(parts[0], "base64url"));
    return typeof header.kid === "string" ? header.kid : "";
  } catch {
    return "";
  }
}

function singleJwks(keys, token) {
  const kid = parseTokenKid(token);
  const key = keys.get(kid);
  if (!key) invalid();
  const jwk = key.export({ format: "jwk" });
  return { keys: [{ kty: "EC", crv: "P-256", alg: "ES256", use: "sig", kid, x: jwk.x, y: jwk.y }] };
}

function invalid(code = "invalid_grant") {
  throw fail(ErrorKind.INVALID_RESPONSE, code);
}

function publicError(error) {
  return error?.kind ? Object.freeze({ kind: error.kind, code: error.code, requestId: error.requestId }) :
    Object.freeze({ kind: ErrorKind.INTERNAL, code: "operation_failed" });
}
