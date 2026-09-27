//! Explicit online metering. Gate authoritative business work on your backend.
use crate::{Client, Device, Error, Result, access};
use serde_json::{Value, json};
use std::time::SystemTime;

pub(crate) const MAX_INTEGER: u64 = (1 << 53) - 1;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UsagePeriod {
    Day,
    Month,
    Lifetime,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsageCounter {
    pub name: String,
    pub period: UsagePeriod,
    pub limit: u64,
    pub used: u64,
    pub remaining: u64,
    pub period_started_at: Option<SystemTime>,
    pub resets_at: Option<SystemTime>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Consumption {
    pub counter: UsageCounter,
    pub operation_id: String,
    pub consumed_units: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceCounter {
    pub name: String,
    pub limit: u64,
    pub used: u64,
    pub remaining: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceState {
    Active,
    Released,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceAllocation {
    pub counter: ResourceCounter,
    pub operation_id: String,
    pub allocation_id: String,
    pub resource_id: String,
    pub units: u64,
    pub state: ResourceState,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CapacityCounter {
    Usage(UsageCounter),
    Resources(ResourceCounter),
}
/// Recover an uncertain mutation with the same operation ID and input.
#[derive(Clone)]
pub struct MutationError {
    pub operation_id: String,
    pub uncertain: bool,
    pub counter: Option<Box<CapacityCounter>>,
    pub cause: Error,
}
impl std::fmt::Display for MutationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Orbit mutation failed; retain its operation ID for recovery")
    }
}
impl std::fmt::Debug for MutationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for MutationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
pub type MutationResult<T> = std::result::Result<T, MutationError>;
fn failure(id: &str, cause: Error) -> MutationError {
    let uncertain = !matches!(
        cause,
        Error::Configuration
            | Error::NotActivated
            | Error::PendingActivation
            | Error::Denied { .. }
    );
    MutationError {
        operation_id: id.into(),
        uncertain,
        counter: None,
        cause,
    }
}
pub(crate) fn name(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}
pub(crate) fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(Error::InvalidResponse)
}
pub(crate) fn integer(value: &Value, key: &str) -> Result<u64> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .filter(|v| *v <= MAX_INTEGER)
        .ok_or(Error::InvalidResponse)
}
pub(crate) fn exact(value: &Value, keys: &[&str]) -> Result<()> {
    let map = value.as_object().ok_or(Error::InvalidResponse)?;
    if map.len() != keys.len() || keys.iter().any(|key| !map.contains_key(*key)) {
        return Err(Error::InvalidResponse);
    }
    Ok(())
}
pub(crate) fn date(value: &Value, key: &str) -> Result<SystemTime> {
    let raw = text(value, key)?;
    let time = time::OffsetDateTime::parse(raw, &time::format_description::well_known::Rfc3339)
        .map_err(|_| Error::InvalidResponse)?;
    if time.offset() != time::UtcOffset::UTC || !(0..=253402300799).contains(&time.unix_timestamp())
    {
        return Err(Error::InvalidResponse);
    }
    crate::accounts::from_unix_seconds(time.unix_timestamp()).ok_or(Error::InvalidResponse)
}
fn optional_date(value: &Value, key: &str) -> Result<Option<SystemTime>> {
    match value.get(key) {
        Some(Value::Null) => Ok(None),
        Some(_) => date(value, key).map(Some),
        None => Err(Error::InvalidResponse),
    }
}
fn counter(value: &Value, expected: &str) -> Result<ResourceCounter> {
    let actual = text(value, "name")?;
    let limit = integer(value, "limit")?;
    let used = integer(value, "used")?;
    let remaining = integer(value, "remaining")?;
    if actual != expected || !name(actual) || used > limit || remaining != limit - used {
        return Err(Error::InvalidResponse);
    }
    Ok(ResourceCounter {
        name: actual.into(),
        limit,
        used,
        remaining,
    })
}
fn usage(value: &Value, expected: &str) -> Result<UsageCounter> {
    let counter = counter(value, expected)?;
    let period = match text(value, "period")? {
        "day" => UsagePeriod::Day,
        "month" => UsagePeriod::Month,
        "lifetime" => UsagePeriod::Lifetime,
        _ => return Err(Error::InvalidResponse),
    };
    let started = optional_date(value, "period_started_at")?;
    let resets = optional_date(value, "resets_at")?;
    match (period, started, resets) {
        (UsagePeriod::Lifetime, None, None) => {}
        (UsagePeriod::Day | UsagePeriod::Month, Some(start), Some(end)) if end > start => {}
        _ => return Err(Error::InvalidResponse),
    }
    Ok(UsageCounter {
        name: counter.name,
        period,
        limit: counter.limit,
        used: counter.used,
        remaining: counter.remaining,
        period_started_at: started,
        resets_at: resets,
    })
}
fn operation_id(id: Option<&str>) -> Result<String> {
    match id {
        Some(id) if access::valid_operation_id(id) => Ok(id.into()),
        Some(_) => Err(Error::Configuration),
        None => Ok(Device::new_installation()?.installation_id),
    }
}
fn denial(value: &Value, expected: &str, id: &str, units: u64, resource: bool) -> MutationError {
    let parsed = (|| -> Result<MutationError> {
        let error = value.get("error").ok_or(Error::InvalidResponse)?;
        let code = text(error, "code")?;
        let request_id = text(error, "request_id")?;
        if code
            != if resource {
                "resource_limit_reached"
            } else {
                "usage_limit_reached"
            }
            || text(error, "message")?.is_empty()
            || !crate::diagnostics::valid_request_id(request_id)
            || text(error, "idempotency_key")? != id
            || integer(error, "requested_units")? != units
        {
            return Err(Error::InvalidResponse);
        }
        let details = error.get("counter").ok_or(Error::InvalidResponse)?;
        let counter = if resource {
            CapacityCounter::Resources(counter(details, expected)?)
        } else {
            CapacityCounter::Usage(usage(details, expected)?)
        };
        let remaining = match &counter {
            CapacityCounter::Resources(value) => value.remaining,
            CapacityCounter::Usage(value) => value.remaining,
        };
        if units <= remaining {
            return Err(Error::InvalidResponse);
        }
        Ok(MutationError {
            operation_id: id.into(),
            uncertain: false,
            counter: Some(Box::new(counter)),
            cause: Error::Denied {
                code: code.into(),
                request_id: Some(request_id.into()),
            },
        })
    })();
    parsed.unwrap_or_else(|cause| failure(id, cause))
}
fn allocation(
    value: Value,
    expected: &str,
    resource: Option<&str>,
    allocation: Option<&str>,
    units: Option<u64>,
    id: &str,
    release: bool,
) -> MutationResult<ResourceAllocation> {
    let result = (|| -> Result<ResourceAllocation> {
        let counter = counter(&value, expected)?;
        let operation = text(&value, "idempotency_key")?;
        let resource_id = text(&value, "resource_id")?;
        let allocation_id = text(&value, "allocation_id")?;
        let count = integer(&value, "units")?;
        let state = match text(&value, "state")? {
            "active" => ResourceState::Active,
            "released" => ResourceState::Released,
            _ => return Err(Error::InvalidResponse),
        };
        if operation != id
            || !access::opaque(resource_id)
            || !access::opaque(allocation_id)
            || count == 0
            || resource.is_some_and(|v| v != resource_id)
            || allocation.is_some_and(|v| v != allocation_id)
            || units.is_some_and(|v| v != count)
            || state == ResourceState::Active && count > counter.used
            || release && state != ResourceState::Released
        {
            return Err(Error::InvalidResponse);
        }
        Ok(ResourceAllocation {
            counter,
            operation_id: id.into(),
            resource_id: resource_id.into(),
            allocation_id: allocation_id.into(),
            units: count,
            state,
        })
    })();
    result.map_err(|error| failure(id, error))
}
pub(crate) fn service_route(path: &str) -> bool {
    path.starts_with("/api/client/v1/activations/")
        && (path.contains("/usage/")
            || path.contains("/resources/")
            || path.ends_with("/updates")
            || path.ends_with("/downloads/authorize"))
}
impl Client {
    pub(crate) async fn online_service(&self, suffix: &str, extra: Value) -> Result<Value> {
        let (saved, generation, mut body) = {
            let mut state = self.0.state.lock().map_err(|_| Error::Storage)?;
            self.sync_storage(&mut state)?;
            if self.0.transport.owner_cancel.is_cancelled() {
                return Err(Error::Cancelled);
            }
            if state
                .offline
                .as_ref()
                .is_some_and(|offline| offline.authorized)
            {
                return Err(Error::Denied {
                    code: "online_required".into(),
                    request_id: None,
                });
            }
            if let Some(storage) = &self.0.installed
                && storage.activation_pending()?
            {
                return Err(Error::PendingActivation);
            }
            let saved = state.credential.clone().ok_or(Error::NotActivated)?;
            let body = json!({"application_id":self.0.config.application_id,"environment_id":self.0.config.environment_id,"credential":saved.credential,"installation_id":self.0.device.installation_id,"fingerprint":self.0.device.fingerprint,"fingerprint_provider":self.0.device.fingerprint_provider});
            (saved, state.generation, body)
        };
        if let Some(extra) = extra.as_object() {
            body.as_object_mut()
                .ok_or(Error::Configuration)?
                .extend(extra.clone());
        }
        let result = self
            .0
            .transport
            .post(
                &format!("/api/client/v1/activations/{}{suffix}", saved.activation_id),
                &body,
                true,
            )
            .await;
        self.check_generation(generation)?;
        if self.0.transport.owner_cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        result?.ok_or(Error::InvalidResponse)
    }
    pub async fn usage(&self, name: &str) -> Result<UsageCounter> {
        if !self::name(name) {
            return Err(Error::Configuration);
        }
        usage(
            &self
                .online_service(&format!("/usage/{name}"), json!({}))
                .await?,
            name,
        )
    }
    pub async fn resources(&self, name: &str) -> Result<ResourceCounter> {
        if !self::name(name) {
            return Err(Error::Configuration);
        }
        counter(
            &self
                .online_service(&format!("/resources/{name}"), json!({}))
                .await?,
            name,
        )
    }
    pub async fn consume(&self, name: &str, units: u64) -> MutationResult<Consumption> {
        self.consume_optional(name, units, None).await
    }
    pub async fn consume_with_id(
        &self,
        name: &str,
        units: u64,
        id: &str,
    ) -> MutationResult<Consumption> {
        self.consume_optional(name, units, Some(id)).await
    }
    async fn consume_optional(
        &self,
        name: &str,
        units: u64,
        id: Option<&str>,
    ) -> MutationResult<Consumption> {
        let id = operation_id(id).map_err(|error| failure(id.unwrap_or(""), error))?;
        if !self::name(name) || units == 0 || units > MAX_INTEGER {
            return Err(failure(&id, Error::Configuration));
        }
        let value = self
            .online_service(
                &format!("/usage/{name}/consume"),
                json!({"units":units,"idempotency_key":id}),
            )
            .await
            .map_err(|error| failure(&id, error))?;
        if value.get("error").is_some() {
            return Err(denial(&value, name, &id, units, false));
        }
        let result = (|| -> Result<Consumption> {
            let counter = usage(&value, name)?;
            if text(&value, "idempotency_key")? != id
                || integer(&value, "consumed_units")? != units
                || counter.used < units
            {
                return Err(Error::InvalidResponse);
            }
            Ok(Consumption {
                counter,
                operation_id: id.clone(),
                consumed_units: units,
            })
        })();
        result.map_err(|error| failure(&id, error))
    }
    pub async fn acquire_resource(
        &self,
        name: &str,
        resource: &str,
        units: u64,
    ) -> MutationResult<ResourceAllocation> {
        self.acquire_optional(name, resource, units, None).await
    }
    pub async fn acquire_resource_with_id(
        &self,
        name: &str,
        resource: &str,
        units: u64,
        id: &str,
    ) -> MutationResult<ResourceAllocation> {
        self.acquire_optional(name, resource, units, Some(id)).await
    }
    async fn acquire_optional(
        &self,
        name: &str,
        resource: &str,
        units: u64,
        id: Option<&str>,
    ) -> MutationResult<ResourceAllocation> {
        let id = operation_id(id).map_err(|error| failure(id.unwrap_or(""), error))?;
        if !self::name(name) || !access::opaque(resource) || units == 0 || units > MAX_INTEGER {
            return Err(failure(&id, Error::Configuration));
        }
        let value = self
            .online_service(
                &format!("/resources/{name}/acquire"),
                json!({"resource_id":resource,"units":units,"idempotency_key":id}),
            )
            .await
            .map_err(|error| failure(&id, error))?;
        if value.get("error").is_some() {
            return Err(denial(&value, name, &id, units, true));
        }
        allocation(value, name, Some(resource), None, Some(units), &id, false)
    }
    pub async fn release_resource(
        &self,
        name: &str,
        allocation: &str,
    ) -> MutationResult<ResourceAllocation> {
        self.release_optional(name, allocation, None).await
    }
    pub async fn release_resource_with_id(
        &self,
        name: &str,
        allocation: &str,
        id: &str,
    ) -> MutationResult<ResourceAllocation> {
        self.release_optional(name, allocation, Some(id)).await
    }
    async fn release_optional(
        &self,
        name: &str,
        allocation_id: &str,
        id: Option<&str>,
    ) -> MutationResult<ResourceAllocation> {
        let id = operation_id(id).map_err(|error| failure(id.unwrap_or(""), error))?;
        if !self::name(name) || !access::opaque(allocation_id) {
            return Err(failure(&id, Error::Configuration));
        }
        let value = self
            .online_service(
                &format!("/resources/{name}/allocations/{allocation_id}/release"),
                json!({"idempotency_key":id}),
            )
            .await
            .map_err(|error| failure(&id, error))?;
        allocation(value, name, None, Some(allocation_id), None, &id, true)
    }
}

#[cfg(all(test, feature = "local-development"))]
pub(crate) mod tests {
    use super::*;
    use crate::{Config, MemoryStorage, Storage, StoredCredential, Transport};
    use std::sync::Arc;
    pub(crate) fn client(transport: Transport) -> Client {
        let storage = Arc::new(MemoryStorage::default());
        storage
            .save(
                0,
                StoredCredential {
                    application_id: "app".into(),
                    environment_id: "test".into(),
                    activation_id: "activation".into(),
                    licence_id: "licence".into(),
                    installation_id: "installation_123456".into(),
                    credential: "a".repeat(43),
                    credential_expires_at: None,
                    fingerprint: None,
                    fingerprint_provider: None,
                },
            )
            .unwrap();
        Client::with_storage(
            Config {
                application_id: "app".into(),
                environment_id: "test".into(),
                issuer: "https://orbit.example.test".into(),
            },
            Device {
                installation_id: "installation_123456".into(),
                fingerprint: None,
                fingerprint_provider: None,
            },
            transport,
            storage,
        )
        .unwrap()
    }
    fn usage_counter() -> Value {
        json!({"name":"exports","period":"lifetime","limit":10,"used":2,"remaining":8,"period_started_at":null,"resets_at":null})
    }
    #[tokio::test]
    async fn consume_retries_exact_proof_and_generated_operation() {
        let mut fixture = crate::transport::tests::Fixture::new().await;
        let client = client(fixture.transport.clone());
        let consuming = client.clone();
        let task = tokio::spawn(async move { consuming.consume("exports", 2).await });
        let first = fixture.next().await;
        let body = first.body.clone();
        let input: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(input["credential"], "a".repeat(43));
        assert_eq!(input["installation_id"], "installation_123456");
        first.respond(503,r#"{"error":{"code":"service_unavailable","message":"Unavailable","request_id":"request"}}"#);
        let retry = fixture.next().await;
        assert_eq!(retry.body, body);
        let mut reply = usage_counter();
        reply["idempotency_key"] = input["idempotency_key"].clone();
        reply["consumed_units"] = json!(2);
        retry.respond(200, &reply.to_string());
        let result = task.await.unwrap().unwrap();
        assert_eq!(result.counter.used, 2);
        assert_eq!(
            result.operation_id,
            input["idempotency_key"].as_str().unwrap()
        );
        fixture.assert_idle();
    }
    #[tokio::test]
    async fn capacity_denial_checks_counter_and_operation_before_exposing_details() {
        for corrupt in [
            "",
            "name",
            "remaining",
            "operation",
            "units",
            "status",
            "duplicate",
        ] {
            let mut fixture = crate::transport::tests::Fixture::new().await;
            let client = client(fixture.transport.clone());
            let task = tokio::spawn(async move {
                client
                    .consume_with_id("exports", 2, "job_1234567890123456")
                    .await
            });
            let request = fixture.next().await;
            let mut counter = usage_counter();
            counter["used"] = json!(10);
            counter["remaining"] = json!(0);
            let mut reply = json!({"error":{"code":"usage_limit_reached","message":"Denied","request_id":"request","counter":counter,"idempotency_key":"job_1234567890123456","requested_units":2}});
            let mut status = 409;
            match corrupt {
                "name" => reply["error"]["counter"]["name"] = json!("other"),
                "remaining" => reply["error"]["counter"]["remaining"] = json!(1),
                "operation" => reply["error"]["idempotency_key"] = json!("other_id"),
                "units" => reply["error"]["requested_units"] = json!(true),
                "status" => status = 201,
                _ => {}
            }
            let mut body = reply.to_string();
            if corrupt == "duplicate" {
                body = body.replace("\"used\":10", "\"used\":10,\"used\":10");
            }
            request.respond(status, &body);
            let error = task.await.unwrap().unwrap_err();
            assert_eq!(error.operation_id, "job_1234567890123456");
            if corrupt.is_empty() {
                assert!(!error.uncertain);
                assert!(matches!(
                    error.counter.as_deref(),
                    Some(CapacityCounter::Usage(_))
                ));
            } else {
                assert!(error.uncertain, "{corrupt}");
                assert!(error.counter.is_none());
                assert!(matches!(error.cause, Error::InvalidResponse));
            }
        }
    }
    #[tokio::test]
    async fn resource_replay_keeps_released_identity_and_current_counter() {
        let mut fixture = crate::transport::tests::Fixture::new().await;
        let client = client(fixture.transport.clone());
        let task = tokio::spawn(async move {
            client
                .acquire_resource_with_id("projects", "project_one", 2, "job_1234567890123456")
                .await
        });
        fixture.next().await.respond(200,r#"{"name":"projects","limit":5,"used":1,"remaining":4,"allocation_id":"old_allocation","resource_id":"project_one","units":2,"state":"released","idempotency_key":"job_1234567890123456"}"#);
        let result = task.await.unwrap().unwrap();
        assert_eq!(result.state, ResourceState::Released);
        assert_eq!(result.counter.used, 1);
    }
    #[tokio::test]
    async fn impossible_metering_outcomes_remain_uncertain() {
        const ID: &str = "job_1234567890123456";
        for resource in [false, true] {
            for denied in [false, true] {
                let mut fixture = crate::transport::tests::Fixture::new().await;
                let client = client(fixture.transport.clone());
                let task = tokio::spawn(async move {
                    if resource {
                        client
                            .acquire_resource_with_id("projects", "project", 2, ID)
                            .await
                            .map(|_| ())
                    } else {
                        client.consume_with_id("exports", 2, ID).await.map(|_| ())
                    }
                });
                let request = fixture.next().await;
                let mut counter = if resource {
                    json!({"name":"projects", "limit":10, "used":0, "remaining":10})
                } else {
                    let mut value = usage_counter();
                    value["used"] = json!(0);
                    value["remaining"] = json!(10);
                    value
                };
                let status = if denied { 409 } else { 200 };
                let reply = if denied {
                    let code = if resource {
                        "resource_limit_reached"
                    } else {
                        "usage_limit_reached"
                    };
                    json!({"error":{"code":code,"message":"Denied","request_id":"request","counter":counter,"idempotency_key":ID,"requested_units":2}})
                } else {
                    counter["idempotency_key"] = json!(ID);
                    if resource {
                        counter["allocation_id"] = json!("allocation");
                        counter["resource_id"] = json!("project");
                        counter["units"] = json!(2);
                        counter["state"] = json!("active");
                    } else {
                        counter["consumed_units"] = json!(2);
                    }
                    counter
                };
                request.respond(status, &reply.to_string());
                let error = task.await.unwrap().unwrap_err();
                assert!(error.uncertain, "resource={resource} denied={denied}");
                assert_eq!(error.operation_id, ID);
                assert!(error.counter.is_none());
                assert!(matches!(error.cause, Error::InvalidResponse));
            }
        }
    }
    #[tokio::test]
    async fn cancellation_preserves_uncertain_operation_and_fences_late_result() {
        let mut fixture = crate::transport::tests::Fixture::new().await;
        let client = client(fixture.transport.clone());
        let consuming = client.clone();
        let task = tokio::spawn(async move {
            consuming
                .consume_with_id("exports", 2, "job_1234567890123456")
                .await
        });
        let request = fixture.next().await;
        client.0.transport.owner_cancel.cancel();
        let error = task.await.unwrap().unwrap_err();
        assert!(error.uncertain);
        assert_eq!(error.operation_id, "job_1234567890123456");
        assert!(matches!(error.cause, Error::Cancelled));
        drop(request);
    }
}

/// Immutable policy metadata; online counter results authorize capacity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsageLimit {
    pub limit: u64,
    pub period: UsagePeriod,
    pub required_feature: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceLimit {
    pub limit: u64,
    pub required_feature: Option<String>,
}
fn feature(value: &Value) -> Result<Option<String>> {
    match value.get("required_feature") {
        Some(Value::Null) => Ok(None),
        Some(Value::String(v)) if name(v) => Ok(Some(v.clone())),
        _ => Err(Error::InvalidResponse),
    }
}
pub(crate) fn deserialize_usage_limits<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<std::collections::BTreeMap<String, UsageLimit>, D::Error> {
    use serde::Deserialize;
    let value = Value::deserialize(deserializer)?;
    let parsed = (|| -> Result<std::collections::BTreeMap<String, UsageLimit>> {
        let map = value.as_object().ok_or(Error::InvalidResponse)?;
        if map.len() > 32 {
            return Err(Error::InvalidResponse);
        }
        map.iter()
            .map(|(key, value)| {
                if !name(key) {
                    return Err(Error::InvalidResponse);
                }
                exact(value, &["limit", "period", "required_feature"])?;
                let period = match text(value, "period")? {
                    "day" => UsagePeriod::Day,
                    "month" => UsagePeriod::Month,
                    "lifetime" => UsagePeriod::Lifetime,
                    _ => return Err(Error::InvalidResponse),
                };
                Ok((
                    key.clone(),
                    UsageLimit {
                        limit: integer(value, "limit")?,
                        period,
                        required_feature: feature(value)?,
                    },
                ))
            })
            .collect()
    })();
    parsed.map_err(serde::de::Error::custom)
}
pub(crate) fn deserialize_resource_limits<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<std::collections::BTreeMap<String, ResourceLimit>, D::Error> {
    use serde::Deserialize;
    let value = Value::deserialize(deserializer)?;
    let parsed = (|| -> Result<std::collections::BTreeMap<String, ResourceLimit>> {
        let map = value.as_object().ok_or(Error::InvalidResponse)?;
        if map.len() > 32 {
            return Err(Error::InvalidResponse);
        }
        map.iter()
            .map(|(key, value)| {
                if !name(key) {
                    return Err(Error::InvalidResponse);
                }
                exact(value, &["limit", "required_feature"])?;
                Ok((
                    key.clone(),
                    ResourceLimit {
                        limit: integer(value, "limit")?,
                        required_feature: feature(value)?,
                    },
                ))
            })
            .collect()
    })();
    parsed.map_err(serde::de::Error::custom)
}
