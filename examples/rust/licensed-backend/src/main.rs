mod config;
mod orbit;

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Request, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::Response,
    routing::post,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{path::Path, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::Semaphore};

struct App {
    orbit: orbit::Orbit,
    requests: Semaphore,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Export {
    licence_id: String,
    activation_id: String,
}

type Error = (StatusCode, &'static str);

async fn export(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    body: Result<Json<Export>, JsonRejection>,
) -> Result<Json<Value>, Error> {
    let _permit = app
        .requests
        .try_acquire()
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "Try again later"))?;
    if headers.get_all(header::AUTHORIZATION).iter().count() != 1 {
        return Err((StatusCode::UNAUTHORIZED, "Customer authentication required"));
    }
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|v| v.len() == 43 && config::opaque(v))
        .ok_or((StatusCode::UNAUTHORIZED, "Customer authentication required"))?;
    let Json(input) =
        body.map_err(|_| (StatusCode::UNPROCESSABLE_ENTITY, "Invalid export request"))?;
    if !config::opaque(&input.licence_id) || !config::opaque(&input.activation_id) {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "Invalid export request"));
    }
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        app.orbit
            .authorize(token, &input.licence_id, &input.activation_id),
    )
    .await
    .map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Authentication service unavailable",
        )
    })?;
    let customer = result.map_err(|error| match error {
        orbit::Failure::Authentication => {
            (StatusCode::UNAUTHORIZED, "Customer authentication required")
        }
        orbit::Failure::Denied => (StatusCode::FORBIDDEN, "Export is not permitted"),
        orbit::Failure::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Authentication service unavailable",
        ),
    })?;
    // Replace this with the real server-side operation, restricting stored data
    // by this derived customer ID. No caller-provided customer ID is trusted.
    Ok(Json(
        json!({"customer_id":customer,"result":"Export completed"}),
    ))
}

async fn no_store(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

async fn run() -> Result<(), &'static str> {
    let mut args = std::env::args_os().skip(1);
    let path = args
        .next()
        .ok_or("Usage: orbit-licensed-backend PRIVATE_CONFIG_FILE")?;
    if args.next().is_some() {
        return Err("Usage: orbit-licensed-backend PRIVATE_CONFIG_FILE");
    }
    let config = config::load(Path::new(&path))?;
    let port = config.port;
    let orbit = orbit::Orbit::new(config)?;
    let app = Router::new()
        .route("/export", post(export))
        .layer(DefaultBodyLimit::max(1024))
        .layer(middleware::from_fn(no_store))
        .with_state(Arc::new(App {
            orbit,
            requests: Semaphore::new(16),
        }));
    // Public hosting belongs behind the developer's HTTPS reverse proxy.
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .map_err(|_| "Cannot bind listener")?;
    let address = listener
        .local_addr()
        .map_err(|_| "Cannot inspect listener")?;
    println!("{}", json!({"listening":address.to_string()}));
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(|_| "Backend stopped unexpectedly")
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}
