use orbit_sdk::{AppConfig, Cancellation, Client, Error};
use std::{
    io::{self, Write},
    path::Path,
};

fn prompt(label: &str) -> io::Result<String> {
    print!("{label}");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().into())
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let app = AppConfig {
        api_origin: args.next().ok_or(
            "Usage: orbit-licensed-export URL APP_ID ENVIRONMENT_ID ISSUER [STATE_DIRECTORY]",
        )?,
        application_id: args.next().ok_or("Missing application ID")?,
        environment_id: args.next().ok_or("Missing environment ID")?,
        issuer: args.next().ok_or("Missing grant issuer")?,
        fingerprint: None,
        fingerprint_provider: None,
    };
    let directory = args.next();
    if args.next().is_some() {
        return Err("Unexpected argument".into());
    }
    let client = open(app, directory.as_deref().map(Path::new)).await?;
    let result = run(&client).await;
    let closed = client.close().await;
    if let Err(error) = &result {
        eprintln!("{error}");
    }
    result?;
    closed?;
    Ok(())
}
async fn open(app: AppConfig, directory: Option<&Path>) -> orbit_sdk::Result<Client> {
    #[cfg(feature = "local-development")]
    if app.api_origin.starts_with("http:") {
        return Client::open_local(app, directory).await;
    }
    Client::open(app, directory).await
}
async fn run(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let cancel = Cancellation::new();
    match client.require_access("export", &cancel).await {
        Ok(_) => {}
        Err(Error::Denied { code, .. }) if code == "access_unavailable" => {
            let key = prompt("Licence key: ")?;
            client.activate_key(&key, &cancel).await?;
            client.require_access("export", &cancel).await?;
        }
        Err(error) => {
            eprintln!("Support summary: {}", client.support_summary(&error));
            return Err(error.into());
        }
    }
    println!("Activation is remembered. Commands: export, status, quit");
    loop {
        match prompt("orbit> ")?.as_str() {
            "export" => match client.require_access("export", &cancel).await {
                Ok(_) => println!("Export authorized: synthetic report, rows=3, total=42"),
                Err(error) => {
                    println!("Export denied: {error}");
                    println!("Support summary: {}", client.support_summary(&error));
                }
            },
            "status" => println!("{:?}", client.snapshot()?),
            "quit" | "" => break,
            _ => println!("Commands: export, status, quit"),
        }
    }
    Ok(())
}
