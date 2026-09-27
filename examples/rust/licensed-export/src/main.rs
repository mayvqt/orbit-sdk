use orbit_sdk::Client;
use std::io::{self, Write};

fn prompt(label: &str) -> io::Result<String> {
    print!("{label}");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().into())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app_key = std::env::var("ORBIT_APP_KEY")?;
    #[cfg(feature = "local-development")]
    let client = Client::open_local(&app_key).await?;
    #[cfg(not(feature = "local-development"))]
    let client = Client::open(&app_key).await?;

    let result = run(&client).await;
    let closed = client.close().await;
    result?;
    closed?;
    Ok(())
}

async fn run(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    client
        .ensure_access("export", || prompt("Licence key: ").ok())
        .await?;
    println!(
        "Activation is remembered. Commands: export, metered-export, updates, download, idle, resume, status, quit"
    );
    loop {
        match prompt("orbit> ")?.as_str() {
            "export" => match client.require_access("export").await {
                Ok(_) => println!("Export authorized: synthetic report, rows=3, total=42"),
                Err(error) => {
                    println!("Export denied: {error}");
                    println!("Support summary: {}", client.support_summary(&error));
                }
            },
            "idle" => {
                client.end_session().await?;
            }
            "resume" => {
                client.start_session().await?;
            }
            "metered-export" => {
                client.require_access("export").await?;
                let job = prompt("Export job ID (16–128 characters; reuse for retries): ")?;
                match client.consume_with_id("exports", 1, &job).await {
                    Ok(result) => println!(
                        "Export authorized: synthetic report. Remaining exports: {}",
                        result.counter.remaining
                    ),
                    Err(error) => {
                        println!("Export denied: {}", error.cause);
                        if error.uncertain {
                            println!("Outcome unknown. Retry with the same job ID.");
                        }
                    }
                }
            }
            command @ ("updates" | "download") => {
                if let Some(update) = client.check_for_updates(0).await? {
                    println!("Update available: {}", update.release.version);
                    if command == "download" {
                        let destination = prompt("Destination file (must not already exist): ")?;
                        let authorization = client
                            .authorize_download(&update.release.id, &update.artifact.id)
                            .await?;
                        authorization
                            .download(destination, 128 * 1024 * 1024)
                            .await?;
                        println!("Verified download saved. No installer was executed.");
                    }
                } else {
                    println!("No eligible update for this target.");
                }
            }
            "status" => println!("{:?}", client.snapshot()?),
            "quit" | "" => break,
            _ => println!(
                "Commands: export, metered-export, updates, download, idle, resume, status, quit"
            ),
        }
    }
    Ok(())
}
