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
    if let Err(error) = &result {
        eprintln!("{error}");
    }
    result?;
    closed?;
    Ok(())
}

async fn run(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    client
        .ensure_access("export", || prompt("Licence key: ").ok())
        .await?;
    println!("Activation is remembered. Commands: export, status, quit");
    loop {
        match prompt("orbit> ")?.as_str() {
            "export" => match client.require_access("export").await {
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
