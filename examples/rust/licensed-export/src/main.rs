use orbit_sdk::{
    Cancellation, Client, Config, Device, PendingRegistration, Registration, Transport,
};
use std::io::{self, Write};

fn prompt(label: &str) -> io::Result<String> {
    print!("{label}");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_owned())
}
fn password_prompt() -> io::Result<String> {
    print!("Password (this console does not hide terminal input): ");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
    Ok(line)
}
const COMMANDS: &str = "Commands: activate, login, licences, more, select, claim, register, resend, recover, email, account-logout, status, export, deactivate, logout, quit";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let url = args
        .next()
        .ok_or("Usage: orbit-licensed-export URL APP_ID ENVIRONMENT_ID ISSUER [INSTALLATION_ID]")?;
    let application_id = args.next().ok_or("Missing app ID")?;
    let environment_id = args.next().ok_or("Missing environment ID")?;
    let issuer = args.next().ok_or("Missing configured issuer")?;
    let mut device = Device::new_installation()?;
    if let Some(id) = args.next() {
        device.installation_id = id;
    }
    if args.next().is_some() {
        return Err("Unexpected argument".into());
    }
    let transport = transport(&url)?;
    println!(
        "Installation ID: {} (public; reuse this ID after restart)",
        device.installation_id
    );
    println!(
        "This example keeps bearer credentials in memory. Use a protected Storage adapter in your application."
    );
    let client = Client::new(
        Config {
            application_id,
            environment_id,
            issuer,
        },
        device,
        transport,
    )?;
    let refresh_client = client.clone();
    let refresh = tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            if let Ok(state) = refresh_client.snapshot()
                && matches!(
                    state.access,
                    orbit_sdk::Access::RefreshRequired
                        | orbit_sdk::Access::Offline
                        | orbit_sdk::Access::Expired
                )
            {
                let _ = refresh_client
                    .require_access("export", &Cancellation::new())
                    .await;
            }
        }
    });
    let mut pending: Option<PendingRegistration> = None;
    let mut next_cursor: Option<String> = None;
    println!("{COMMANDS}");
    loop {
        match prompt("orbit> ")?.as_str() {
            "activate" => {
                let key =
                    prompt("Licence key (paste locally; never pass it on the command line): ")?;
                let operation = Device::new_installation()
                    .map_err(|error| terminal_error(&client, error))?
                    .installation_id;
                match client
                    .activate(&key, &operation, &Cancellation::new())
                    .await
                {
                    Ok(value) => println!("Access: {:?}", value.access),
                    Err(error) => report_error(&client, &error),
                }
            }
            "login" => {
                let username = prompt("Customer username: ")?;
                let password = password_prompt()?;
                next_cursor = None;
                match client
                    .login(&username, &password, &Cancellation::new())
                    .await
                {
                    Ok(account) => println!(
                        "Signed in as {}. Use licences and select before protected work.",
                        account.customer.username
                    ),
                    Err(error) => report_error(&client, &error),
                }
            }
            command @ ("licences" | "more") => {
                if command == "licences" {
                    next_cursor = None;
                }
                if command == "more" && next_cursor.is_none() {
                    println!("No next page. Use licences to start again.");
                    continue;
                }
                match client
                    .owned_licences(next_cursor.as_deref(), &Cancellation::new())
                    .await
                {
                    Ok(page) => {
                        if page.items.is_empty() {
                            println!("No owned licences. Use claim with an eligible key.");
                        }
                        for licence in page.items {
                            println!(
                                "{} | {} | {} | expires {}",
                                licence.id,
                                licence.policy_name,
                                licence.state,
                                licence
                                    .expires_at
                                    .as_deref()
                                    .unwrap_or("not started or perpetual")
                            );
                        }
                        next_cursor = page.next_cursor;
                        if next_cursor.is_some() {
                            println!("Use more for the next page.");
                        }
                    }
                    Err(error) => report_error(&client, &error),
                }
            }
            "select" => {
                let licence = prompt("Licence ID from licences: ")?;
                let operation = Device::new_installation()
                    .map_err(|error| terminal_error(&client, error))?
                    .installation_id;
                match client
                    .activate_account(&licence, &operation, &Cancellation::new())
                    .await
                {
                    Ok(value) => println!("Access: {:?}", value.access),
                    Err(error) => report_error(&client, &error),
                }
            }
            "claim" => {
                let key = prompt("Licence key to claim (paste locally): ")?;
                let operation = Device::new_installation()
                    .map_err(|error| terminal_error(&client, error))?
                    .installation_id;
                match client
                    .claim_licence(&key, &operation, &Cancellation::new())
                    .await
                {
                    Ok(licence) => {
                        println!("Claimed licence {}. Use select to activate it.", licence.id)
                    }
                    Err(error) => report_error(&client, &error),
                }
            }
            "register" => {
                let key = prompt("Licence key (paste locally): ")?;
                let username = prompt("New customer username: ")?;
                let email = prompt("Email address: ")?;
                println!("Customer passwords require at least 8 characters; spaces are preserved.");
                let password = password_prompt()?;
                match client
                    .register(
                        Registration {
                            licence_key: &key,
                            username: &username,
                            email: &email,
                            password: &password,
                        },
                        &Cancellation::new(),
                    )
                    .await
                {
                    Ok(value) => {
                        pending = Some(value);
                        println!(
                            "Request accepted. If eligible, confirm the email link, then return here and login. Use resend if needed."
                        );
                    }
                    Err(error) => report_error(&client, &error),
                }
            }
            "resend" => {
                if let Some(pending) = &pending {
                    match client
                        .resend_registration(pending, &Cancellation::new())
                        .await
                    {
                        Ok(()) => println!(
                            "Request accepted. Check your email if the pending registration is eligible."
                        ),
                        Err(error) => report_error(&client, &error),
                    }
                } else {
                    println!("Start registration in this process before requesting a resend.");
                }
            }
            "recover" => {
                let email = prompt("Customer email address: ")?;
                match client
                    .request_password_recovery(&email, &Cancellation::new())
                    .await
                {
                    Ok(()) => println!(
                        "Request accepted. If eligible, use the email link and then login again."
                    ),
                    Err(error) => report_error(&client, &error),
                }
            }
            "email" => {
                let email = prompt("New customer email address: ")?;
                let password = password_prompt()?;
                match client
                    .request_email_change(&password, &email, &Cancellation::new())
                    .await
                {
                    Ok(()) => {
                        println!("Confirm the links sent to both addresses, then login again.")
                    }
                    Err(error) => report_error(&client, &error),
                }
            }
            "account-logout" => {
                next_cursor = None;
                match client.logout_account(&Cancellation::new()).await {
                    Ok(()) => println!(
                        "Customer session signed out. Local access is cleared; occupied device slots remain."
                    ),
                    Err(error) => {
                        println!(
                            "Local access cleared; remote customer signout was not confirmed: {error}"
                        );
                        print_support(&client, &error);
                    }
                }
            }
            "status" => println!(
                "{:?}",
                client
                    .snapshot()
                    .map_err(|error| terminal_error(&client, error))?
            ),
            "export" => match client.require_access("export", &Cancellation::new()).await {
                Ok(_) => println!("Export authorized: synthetic report, rows=3, total=42"),
                Err(error) => {
                    println!("Export denied: {error}");
                    print_support(&client, &error);
                }
            },
            "deactivate" => match client
                .deactivate(
                    &Device::new_installation()
                        .map_err(|error| terminal_error(&client, error))?
                        .installation_id,
                    &Cancellation::new(),
                )
                .await
            {
                Ok(()) => {
                    println!("Device slot released; new activation follows the policy cooldown.")
                }
                Err(error) => {
                    println!("Local access cleared; server release was not confirmed: {error}");
                    print_support(&client, &error);
                }
            },
            "logout" => {
                client
                    .logout()
                    .map_err(|error| terminal_error(&client, error))?;
                pending = None;
                next_cursor = None;
                println!("Local access cleared. The server device slot remains occupied.");
            }
            "quit" | "" => break,
            _ => println!("{COMMANDS}"),
        }
    }
    client
        .logout()
        .map_err(|error| terminal_error(&client, error))?;
    refresh.abort();
    Ok(())
}
fn transport(url: &str) -> orbit_sdk::Result<Transport> {
    #[cfg(feature = "local-development")]
    if url.starts_with("http:") {
        return Transport::local_loopback(url);
    }
    Transport::new(url)
}

fn print_support(client: &Client, error: &orbit_sdk::Error) {
    println!("Support summary: {}", client.support_summary(error));
}

fn report_error(client: &Client, error: &orbit_sdk::Error) {
    println!("{error}");
    print_support(client, error);
}

fn terminal_error(client: &Client, error: orbit_sdk::Error) -> orbit_sdk::Error {
    eprintln!("Support summary: {}", client.support_summary(&error));
    error
}
