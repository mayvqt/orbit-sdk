using Orbit.Sdk;
using System.Text.Json;

const string commands = "Commands: activate, login, licences, more, select, claim, register, resend, recover, email, account-logout, status, export, deactivate, logout, quit";
var appKey = Environment.GetEnvironmentVariable("ORBIT_APP_KEY");
if (string.IsNullOrWhiteSpace(appKey))
{
    Console.Error.WriteLine("Set ORBIT_APP_KEY to the public app key copied from Orbit Integration.");
    return 2;
}

OrbitClient? supportClient = null;
try
{
    using var lifetime = new CancellationTokenSource();
    Console.CancelKeyPress += (_, cancel) => { cancel.Cancel = true; lifetime.Cancel(); };
    await using var client = await OrbitClient.OpenAsync(appKey, cancellationToken: lifetime.Token);
    supportClient = client;
    try
    {
        await client.EnsureAccessAsync("export",
            _ => ValueTask.FromResult<string?>(Prompt("Licence key (leave empty to use account commands): ")),
            lifetime.Token);
    }
    catch (OrbitException error) { Console.WriteLine(error.Message); PrintSupport(client, error, Console.Out); }
    Console.WriteLine(commands);
    RegistrationResult? pending = null;
    string? nextCursor = null;
    try
    {
        while (!lifetime.IsCancellationRequested)
        {
            var command = Prompt("orbit> ");
            if (command is "quit" or "")
                break;
            try
            {
                switch (command)
                {
                    case "activate":
                        {
                            var key = Prompt("Licence key (paste locally; never pass it on the command line): ");
                            var state = await client.ActivateAsync(key, cancellationToken: lifetime.Token);
                            Console.WriteLine($"Access: {state.Access}");
                            break;
                        }
                    case "login":
                        {
                            var username = Prompt("Customer username: ");
                            var password = PasswordPrompt();
                            nextCursor = null;
                            var account = await client.LoginAsync(username, password, lifetime.Token);
                            Console.WriteLine($"Signed in as {account.Customer.Username}. Use licences and select before protected work.");
                            break;
                        }
                    case "licences":
                    case "more":
                        {
                            if (command == "licences")
                                nextCursor = null;
                            if (command == "more" && nextCursor == null)
                            {
                                Console.WriteLine("No next page. Use licences to start again.");
                                break;
                            }
                            var page = await client.OwnedLicencesAsync(nextCursor, lifetime.Token);
                            if (page.Items.Count == 0)
                                Console.WriteLine("No owned licences. Use claim with an eligible key.");
                            foreach (var licence in page.Items)
                                Console.WriteLine($"{licence.Id} | {licence.PolicyName} | {licence.State} | expires {licence.ExpiresAt?.ToString("O") ?? "not started or perpetual"}");
                            nextCursor = page.NextCursor;
                            if (nextCursor != null)
                                Console.WriteLine("Use more for the next page.");
                            break;
                        }
                    case "select":
                        {
                            var licence = Prompt("Licence ID from licences: ");
                            var state = await client.ActivateAccountAsync(licence, cancellationToken: lifetime.Token);
                            Console.WriteLine($"Access: {state.Access}");
                            break;
                        }
                    case "claim":
                        {
                            var key = Prompt("Licence key to claim (paste locally): ");
                            var licence = await client.ClaimLicenceAsync(key, cancellationToken: lifetime.Token);
                            Console.WriteLine($"Claimed licence {licence.Id}. Use select to activate it.");
                            break;
                        }
                    case "register":
                        {
                            var key = Prompt("Licence key (paste locally): ");
                            var username = Prompt("New customer username: ");
                            var email = Prompt("Email address: ");
                            Console.WriteLine("Customer passwords require at least 8 characters; spaces are preserved.");
                            var password = PasswordPrompt();
                            pending = await client.RegisterAsync(new Registration(key, username, email, password), lifetime.Token);
                            Console.WriteLine("Request accepted. If eligible, confirm the email link, then return here and login. Use resend if needed.");
                            break;
                        }
                    case "resend":
                        if (pending == null)
                            Console.WriteLine("Start registration in this process before requesting a resend.");
                        else
                        {
                            await client.ResendRegistrationAsync(pending, lifetime.Token);
                            Console.WriteLine("Request accepted. Check your email if the pending registration is eligible.");
                        }
                        break;
                    case "recover":
                        await client.RequestPasswordRecoveryAsync(Prompt("Customer email address: "), lifetime.Token);
                        Console.WriteLine("Request accepted. If eligible, use the email link and then login again.");
                        break;
                    case "email":
                        {
                            var email = Prompt("New customer email address: ");
                            var password = PasswordPrompt();
                            await client.RequestEmailChangeAsync(password, email, lifetime.Token);
                            Console.WriteLine("Confirm the links sent to both addresses, then login again.");
                            break;
                        }
                    case "account-logout":
                        nextCursor = null;
                        try
                        {
                            await client.LogoutAccountAsync(lifetime.Token);
                            Console.WriteLine("Customer session signed out. Local access is cleared; occupied device slots remain.");
                        }
                        catch (OrbitException error) { Console.WriteLine($"Local access cleared; remote customer signout was not confirmed: {error.Message}"); PrintSupport(client, error, Console.Out); }
                        break;
                    case "status":
                        {
                            var state = client.Snapshot();
                            Console.WriteLine($"Access: {state.Access}; grant expiry: {state.ExpiresAt}; next check: {state.NextCheckAt}; credential expiry: {state.CredentialExpiresAt}; reauthentication required: {state.ReauthenticationRequired}; offline allowed: {state.OfflineAllowed}; offline time: {state.RemainingOffline}; storage: {client.StorageCapability}");
                            break;
                        }
                    case "export":
                        try
                        {
                            await client.RequireAccessAsync("export", lifetime.Token);
                            Console.WriteLine("Export authorized: synthetic report, rows=3, total=42");
                        }
                        catch (OrbitException error) { Console.WriteLine($"Export denied: {error.Message}"); PrintSupport(client, error, Console.Out); }
                        break;
                    case "deactivate":
                        try
                        {
                            await client.DeactivateAsync(cancellationToken: lifetime.Token);
                            Console.WriteLine("Device slot released.");
                        }
                        catch (OrbitException error) { Console.WriteLine($"Local access cleared; server release was not confirmed: {error.Message}"); PrintSupport(client, error, Console.Out); }
                        break;
                    case "logout":
                        client.Logout();
                        pending = null;
                        nextCursor = null;
                        Console.WriteLine("Local access cleared. The server device slot remains occupied.");
                        break;
                    default:
                        Console.WriteLine(commands);
                        break;
                }
            }
            catch (OrbitException error) { Console.WriteLine(error.Message); PrintSupport(client, error, Console.Out); }
        }
    }
    finally
    {
        lifetime.Cancel();

    }
    return 0;
}
catch (OrbitException error)
{
    Console.Error.WriteLine(error.Message);
    if (supportClient != null)
        PrintSupport(supportClient, error, Console.Error);
    return 1;
}
catch (IOException) { Console.Error.WriteLine("Console input/output failed"); return 1; }

static string Prompt(string label)
{
    Console.Write(label);
    return (Console.ReadLine() ?? "").Trim();
}

static string PasswordPrompt()
{
    Console.Write("Password (this console does not hide terminal input): ");
    return Console.ReadLine() ?? "";
}

static void PrintSupport(OrbitClient client, OrbitException error, TextWriter output) =>
    output.WriteLine("Support summary: " + JsonSerializer.Serialize(client.SupportSummary(error)));
