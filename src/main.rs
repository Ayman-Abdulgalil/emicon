// Prevent console window in addition to Slint window in Windows release builds when, e.g., starting the app via file manager. Ignored on other platforms.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod hibp;
mod shared;

use hibp::HibpClient;
use shared::EmiconResult;

// slint::include_modules!();

fn main() -> EmiconResult<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut client = HibpClient::new(None, "emicon".to_string(), 30)?;

    client.change_api_key(None)?;
    client.change_time_out(20)?;

    let (breache_names,
        breaches,
        pastes,
        passwords,
        breach,
        all_bs,
        substat,
        subdomains
    ) = runtime.block_on(async {
        tokio::join!(
            client.check_account_breach_names("account-exists@hibp-integration-tests.com"),
            client.check_account_breaches("account-exists@hibp-integration-tests.com"),
            client.check_account_paste("google.com"),
            client.check_password("123456789"),
            client.get_breach("Adobe"),
            client.get_all_breaches(None),
            client.get_subscription_status(),
            client.get_subscribed_domains()
        )
    });

    println!(" - {} passwords.", passwords?);
    println!(" - {}", breache_names?.len());
    println!(" - {}", breaches?.len());
    println!(" - {} pastes", pastes?.len());
    println!(" - {} breach found", breach?.title);
    println!(" - {} breaches", all_bs?.len());
    println!(" - subscription status: {}", substat?.sub_name);
    println!(" - subscribed domains: {}", subdomains?.len());


    // let ui = AppWindow::new()?;

    // ui.run()?;

    Ok(())
}
