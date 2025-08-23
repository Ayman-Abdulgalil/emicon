// Prevent console window in addition to Slint window in Windows release builds when, e.g., starting the app via file manager. Ignored on other platforms.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod hibp;
mod shared;

use hibp::HibpClient;
use shared::Result;

// slint::include_modules!();

fn main() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let client = HibpClient::new(None, "emicon".to_string());

    let (breaches, pastes, d_breaches, passwords, breach, all_bs) = runtime.block_on(async {
        tokio::join!(
            client.check_breaches("account-exists@hibp-integration-tests.com"),
            client.check_pastes("account-exists@hibp-integration-tests.com"),
            client.check_domain("google.com"),
            client.check_password("123456789"),
            client.get_breach("IDK"),
            client.all_breaches()
        )
    });

    println!("Checking passwords");
    if let Some(no) = passwords? {
        println!(
            "Your password appeared {} times in the search results !",
            no
        );
    } else {
        println!("Your password didn't appear in the search results !");
    }

    println!("Checking domain breaches");
    match d_breaches {
        Ok(breach_vector) => {
            println!("Found {} breaches:", breach_vector.len());
            for breach in breach_vector {
                println!("- {} ({})", breach.title, breach.date);
            }
        }
        Err(e) => {
            return Err(e);
        }
    }

    println!("Checking breaches");
    match breaches {
        Ok(breach_vector) => {
            println!("Found {} breaches:", breach_vector.len());
            for breach in breach_vector {
                println!("- {} ({})", breach.title, breach.date);
            }
        }
        Err(e) => {
            return Err(e);
        }
    }

    println!("Checking pastes");
    match pastes {
        Ok(paste_vector) => {
            println!("Found {} breaches:", paste_vector.len());
            for paste in paste_vector {
                println!("- {} ({})", paste.title, paste.date);
            }
        }
        Err(e) => {
            return Err(e);
        }
    }

    println!("{}", breach?.title);
    println!("{}", all_bs?.len());
    // let ui = AppWindow::new()?;

    // ui.run()?;

    Ok(())
}
