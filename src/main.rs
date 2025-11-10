#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

slint::include_modules!();

mod hibp;

use hibp::{HibpClient, HibpError};
use slint::{ModelRc, SharedString, VecModel};
use std::cell::RefCell;
use std::io;
use std::rc::Rc;
use tokio::runtime::Runtime;

#[derive(Debug, thiserror::Error)]
enum WrapperError {
    #[error(transparent)]
    HibpError(#[from] hibp::HibpError),
    #[error("Slint Error: {0}")]
    SlintError(#[from] slint::PlatformError),
    #[error("JSON parsing failed: {0}")]
    JsonParseError(#[from] serde_json::Error),
    #[error(transparent)]
    IoError(#[from] io::Error),
}

type WrapperResult<T> = std::result::Result<T, WrapperError>;

fn remove_tags(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut inside_tag = false;

    for ch in input.chars() {
        match ch {
            '<' => inside_tag = true,
            '>' => inside_tag = false,
            _ => {
                if !inside_tag {
                    result.push(ch);
                }
            }
        }
    }

    result
}

fn main() -> WrapperResult<()> {
    let ui = MainWindow::new()?;

    // Wrap client and runtime in Rc<RefCell<>> for shared mutable access across closures
    let client = Rc::new(RefCell::new(HibpClient::new(
        "HibpWrapper".to_string(),
        20,
    )?));
    let runtime = Rc::new(Runtime::new()?);

    // Handler for email breach lookup
    {
        let ui_weak = ui.as_weak();
        let client_clone = Rc::clone(&client);
        let runtime_clone = Rc::clone(&runtime);

        ui.on_submit_e_breach(move |email, api_key| {
            let ui = match ui_weak.upgrade() {
                Some(ui) => ui,
                None => return,
            };

            let email_str = email.as_str();
            let key_str = api_key.as_str();

            // Update API key if changed
            {
                let mut client_ref = client_clone.borrow_mut();

                client_ref.change_api_key(key_str.to_string());
            }

            // Fetch breaches
            let fut = {
                let client_ref = client_clone.borrow();
                runtime_clone.block_on(async { client_ref.get_account_breaches(email_str).await })
            };

            match fut {
                Ok(breaches) => {
                    let slint_breaches: Vec<Breach> = breaches
                        .iter()
                        .map(|b| Breach {
                            name: SharedString::from(&b.name),
                            domain: SharedString::from(&b.domain),
                            pwn_count: b.pwn_count as i32,
                            description: SharedString::from(&remove_tags(b.description.as_str())),
                            breach_date: SharedString::from(&b.breach_date.to_string()),
                            data_classes: ModelRc::new(VecModel::from(
                                b.data_classes
                                    .iter()
                                    .map(|dc| SharedString::from(dc))
                                    .collect::<Vec<_>>(),
                            )),
                        })
                        .collect();

                    ui.set_successful(true);
                    ui.set_breaches(ModelRc::new(VecModel::from(slint_breaches)));
                }
                Err(err) => match err {
                    HibpError::NotFound => {
                        ui.set_successful(true);
                        ui.set_breaches(ModelRc::new(VecModel::from(Vec::new())))
                    }
                    _ => {
                        ui.set_successful(false);
                        ui.set_overlay_message(SharedString::from(format!("HIBP is now dealing with a service issue\nBoth email breach and email pastes endpoints are down, but should comeback shortly")));
                        ui.set_overlay_title(SharedString::from("Error!"));
                    }
                },
            }
        });
    }

    // Handler for email pastes lookup
    {
        let ui_weak = ui.as_weak();
        let client_clone = Rc::clone(&client);
        let runtime_clone = Rc::clone(&runtime);

        ui.on_submit_e_pastes(move |email, api_key| {
            let ui = match ui_weak.upgrade() {
                Some(ui) => ui,
                None => return,
            };

            let email_str = email.as_str();
            let key_str = api_key.as_str();

            // Update API key if changed
            {
                let mut client_ref = client_clone.borrow_mut();
                client_ref.change_api_key(key_str.to_string());
            }

            // Fetch pastes
            let fut = {
                let client_ref = client_clone.borrow();
                runtime_clone.block_on(async { client_ref.get_account_pastes(email_str).await })
            };

            match fut {
                Ok(pastes) => {
                    let slint_pastes: Vec<Paste> = pastes
                        .iter()
                        .map(|p| Paste {
                            title: SharedString::from(p.title.as_deref().unwrap_or("")),
                            date: SharedString::from(
                                &p.date.unwrap_or_else(chrono::Utc::now).to_string(),
                            ),
                            pasteId: SharedString::from(p.id.as_deref().unwrap_or("")),
                            emailCount: p.email_count.unwrap_or(0) as i32,
                            source: SharedString::from(p.source.as_deref().unwrap_or("")),
                        })
                        .collect();

                    ui.set_successful(true);
                    ui.set_pastes(ModelRc::new(VecModel::from(slint_pastes)));
                }
                Err(err) => match err {
                    HibpError::NotFound => {
                        ui.set_successful(true);
                        ui.set_pastes(ModelRc::new(VecModel::from(Vec::new())))
                    }
                    _ => {
                        ui.set_successful(false);
                        ui.set_overlay_message(SharedString::from(format!("HIBP is now dealing with a service issue\nBoth email breach and email pastes endpoints are down, but should comeback shortly")));
                        ui.set_overlay_title(SharedString::from("Error!"));
                    }
                },
            }
        });
    }

    // Handler for password check
    {
        let ui_weak = ui.as_weak();
        let client_clone = Rc::clone(&client);
        let runtime_clone = Rc::clone(&runtime);

        ui.on_submit_password(move |password| {
            let ui = match ui_weak.upgrade() {
                Some(ui) => ui,
                None => return,
            };

            let password_str = password.as_str();

            let fut = {
                let client_ref = client_clone.borrow();
                runtime_clone.block_on(async { client_ref.check_password(password_str).await })
            };

            match fut {
                Ok(count) => {
                    ui.set_successful(true);
                    ui.set_password_count(count as i32);
                }
                Err(e) => {
                    ui.set_successful(false);
                    ui.set_overlay_message(SharedString::from(format!("Error: {}", e)));
                    ui.set_overlay_title(SharedString::from("Error!"));
                }
            }
        });
    }

    // Handler for single breach lookup
    {
        let ui_weak = ui.as_weak();
        let client_clone = Rc::clone(&client);
        let runtime_clone = Rc::clone(&runtime);

        ui.on_submit_breach(move |breach_name| {
            let ui = match ui_weak.upgrade() {
                Some(ui) => ui,
                None => return,
            };

            let name_str = breach_name.as_str();

            // Fetch breach data
            let fut = {
                let client_ref = client_clone.borrow();
                runtime_clone.block_on(async { client_ref.get_breach(name_str).await })
            };

            match fut {
                Ok(breach_data) => {
                    let breach = Breach {
                        name: SharedString::from(&breach_data.name),
                        domain: SharedString::from(&breach_data.domain),
                        pwn_count: breach_data.pwn_count as i32,
                        description: SharedString::from(&remove_tags(
                            breach_data.description.as_str(),
                        )),
                        breach_date: SharedString::from(&breach_data.breach_date.to_string()),
                        data_classes: ModelRc::new(VecModel::from(
                            breach_data
                                .data_classes
                                .iter()
                                .map(|dc| SharedString::from(dc))
                                .collect::<Vec<_>>(),
                        )),
                    };

                    ui.set_successful(true);
                    ui.set_breach(breach);
                }
                Err(e) => {
                    ui.set_successful(false);
                    ui.set_overlay_message(SharedString::from(format!("Error: {}", e)));
                    ui.set_overlay_title(SharedString::from("Error!"));
                }
            }
        });
    }

    // Handler for latest breach lookup
    {
        let ui_weak = ui.as_weak();
        let client_clone = Rc::clone(&client);
        let runtime_clone = Rc::clone(&runtime);

        ui.on_get_latest(move || {
            let ui = match ui_weak.upgrade() {
                Some(ui) => ui,
                None => return,
            };

            // Fetch breach data
            let fut = {
                let client_ref = client_clone.borrow();
                runtime_clone.block_on(async { client_ref.get_latest_breach().await })
            };

            match fut {
                Ok(breach_data) => {
                    let breach = Breach {
                        name: SharedString::from(&breach_data.name),
                        domain: SharedString::from(&breach_data.domain),
                        pwn_count: breach_data.pwn_count as i32,
                        description: SharedString::from(&remove_tags(
                            breach_data.description.as_str(),
                        )),
                        breach_date: SharedString::from(&breach_data.breach_date.to_string()),
                        data_classes: ModelRc::new(VecModel::from(
                            breach_data
                                .data_classes
                                .iter()
                                .map(|dc| SharedString::from(dc))
                                .collect::<Vec<_>>(),
                        )),
                    };

                    ui.set_successful(true);
                    ui.set_breach(breach);
                }
                Err(e) => {
                    ui.set_successful(false);
                    ui.set_overlay_message(SharedString::from(format!("Error: {}", e)));
                    ui.set_overlay_title(SharedString::from("Error!"));
                }
            }
        });
    }

    // Handler for all breaches lookup
    {
        let ui_weak = ui.as_weak();
        let client_clone = Rc::clone(&client);
        let runtime_clone = Rc::clone(&runtime);

        ui.on_get_all(move || {
            let ui = match ui_weak.upgrade() {
                Some(ui) => ui,
                None => return,
            };

            // Fetch breach data
            let fut = {
                let client_ref = client_clone.borrow();
                runtime_clone.block_on(async { client_ref.get_all_breaches().await })
            };

            match fut {
                Ok(breaches) => {
                    let slint_breaches: Vec<Breach> = breaches
                        .iter()
                        .map(|b| Breach {
                            name: SharedString::from(&b.name),
                            domain: SharedString::from(&b.domain),
                            pwn_count: b.pwn_count as i32,
                            description: SharedString::from(&remove_tags(b.description.as_str())),
                            breach_date: SharedString::from(&b.breach_date.to_string()),
                            data_classes: ModelRc::new(VecModel::from(
                                b.data_classes
                                    .iter()
                                    .map(|dc| SharedString::from(dc))
                                    .collect::<Vec<_>>(),
                            )),
                        })
                        .collect();

                    ui.set_successful(true);
                    ui.set_breaches(ModelRc::new(VecModel::from(slint_breaches)));
                }
                Err(e) => {
                    ui.set_successful(false);
                    ui.set_overlay_message(SharedString::from(format!("Error: {}", e)));
                    ui.set_overlay_title(SharedString::from("Error!"));
                }
            }
        });
    }

    ui.run()?;
    Ok(())
}
