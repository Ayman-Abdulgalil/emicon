//! # Have I Been Pwned (HIBP) Client
//!
//! This module provides a typed Rust wrapper around the
//! [Have I Been Pwned API v3](https://haveibeenpwned.com/API/v3) and the
//! [Pwned Passwords API](https://haveibeenpwned.com/Passwords).
//!
//! ## Features
//! - Check if an email has been involved in breaches or pastes
//! - Retrieve details of specific breaches
//! - Fetch the full list of breach datasets
//! - Verify whether a password has appeared in breaches (using k-Anonymity hashing)
//!
//! ## Example Usage
//! ```
//! use hibp_client::HibpClient;
//!
//! #[tokio::main]
//! async fn main() {
//!     let hibp = HibpClient::new(
//!         Some("your-api-key".to_string()),  // API key required for breach APIs
//!         "my-app/1.0".to_string(),          // Meaningful User-Agent (mandatory)
//!         10                                 // Timeout in seconds
//!     ).unwrap();
//!
//!     // Check breaches linked to an email
//!     if let Ok(breaches) = hibp.check_account_breaches("user@example.com").await {
//!         for breach in breaches {
//!             println!("Breached in: {}", breach.name);
//!         }
//!     }
//!
//!     // Check if a password is compromised
//!     if let Ok(count) = hibp.check_password("hunter2").await {
//!         if count > 0 {
//!             println!("Password appeared in {count} breaches.");
//!         } else {
//!             println!("Password not found in breaches.");
//!         }
//!     }
//! }
//! ```

use chrono::{DateTime, NaiveDate, Utc};
use reqwest::{Client, Response, StatusCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha1::{Digest, Sha1};

/// Wrapper type used for all results returned by this crate
pub type HibpResult<T> = std::result::Result<T, HibpError>;

/// Errors that can arise when interacting with the Have I Been Pwned API
#[derive(thiserror::Error, Debug)]
pub enum HibpError {
    /// Failed to build Hibp client
    #[error("Client build error: {0}")]
    ClientBuildError(String),
    
    /// Response status `404`. In account queries, it means the account didn't match any data entry.
    #[error("Email not found in any breaches")]
    NotFound,
    
    /// Response status `429`. Try again later.
    #[error("Rate limited - too many requests")]
    RateLimit,
    
    /// Response status `401`. Missing or invalid API key.
    #[error("Unauthorized - missing or invalid API key")]
    Unauthorized,
    
    /// Response status `403`. Request rejected (likely missing or banned User-Agent).
    #[error("Forbidden - request rejected (likely missing or banned User-Agent)")]
    Forbidden,
    
    /// Response status `400`. Bad request (invalid email format).
    #[error("Bad request - invalid email format")]
    BadRequest,
    
    /// Response status `503`. Service unavailable (usually upstream or Cloudflare).
    #[error("Service unavailable")]
    ServiceUnavailable,
    
    /// Error requesting data.
    #[error("Request error: {0}")]
    ReqwestError(#[from] reqwest::Error),
    
    /// Unknown response status code.
    #[error("Unexpected API response: {status}, body: {body}")]
    Unknown { status: StatusCode, body: String },
}

/// Detailed information about a specific data breach.
/// Returned when querying `check_account_breaches`, `get_breach`, or `get_all_breaches`.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Breach {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Title")]
    pub title: String,
    #[serde(rename = "Domain")]
    pub domain: String,

    /// Date without time (ISO 8601 date)
    #[serde(rename = "BreachDate")]
    pub breach_date: NaiveDate,

    /// Datetime with minute precision (ISO 8601)
    #[serde(rename = "AddedDate")]
    pub added_date: Option<DateTime<Utc>>,
    /// Datetime with minute precision (ISO 8601)
    #[serde(rename = "ModifiedDate")]
    pub modified_date: Option<DateTime<Utc>>,

    #[serde(rename = "PwnCount")]
    pub pwn_count: u64,
    #[serde(rename = "Description")]
    pub description: String,

    #[serde(rename = "DataClasses")]
    pub data_classes: Vec<String>,

    #[serde(rename = "IsVerified")]
    pub is_verified: bool,
    #[serde(rename = "IsFabricated")]
    pub is_fabricated: bool,
    #[serde(rename = "IsSensitive")]
    pub is_sensitive: bool,
    #[serde(rename = "IsRetired")]
    pub is_retired: bool,
    #[serde(rename = "IsSpamList")]
    pub is_spam_list: bool,
    #[serde(rename = "IsMalware")]
    pub is_malware: bool,
    #[serde(rename = "IsSubscriptionFree")]
    pub is_subscription_free: bool,
    #[serde(rename = "IsStealerLog")]
    pub is_stealer_log: bool,

    #[serde(rename = "LogoPath")]
    pub logo_path: Option<String>,
    #[serde(rename = "Attribution")]
    pub attribution: Option<String>,
}

/// Information about a paste (e.g. from Pastebin) containing an email address.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Paste {
    #[serde(rename = "Source")]
    pub source: Option<String>,
    #[serde(rename = "Id")]
    pub id: Option<String>,
    #[serde(rename = "Title")]
    pub title: Option<String>,
    #[serde(rename = "Date")]
    pub date: Option<chrono::DateTime<Utc>>,
    #[serde(rename = "EmailCount")]
    pub email_count: Option<u64>,
}

/// Information about the subscription status (e.g. rate limit).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SubscriptionStatus {
    #[serde(rename = "SubscriptionName")]
    pub sub_name: String,
    #[serde(rename = "Description")]
    pub description: String,
    #[serde(rename = "SubscribedUntil")]
    pub sub_until: DateTime<Utc>,
    #[serde(rename = "Rpm")]
    pub rpm: u64,
    /// will be null if no searches yet performed.
    #[serde(rename = "DomainSearchMaxBreachedAccounts")] 
    pub domain_search_max_breached_accounts: Option<u64>,
    #[serde(rename = "IncludesStealerLogs")]
    pub includes_stealer_logs: Option<bool>,
}

/// Information about the subscribed domain (e.g. pawn count).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SubscribedDomain {
    #[serde(rename = "DomainName")]
    pub domain_name: String,
    #[serde(rename = "PwnCount")]
    pub pwn_count: Option<u64>,
    #[serde(rename = "PwnCountExcludingSpamLists")]
    pub pwn_count_excluding_spam_lists: Option<u64>,
    #[serde(rename = "PwnCountExcludingSpamListsAtLastSubscriptionRenewal")]
    pub pwn_count_excl_spam_lists_at_last_subscription_renewal: Option<u64>,
    #[serde(rename = "NextSubscriptionRenewal")]
    pub next_subscription_renewal: Option<DateTime<Utc>>,
}

/// Client for accessing the HIBP API.
///
/// Create an instance using [`HibpClient::new`], supplying:
/// - An optional API key (required for breach endpoints)
/// - A mandatory User-Agent string
/// - Timeout duration
pub struct HibpClient {
    client: Client,
    api_key: Option<String>,
    user_agent: String,
}

impl HibpClient {
    /// Creates a new HIBP client.
    ///
    /// # Errors
    /// - Returns [`HibpError::ClientBuildError`] if the `reqwest::Client` fails to build
    /// - Returns [`HibpError::ClientBuildError`] if the User-Agent is empty
    pub fn new(api_key: Option<String>, user_agent: String, time_out: u64) -> HibpResult<Self> {
        if user_agent.trim().is_empty() {
            return Err(HibpError::ClientBuildError(
                "User Agent can't be empty.".to_string(),
            ));
        }

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(time_out))
            .build()
            .map_err(|e| HibpError::ClientBuildError(e.to_string()))?;

        Ok(Self {
            client,
            api_key,
            user_agent,
        })
    }

    /// Updates the client timeout duration (Builds a new client, should be fine since HIBP is stateless).
    pub fn change_time_out(&mut self, new_time_out: u64) -> HibpResult<()> {
        self.client = Client::builder()
            .timeout(std::time::Duration::from_secs(new_time_out))
            .build()
            .map_err(|e| HibpError::ClientBuildError(e.to_string()))?;
        Ok(())
    }

    /// Updates the API key.
    pub fn change_api_key(&mut self, new_api_key: Option<String>) -> HibpResult<()> {
        self.api_key = new_api_key;
        Ok(())
    }

    /// Ensures an API key is set (breach/paste/subscription APIs require it; Pwned Passwords does not).
    fn assert_auth(&self) -> HibpResult<()> {
        self.api_key.as_deref().ok_or(HibpError::Unauthorized)?;
        Ok(())
    }

    /// Generic GET request helper that deserializes JSON into type `D`.
    async fn request<D: DeserializeOwned>(&self, url: &str) -> HibpResult<D> {
        let mut req = self.client.get(url).header("User-Agent", &self.user_agent);
        if let Some(key) = &self.api_key {
            req = req.header("hibp-api-key", key);
        }
        let response = req.send().await?;
        let parsed: D = self.handle_response(response).await?.json::<D>().await?;
        Ok(parsed)
    }

    /// Internal helper to process API responses consistently.
    async fn handle_response(&self, response: Response) -> HibpResult<Response> {
        match response.status() {
            StatusCode::OK => Ok(response),
            StatusCode::NOT_FOUND => Err(HibpError::NotFound),
            StatusCode::FORBIDDEN => Err(HibpError::Forbidden),
            StatusCode::BAD_REQUEST => Err(HibpError::BadRequest),
            StatusCode::UNAUTHORIZED => Err(HibpError::Unauthorized),
            StatusCode::TOO_MANY_REQUESTS => Err(HibpError::RateLimit),
            StatusCode::SERVICE_UNAVAILABLE => Err(HibpError::ServiceUnavailable),
            status => {
                let bytes = response.bytes().await?;
                let body = String::from_utf8(bytes.to_vec())
                    .unwrap_or_else(|_| "<non-UTF8 body>".to_string());
                Err(HibpError::Unknown { status, body })
            }
        }
    }

    /// Returns a list of breach names for a given email (truncated).
    pub async fn check_account_breach_names(&self, email: &str) -> HibpResult<Vec<String>> {
        self.assert_auth()?;

        let url = format!(
            "https://haveibeenpwned.com/api/v3/breachedaccount/{}?truncateResponse=true",
            urlencoding::encode(&email)
        );
        Ok(self.request(&url).await?)
    }

    /// Returns full breach details (not truncated) for a given email.
    pub async fn check_account_breaches(&self, email: &str) -> HibpResult<Vec<Breach>> {
        self.assert_auth()?;

        let url = format!(
            "https://haveibeenpwned.com/api/v3/breachedaccount/{}?truncateResponse=false",
            urlencoding::encode(&email)
        );
        Ok(self.request(&url).await?)
    }

    /// Returns paste dumps where the given email appears.
    pub async fn check_account_paste(&self, email: &str) -> HibpResult<Vec<Paste>> {
        self.assert_auth()?;

        let url = format!(
            "https://haveibeenpwned.com/api/v3/pasteaccount/{}",
            urlencoding::encode(&email)
        );
        Ok(self.request(&url).await?)
    }

    /// Returns all breaches, optionally filtered by a domain.
    ///
    /// If `domain` is `None`, all known breaches are returned.
    pub async fn get_all_breaches(&self, domain: Option<&str>) -> HibpResult<Vec<Breach>> {
        self.assert_auth()?;

        if let Some(dom) = domain {
            let url = format!(
                "https://haveibeenpwned.com/api/v3/breaches?domain={}",
                urlencoding::encode(&dom)
            );
            Ok(self.request(&url).await?)
        } else {
            let url = "https://haveibeenpwned.com/api/v3/breaches".to_string();
            Ok(self.request(&url).await?)
        }
    }

    /// Gets detailed information about a specific breach by name.
    pub async fn get_breach(&self, name: &str) -> HibpResult<Breach> {
        self.assert_auth()?;

        let url = format!(
            "https://haveibeenpwned.com/api/v3/breach/{}",
            urlencoding::encode(&name)
        );
        Ok(self.request(&url).await?)
    }

    /// Checks how many times a password has appeared in breaches (k-Anonymity model).
    ///
    /// - Hashes the password with SHA1 (uppercase hex form).
    /// - Sends only the first 5 chars (prefix) to the HIBP k-Anonymity API.
    /// - Looks for the remaining suffix in the returned dataset.
    ///
    /// Returns the number of breaches in which the password appeared.
    ///
    /// ### Security
    /// The password is never directly sent to HIBP,
    /// only a partial hash prefix, keeping it private.
    pub async fn check_password(&self, password: impl AsRef<[u8]>) -> HibpResult<u64> {
        // Convert password into uppercase SHA1 hash
        let sha1_hex = hex::encode_upper(Sha1::digest(password.as_ref()));
        let (prefix, suffix) = sha1_hex.split_at(5);

        // Query the Pwned Passwords k-Anonymity API and parse the response
        let resp = self
            .client
            .get(format!("https://api.pwnedpasswords.com/range/{prefix}"))
            .header("User-Agent", &self.user_agent)
            .header("Add-Padding", "true")
            .send()
            .await?;

        let body = self.handle_response(resp).await?.text().await?;

        // Check if the suffix exists in returned hash list
        let target_suffix = suffix.to_ascii_uppercase();
        let count = body
            .lines()
            .find_map(|line| {
                let (sfx, cnt) = line.split_once(':')?;
                if sfx.eq_ignore_ascii_case(&target_suffix) {
                    cnt.trim().parse::<u64>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0);

        Ok(count)
    }

    /// Get current subscription status for the API key.
    pub async fn get_subscription_status(&self) -> HibpResult<SubscriptionStatus> {
        self.assert_auth()?;
        let url = "https://haveibeenpwned.com/api/v3/subscription/status";
        Ok(self.request(url).await?)
    }

    /// Get all domains subscribed (verified) under the API key.
    pub async fn get_subscribed_domains(&self) -> HibpResult<Vec<SubscribedDomain>> {
        self.assert_auth()?;
        let url = "https://haveibeenpwned.com/api/v3/subscribeddomains";
        Ok(self.request(url).await?)
    }
}
