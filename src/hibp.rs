use crate::shared::{HibpError, Result};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Breach {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Title")]
    pub title: String,
    #[serde(rename = "Domain")]
    pub domain: String,
    #[serde(rename = "BreachDate")]
    pub date: String,
    #[serde(rename = "AddedDate")]
    pub added_date: String,
    #[serde(rename = "ModifiedDate")]
    pub modified_date: String,
    #[serde(rename = "PwnCount")]
    pub pwn_count: u64,
    #[serde(rename = "Description")]
    pub description: String,
    #[serde(rename = "LogoPath")]
    pub logo_path: String,
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
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Paste {
    #[serde(rename = "Source")]
    pub source: String,
    #[serde(rename = "Id")]
    pub id: String,
    #[serde(rename = "Title")]
    pub title: String,
    #[serde(rename = "Date")]
    pub date: String,
    #[serde(rename = "EmailCount")]
    pub email_count: u64,
}

#[derive(Debug)]
struct RateLimiterState {
    tokens: f64,
    last_refill: Instant,
}

struct RateLimiter {
    state: Arc<Mutex<RateLimiterState>>,
    capacity: f64,
    refill_rate: f64,
}

impl RateLimiter {
    fn new(capacity: f64, refill_rate: f64) -> Self {
        Self {
            state: Arc::new(Mutex::new(RateLimiterState {
                tokens: capacity,
                last_refill: Instant::now(),
            })),
            capacity,
            refill_rate,
        }
    }

    async fn acquire(&self) -> Result<()> {
        let mut state = self.state.lock().await;

        // Refill tokens atomically within the same lock
        let now = Instant::now();
        let time_passed = now.duration_since(state.last_refill).as_secs_f64();

        if time_passed > 0.0 {
            let new_tokens = time_passed * self.refill_rate;
            state.tokens = (state.tokens + new_tokens).min(self.capacity);
            state.last_refill = now;
        }

        // Check and consume token
        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            Ok(())
        } else {
            Err(HibpError::RateLimit.into())
        }
    }
}

pub struct HibpClient {
    client: Client,
    api_key: Option<String>,
    user_agent: String,
    limiter: RateLimiter,
}

impl HibpClient {
    pub fn new(api_key: Option<String>, user_agent: String) -> Self {
        const HIBP_TOKEN_CAPACITY: f64 = 10.0;
        const HIBP_REFILL_RATE: f64 = 0.75 / 60.0;
        const HIBP_TIMEOUT_SECONDS: u64 = 30;

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(HIBP_TIMEOUT_SECONDS))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            api_key,
            user_agent,
            limiter: RateLimiter::new(HIBP_TOKEN_CAPACITY, HIBP_REFILL_RATE),
        }
    }

    pub async fn check_breaches(&self, email: &str) -> Result<Vec<Breach>> {
        if self.api_key.is_none() {
            return Err(HibpError::Unauthorized.into());
        }

        self.limiter.acquire().await?;

        let url = format!(
            "https://haveibeenpwned.com/api/v3/breachedaccount/{}?truncateResponse=false",
            urlencoding::encode(email)
        );

        let request = self
            .client
            .get(&url)
            .header("User-Agent", &self.user_agent)
            .header("hibp-api-key", self.api_key.as_ref().unwrap());

        let response = request.send().await?;

        match response.status() {
            StatusCode::OK => {
                let breaches: Vec<Breach> = response.json().await?;
                Ok(breaches)
            }
            StatusCode::NOT_FOUND => Err(HibpError::NotFound.into()),
            StatusCode::BAD_REQUEST => Err(HibpError::BadRequest.into()),
            StatusCode::UNAUTHORIZED => Err(HibpError::Unauthorized.into()),
            StatusCode::TOO_MANY_REQUESTS => Err(HibpError::RateLimit.into()),
            StatusCode::SERVICE_UNAVAILABLE => Err(HibpError::ServiceUnavailable.into()),
            status => {
                let error_text = response.text().await?;
                Err(HibpError::Unknown {
                    status: status.as_u16(),
                    message: error_text,
                }
                .into())
            }
        }
    }

    pub async fn check_pastes(&self, email: &str) -> Result<Vec<Paste>> {
        if self.api_key.is_none() {
            return Err(HibpError::Unauthorized.into());
        }

        self.limiter.acquire().await?;

        let url = format!(
            "https://haveibeenpwned.com/api/v3/pasteaccount/{}",
            urlencoding::encode(email)
        );

        let request = self
            .client
            .get(&url)
            .header("User-Agent", &self.user_agent)
            .header("hibp-api-key", self.api_key.as_ref().unwrap());

        let response = request.send().await?;

        match response.status() {
            StatusCode::OK => {
                let pastes: Vec<Paste> = response.json().await?;
                Ok(pastes)
            }
            StatusCode::NOT_FOUND => Err(HibpError::NotFound.into()),
            StatusCode::BAD_REQUEST => Err(HibpError::BadRequest.into()),
            StatusCode::UNAUTHORIZED => Err(HibpError::Unauthorized.into()),
            StatusCode::TOO_MANY_REQUESTS => Err(HibpError::RateLimit.into()),
            StatusCode::SERVICE_UNAVAILABLE => Err(HibpError::ServiceUnavailable.into()),
            status => {
                let error_text = response.text().await?;
                Err(HibpError::Unknown {
                    status: status.as_u16(),
                    message: error_text,
                }
                .into())
            }
        }
    }

    pub async fn check_password(&self, password: &str) -> Result<Option<u64>> {
        self.limiter.acquire().await?;

        let mut hasher = Sha1::new();
        hasher.update(password.as_bytes());
        let full_hash = format!("{:X}", hasher.finalize());

        let prefix = &full_hash[..5];
        let suffix = &full_hash[5..];

        let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);

        let response = self
            .client
            .get(&url)
            .header("User-Agent", &self.user_agent)
            .send()
            .await?;

        match response.status() {
            StatusCode::OK => {
                let body = response.text().await?;
                for line in body.lines() {
                    if let Some((resp_suffix, count_str)) = line.split_once(':') {
                        if resp_suffix.trim().eq_ignore_ascii_case(suffix) {
                            if let Ok(count) = count_str.trim().parse::<u64>() {
                                return Ok(Some(count));
                            }
                        }
                    }
                }
                Ok(None)
            }
            StatusCode::BAD_REQUEST => Err(HibpError::BadRequest.into()),
            StatusCode::TOO_MANY_REQUESTS => Err(HibpError::RateLimit.into()),
            StatusCode::SERVICE_UNAVAILABLE => Err(HibpError::ServiceUnavailable.into()),
            status => {
                let error_text = response.text().await?;
                Err(HibpError::Unknown {
                    status: status.as_u16(),
                    message: error_text,
                }
                .into())
            }
        }
    }

    pub async fn check_domain(&self, domain: &str) -> Result<Vec<Breach>> {
        if self.api_key.is_none() {
            return Err(HibpError::Unauthorized.into());
        }

        self.limiter.acquire().await?;

        let url = format!(
            "https://haveibeenpwned.com/api/v3/breaches?domain={}",
            urlencoding::encode(domain)
        );

        let request = self
            .client
            .get(&url)
            .header("User-Agent", &self.user_agent)
            .header("hibp-api-key", self.api_key.as_ref().unwrap());

        let response = request.send().await?;

        match response.status() {
            StatusCode::OK => {
                let breaches: Vec<Breach> = response.json().await?;
                Ok(breaches)
            }
            StatusCode::NOT_FOUND => Err(HibpError::NotFound.into()),
            StatusCode::FORBIDDEN => Err(HibpError::Forbidden.into()),
            StatusCode::BAD_REQUEST => Err(HibpError::BadRequest.into()),
            StatusCode::UNAUTHORIZED => Err(HibpError::Unauthorized.into()),
            StatusCode::TOO_MANY_REQUESTS => Err(HibpError::RateLimit.into()),
            StatusCode::SERVICE_UNAVAILABLE => Err(HibpError::ServiceUnavailable.into()),
            status => {
                let error_text = response.text().await?;
                Err(HibpError::Unknown {
                    status: status.as_u16(),
                    message: error_text,
                }
                .into())
            }
        }
    }

    pub async fn get_breach(&self, name: &str) -> Result<Breach> {
        if self.api_key.is_none() {
            return Err(HibpError::Unauthorized.into());
        }

        self.limiter.acquire().await?;

        let url = format!(
            "https://haveibeenpwned.com/api/v3/breach/{}",
            urlencoding::encode(name)
        );

        let request = self
            .client
            .get(&url)
            .header("User-Agent", &self.user_agent)
            .header("hibp-api-key", self.api_key.as_ref().unwrap());

        let response = request.send().await?;

        match response.status() {
            StatusCode::OK => {
                let breach: Breach = response.json().await?;
                Ok(breach)
            }
            StatusCode::NOT_FOUND => Err(HibpError::NotFound.into()),
            StatusCode::FORBIDDEN => Err(HibpError::Forbidden.into()),
            StatusCode::BAD_REQUEST => Err(HibpError::BadRequest.into()),
            StatusCode::UNAUTHORIZED => Err(HibpError::Unauthorized.into()),
            StatusCode::TOO_MANY_REQUESTS => Err(HibpError::RateLimit.into()),
            StatusCode::SERVICE_UNAVAILABLE => Err(HibpError::ServiceUnavailable.into()),
            status => {
                let error_text = response.text().await?;
                Err(HibpError::Unknown {
                    status: status.as_u16(),
                    message: error_text,
                }
                .into())
            }
        }
    }

    pub async fn all_breaches(&self) -> Result<Vec<Breach>> {
        if self.api_key.is_none() {
            return Err(HibpError::Unauthorized.into());
        }

        self.limiter.acquire().await?;

        let url = "https://haveibeenpwned.com/api/v3/breaches";

        let request = self
            .client
            .get(url)
            .header("User-Agent", &self.user_agent)
            .header("hibp-api-key", self.api_key.as_ref().unwrap());

        let response = request.send().await?;

        match response.status() {
            StatusCode::OK => {
                let breaches: Vec<Breach> = response.json().await?;
                Ok(breaches)
            }
            StatusCode::NOT_FOUND => Err(HibpError::NotFound.into()),
            StatusCode::FORBIDDEN => Err(HibpError::Forbidden.into()),
            StatusCode::BAD_REQUEST => Err(HibpError::BadRequest.into()),
            StatusCode::UNAUTHORIZED => Err(HibpError::Unauthorized.into()),
            StatusCode::TOO_MANY_REQUESTS => Err(HibpError::RateLimit.into()),
            StatusCode::SERVICE_UNAVAILABLE => Err(HibpError::ServiceUnavailable.into()),
            status => {
                let error_text = response.text().await?;
                Err(HibpError::Unknown {
                    status: status.as_u16(),
                    message: error_text,
                }
                .into())
            }
        }
    }
}
