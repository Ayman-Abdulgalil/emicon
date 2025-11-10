//! Token bucket implementation for rate limiting in async Rust applications.
//!
//! This module provides a thread-safe, async token bucket that can be used to control
//! the rate of operations. It supports dynamic backoff periods and HTTP Retry-After
//! header parsing for integration with rate-limited APIs.
//!
//! # Example
//!
//! ```rust
//! use std::time::Duration;
//! use tokio_token_bucket::TokenBucket;
//!
//! #[tokio::main]
//! async fn main() {
//!     // Create a bucket with 10 tokens capacity, refilling at 2 tokens per second
//!     let bucket = TokenBucket::new(10, 2.0);
//!     
//!     // Consume a token (will wait if none available)
//!     bucket.consume().await;
//!     
//!     // Try to consume without waiting
//!     if bucket.try_consume().await {
//!         println!("Token consumed successfully");
//!     }
//! }
//! ```

// ╔═ To Do: ═════════════════════════════════════════════════════════════════════════════════════╗
// ║
// ║  - Improve accuracy.
// ║  - Validate inputs. (0, 0) input should mean no limiting, while providing the backoff and parser methods.
// ║  - Handle post backoff stamped.
// ║  - Handle non-standard retry_after header formats.
// ║
// ╚══════════════════════════════════════════════════════════════════════════════════════════════╝

use std::sync::Arc;
use tokio::sync::{Mutex, Notify};
use tokio::time::{sleep_until, Duration, Instant};

/// A thread-safe, async token bucket for rate limiting.
///
/// The `TokenBucket` implements the token bucket algorithm, which maintains a bucket
/// of tokens that are consumed by operations and refilled at a constant rate. This
/// provides smooth rate limiting that allows for bursts up to the bucket capacity.
///
/// # Thread Safety
///
/// This implementation is fully thread-safe and can be safely shared across multiple
/// async tasks using `Clone`.
///
/// # Rate Limiting Features
///
/// - Configurable capacity and refill rate
/// - Non-blocking token consumption attempts
/// - Blocking token consumption with automatic waiting
/// - Dynamic backoff periods (useful for HTTP 429 responses)
/// - HTTP Retry-After header parsing
#[derive(Clone)]
pub struct TokenBucket {
    /// The shared inner state of the token bucket
    inner: Arc<Mutex<TokenBucketInner>>,
    /// Notifier for waking up waiting consumers when backoff periods end
    notify: Arc<Notify>,
}

/// Internal state of the token bucket.
///
/// This struct contains all the mutable state that needs to be protected by a mutex.
struct TokenBucketInner {
    /// Maximum number of tokens the bucket can hold
    capacity: u32,
    /// Current number of available tokens
    tokens: u32,
    /// Rate at which tokens are added per second
    refill_rate: f64,
    /// Timestamp of the last token refill operation
    last_refill: Instant,
    /// Float remainder since last update
    remainder: f64,
    /// Optional pause period during which no tokens can be consumed
    /// (used for implementing backoff after rate limit errors)
    pause_until: Option<Instant>,
}

impl TokenBucket {
    /// Creates a new token bucket with the specified capacity and refill rate.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum number of tokens the bucket can hold
    /// * `refill_rate` - Number of tokens added per second (can be fractional)
    ///
    /// # Example
    ///
    /// ```rust
    /// // Create a bucket that holds 100 tokens and refills at 10 tokens per second
    /// let bucket = TokenBucket::new(100, 10.0);
    ///
    /// // Create a bucket that refills slowly (1 token every 2 seconds)
    /// let slow_bucket = TokenBucket::new(5, 0.5);
    /// ```
    pub fn new(capacity: u32, refill_rate: f64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(TokenBucketInner {
                capacity,
                tokens: capacity, // Start with a full bucket
                refill_rate,
                last_refill: Instant::now(),
                remainder: 0.0,
                pause_until: None,
            })),
            notify: Arc::new(Notify::new()),
        }
    }

    /// Initiates a backoff period during which no tokens can be consumed.
    ///
    /// This method is useful when handling rate limit errors from APIs. During the
    /// backoff period, all token consumption attempts will fail or wait until the
    /// period expires.
    ///
    /// If multiple backoff periods are set, the latest (furthest in the future) one
    /// will be used. The bucket is also immediately emptied of all tokens.
    ///
    /// # Arguments
    ///
    /// * `dur` - Duration of the backoff period
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::time::Duration;
    ///
    /// // Backoff for 5 minutes after receiving a rate limit error
    /// bucket.backoff_for(Duration::from_secs(300)).await;
    /// ```
    pub async fn backoff_for(&self, dur: Duration) {
        let until = Instant::now() + dur;
        let mut inner = self.inner.lock().await;

        // Keep the furthest future pause time
        inner.pause_until = Some(match inner.pause_until {
            Some(existing) if existing > until => existing,
            _ => until,
        });

        // Empty the bucket during backoff
        inner.tokens = 0;
        inner.remainder = 0.0;

        // Wake up any waiting consumers so they can check the new backoff state
        self.notify.notify_waiters();
    }

    /// Parses an HTTP Retry-After header value into a Duration.
    ///
    /// The Retry-After header can contain either:
    /// - A number of seconds (e.g., "120")
    /// - An HTTP date (e.g., "Wed, 21 Oct 2015 07:28:00 GMT")
    ///
    /// # Arguments
    ///
    /// * `value` - The value from the Retry-After header
    ///
    /// # Returns
    ///
    /// * `Some(Duration)` - The parsed duration to wait
    /// * `None` - If the header value couldn't be parsed
    ///
    /// # Example
    ///
    /// ```rust
    /// // Parse a seconds-based header
    /// if let Some(duration) = TokenBucket::parse_retry_after("300") {
    ///     bucket.backoff_for(duration).await;
    /// }
    ///
    /// // Parse a date-based header
    /// if let Some(duration) = TokenBucket::parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT") {
    ///     bucket.backoff_for(duration).await;
    /// }
    /// ```
    pub fn parse_retry_after(&self, value: &str) -> Duration {
        // Try parsing as seconds first
        if let Ok(secs) = value.trim().parse::<u64>() {
            return Duration::from_secs(secs);
        }

        // Try parsing as HTTP date
        if let Ok(date) = httpdate::parse_http_date(value.trim()) {
            let now = std::time::SystemTime::now();
            if let Ok(diff) = date.duration_since(now) {
                return diff;
            } else {
                // If the date is in the past, don't wait
                return Duration::from_secs(0);
            }
        };

        Duration::from_secs(30)
    }

    /// Attempts to consume a token without blocking.
    ///
    /// This method will immediately return whether a token was successfully consumed.
    /// It will not wait if no tokens are available or if the bucket is in a backoff period.
    ///
    /// # Returns
    ///
    /// * `true` - A token was successfully consumed
    /// * `false` - No token was available (bucket empty or in backoff)
    ///
    /// # Example
    ///
    /// ```rust
    /// if bucket.try_consume().await {
    ///     // Proceed with rate-limited operation
    ///     make_api_call().await;
    /// } else {
    ///     // Handle rate limit (maybe try again later)
    ///     println!("Rate limited, try again later");
    /// }
    /// ```
    // pub async fn try_consume(&self) -> bool {
    //     {
    //         let mut inner = self.inner.lock().await;

    //         // Check if we're in a backoff period
    //         if let Some(until) = inner.pause_until {
    //             let now = Instant::now();
    //             if now < until {
    //                 return false; // Still in backoff
    //             } else {
    //                 inner.pause_until = None; // Backoff period ended
    //             }
    //         }

    //         // Refill tokens based on elapsed time
    //         inner.refill();

    //         // Try to consume a token
    //         if inner.tokens > 0 {
    //             inner.tokens -= 1;
    //             return true;
    //         }
    //     }
    //     false
    // }

    /// Consumes a token, waiting if necessary until one becomes available.
    ///
    /// This method will block until a token can be successfully consumed. It respects
    /// backoff periods and will wait for them to expire before attempting to consume tokens.
    ///
    /// # Example
    ///
    /// ```rust
    /// // This will wait until a token is available
    /// bucket.consume().await;
    ///
    /// // Now we can proceed with the rate-limited operation
    /// make_api_call().await;
    /// ```
    pub async fn consume(&self) {
        loop {
            let (maybe_sleep_until, consumed) = {
                let mut inner = self.inner.lock().await;

                if let Some(until) = inner.pause_until {
                    let now = Instant::now();
                    if now < until {
                        // Still in backoff period
                        (Some(until), false)
                    } else {
                        // Backoff period ended
                        inner.pause_until = None;
                        inner.refill();
                        if inner.tokens > 0 {
                            inner.tokens -= 1;
                            (None, true)
                        } else {
                            // No tokens available, wait for next refill
                            let wait = now + Duration::from_secs_f64(1.0 / inner.refill_rate);
                            (Some(wait), false)
                        }
                    }
                } else {
                    inner.refill();
                    if inner.tokens > 0 {
                        inner.tokens -= 1;
                        (None, true)
                    } else {
                        // Calculate when the next token will be available
                        let now = Instant::now();
                        let wait = now + Duration::from_secs_f64(1.0 / inner.refill_rate);
                        (Some(wait), false)
                    }
                }
            };

            if consumed {
                return; // Successfully consumed a token
            }

            // Wait until either the calculated time or until notified of a state change
            if let Some(until) = maybe_sleep_until {
                tokio::select! {
                    _ = sleep_until(until) => {}, // Time-based wakeup
                    _ = self.notify.notified() => {}, // State change notification
                }
            }
        }
    }

    // / Returns the number of tokens currently available in the bucket.
    // /
    // / This method provides a snapshot of the current token count. The actual number
    // / may change immediately after this call due to concurrent operations or token refills.
    // /
    // / # Returns
    // /
    // / The current number of available tokens (0 if in backoff period)
    // /
    // / # Example
    // /
    // / ```rust
    // / let available = bucket.available_tokens().await;
    // / println!("Tokens available: {}", available);
    // /
    // / if available >= 5 {
    // /     // We have enough tokens for a batch operation
    // /     perform_batch_operation().await;
    // / }
    // / ```
    // pub async fn available_tokens(&self) -> u32 {
    //     let mut inner = self.inner.lock().await;

    //     // Check backoff period
    //     if let Some(until) = inner.pause_until {
    //         if Instant::now() < until {
    //             return 0; // No tokens available during backoff
    //         } else {
    //             inner.pause_until = None; // Backoff period ended
    //         }
    //     }

    //     inner.refill();
    //     inner.tokens
    // }
}

impl TokenBucketInner {
    /// Refills tokens based on the elapsed time since the last refill.
    ///
    /// This method calculates how many tokens should be added based on the configured
    /// refill rate and the time that has passed. It ensures the bucket never exceeds
    /// its maximum capacity.
    ///
    /// # Implementation Notes
    ///
    /// - Uses floating-point arithmetic to handle fractional refill rates
    /// - Only refills if measurable time has elapsed (> 0 seconds)
    /// - Updates the `last_refill` timestamp to prevent duplicate refills
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);

        // Only refill if measurable time has passed
        if elapsed.as_secs_f64() > 0.0 {
            let tokens_to_add = (elapsed.as_secs_f64() * self.refill_rate) + self.remainder;
            self.remainder = tokens_to_add - (tokens_to_add as u32) as f64;
            self.tokens = (self.tokens + tokens_to_add as u32).min(self.capacity);
            self.last_refill = now;
        }
    }
}
