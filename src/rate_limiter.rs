use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::time::sleep;
use std::collections::HashMap;

/// A token bucket rate limiter that can be awaited
#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<TokenBucket>>,
    hard_limits: Arc<Mutex<HardLimits>>,
}

struct TokenBucket {
    /// Maximum number of tokens the bucket can hold
    capacity: u32,
    /// Current number of tokens in the bucket
    tokens: u32,
    /// Rate at which tokens are added (tokens per second)
    refill_rate: u32,
    /// Last time the bucket was refilled
    last_refill: Instant,
}

#[derive(Debug, Clone, Copy)]
pub enum LimitPeriod {
    Minute,
    Hour,
    Day,
    Month,
    Year,
}

impl LimitPeriod {
    fn duration(&self) -> Duration {
        match self {
            LimitPeriod::Minute => Duration::from_secs(60),
            LimitPeriod::Hour => Duration::from_secs(3600),
            LimitPeriod::Day => Duration::from_secs(86400),
            LimitPeriod::Month => Duration::from_secs(2629746), // 30.44 days average
            LimitPeriod::Year => Duration::from_secs(31556952), // 365.2425 days
        }
    }

    fn start_of_period(&self, now: Instant) -> Instant {
        // For simplicity, we'll use rolling windows based on duration
        // In production, you might want calendar-based periods
        now
    }
}

struct HardLimit {
    max_calls: u32,
    current_calls: u32,
    period: LimitPeriod,
    period_start: Instant,
}

impl HardLimit {
    fn new(max_calls: u32, period: LimitPeriod) -> Self {
        Self {
            max_calls,
            current_calls: 0,
            period,
            period_start: Instant::now(),
        }
    }

    fn reset_if_needed(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.period_start) >= self.period.duration() {
            self.current_calls = 0;
            self.period_start = now;
        }
    }

    fn can_consume(&mut self, tokens: u32) -> bool {
        self.reset_if_needed();
        self.current_calls + tokens <= self.max_calls
    }

    fn consume(&mut self, tokens: u32) -> Result<(), RateLimitError> {
        self.reset_if_needed();
        if self.current_calls + tokens <= self.max_calls {
            self.current_calls += tokens;
            Ok(())
        } else {
            Err(RateLimitError::HardLimitExceeded {
                limit: self.max_calls,
                period: self.period,
                current: self.current_calls,
                reset_in: self.time_until_reset(),
            })
        }
    }

    fn time_until_reset(&self) -> Duration {
        let elapsed = Instant::now().duration_since(self.period_start);
        self.period.duration().saturating_sub(elapsed)
    }

    fn remaining_calls(&self) -> u32 {
        self.max_calls.saturating_sub(self.current_calls)
    }
}

struct HardLimits {
    limits: HashMap<String, HardLimit>,
}

impl RateLimiter {
    /// Creates a new rate limiter
    /// 
    /// # Arguments
    /// * `capacity` - Maximum number of tokens (burst capacity)
    /// * `refill_rate` - Number of tokens added per second
    pub fn new(capacity: u32, refill_rate: u32) -> Self {
        Self {
            inner: Arc::new(Mutex::new(TokenBucket {
                capacity,
                tokens: capacity, // Start with full bucket
                refill_rate,
                last_refill: Instant::now(),
            })),
            hard_limits: Arc::new(Mutex::new(HardLimits {
                limits: HashMap::new(),
            })),
        }
    }

    /// Adds a hard limit for a specific period
    /// 
    /// # Arguments
    /// * `name` - Identifier for this limit (e.g., "daily", "monthly")
    /// * `max_calls` - Maximum calls allowed in the period
    /// * `period` - The time period for the limit
    pub async fn add_hard_limit(&self, name: &str, max_calls: u32, period: LimitPeriod) {
        let mut limits = self.hard_limits.lock().await;
        limits.limits.insert(name.to_string(), HardLimit::new(max_calls, period));
    }

    /// Removes a hard limit
    pub async fn remove_hard_limit(&self, name: &str) {
        let mut limits = self.hard_limits.lock().await;
        limits.limits.remove(name);
    }

    /// Waits until a token is available and consumes it, checking hard limits
    /// 
    /// # Arguments
    /// * `tokens_needed` - Number of tokens required (default: 1)
    pub async fn acquire(&self, tokens_needed: u32) -> Result<(), RateLimitError> {
        if tokens_needed == 0 {
            return Ok(());
        }

        // Check hard limits first
        {
            let mut hard_limits = self.hard_limits.lock().await;
            for limit in hard_limits.limits.values_mut() {
                if !limit.can_consume(tokens_needed) {
                    return Err(RateLimitError::HardLimitExceeded {
                        limit: limit.max_calls,
                        period: limit.period,
                        current: limit.current_calls,
                        reset_in: limit.time_until_reset(),
                    });
                }
            }
        }

        // Wait for token bucket
        loop {
            let wait_time = {
                let mut bucket = self.inner.lock().await;
                bucket.refill();

                if bucket.tokens >= tokens_needed {
                    bucket.tokens -= tokens_needed;
                    break;
                }

                // Calculate how long to wait for enough tokens
                let tokens_deficit = tokens_needed - bucket.tokens;
                let wait_seconds = tokens_deficit as f64 / bucket.refill_rate as f64;
                Duration::from_secs_f64(wait_seconds)
            };

            // Wait outside the lock to avoid blocking other tasks
            sleep(wait_time).await;

            // Re-check hard limits after waiting (they might have reset)
            {
                let mut hard_limits = self.hard_limits.lock().await;
                for limit in hard_limits.limits.values_mut() {
                    if !limit.can_consume(tokens_needed) {
                        return Err(RateLimitError::HardLimitExceeded {
                            limit: limit.max_calls,
                            period: limit.period,
                            current: limit.current_calls,
                            reset_in: limit.time_until_reset(),
                        });
                    }
                }
            }
        }

        // Consume hard limit tokens after successful token bucket acquisition
        {
            let mut hard_limits = self.hard_limits.lock().await;
            for limit in hard_limits.limits.values_mut() {
                limit.consume(tokens_needed)?;
            }
        }

        Ok(())
    }

    /// Tries to acquire tokens without waiting, checking hard limits
    /// 
    /// # Arguments
    /// * `tokens_needed` - Number of tokens required (default: 1)
    pub async fn try_acquire(&self, tokens_needed: u32) -> Result<bool, RateLimitError> {
        if tokens_needed == 0 {
            return Ok(true);
        }

        // Check hard limits first
        {
            let mut hard_limits = self.hard_limits.lock().await;
            for limit in hard_limits.limits.values_mut() {
                if !limit.can_consume(tokens_needed) {
                    return Err(RateLimitError::HardLimitExceeded {
                        limit: limit.max_calls,
                        period: limit.period,
                        current: limit.current_calls,
                        reset_in: limit.time_until_reset(),
                    });
                }
            }
        }

        // Check token bucket
        let success = {
            let mut bucket = self.inner.lock().await;
            bucket.refill();

            if bucket.tokens >= tokens_needed {
                bucket.tokens -= tokens_needed;
                true
            } else {
                false
            }
        };

        if success {
            // Consume hard limit tokens
            let mut hard_limits = self.hard_limits.lock().await;
            for limit in hard_limits.limits.values_mut() {
                limit.consume(tokens_needed)?;
            }
        }

        Ok(success)
    }

    /// Gets current token count (for monitoring/debugging)
    pub async fn available_tokens(&self) -> u32 {
        let mut bucket = self.inner.lock().await;
        bucket.refill();
        bucket.tokens
    }

    /// Gets hard limit status for all configured limits
    pub async fn hard_limit_status(&self) -> HashMap<String, HardLimitStatus> {
        let mut hard_limits = self.hard_limits.lock().await;
        let mut status = HashMap::new();
        
        for (name, limit) in hard_limits.limits.iter_mut() {
            limit.reset_if_needed();
            status.insert(name.clone(), HardLimitStatus {
                max_calls: limit.max_calls,
                current_calls: limit.current_calls,
                remaining_calls: limit.remaining_calls(),
                period: limit.period,
                reset_in: limit.time_until_reset(),
            });
        }
        
        status
    }

    /// Gets the time until the next token will be available
    pub async fn time_until_available(&self, tokens_needed: u32) -> Duration {
        let bucket = self.inner.lock().await;
        if bucket.tokens >= tokens_needed {
            Duration::ZERO
        } else {
            let tokens_deficit = tokens_needed - bucket.tokens;
            let wait_seconds = tokens_deficit as f64 / bucket.refill_rate as f64;
            Duration::from_secs_f64(wait_seconds)
        }
    }
}

impl TokenBucket {
    /// Refills the bucket based on time elapsed
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        let elapsed_secs = elapsed.as_secs_f64();

        // Calculate tokens to add
        let tokens_to_add = (elapsed_secs * self.refill_rate as f64) as u32;
        
        if tokens_to_add > 0 {
            self.tokens = (self.tokens + tokens_to_add).min(self.capacity);
            self.last_refill = now;
        }
    }
}

#[derive(Debug, Clone)]
pub struct HardLimitStatus {
    pub max_calls: u32,
    pub current_calls: u32,
    pub remaining_calls: u32,
    pub period: LimitPeriod,
    pub reset_in: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum RateLimitError {
    #[error("Invalid token count: {0}")]
    InvalidTokenCount(u32),
    #[error("Hard limit exceeded: {current}/{limit} calls used for {period:?}. Resets in {reset_in:?}")]
    HardLimitExceeded {
        limit: u32,
        period: LimitPeriod,
        current: u32,
        reset_in: Duration,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_basic_rate_limiting() {
        let limiter = RateLimiter::new(5, 2); // 5 tokens max, 2 per second

        // Should be able to acquire 5 tokens immediately
        for _ in 0..5 {
            limiter.acquire(1).await.unwrap();
        }

        // Check that we're out of tokens
        assert!(!limiter.try_acquire(1).await.unwrap());

        // Wait for refill and try again
        sleep(Duration::from_secs(1)).await;
        assert!(limiter.try_acquire(1).await.unwrap());
    }

    #[tokio::test]
    async fn test_burst_capacity() {
        let limiter = RateLimiter::new(10, 1); // 10 tokens max, 1 per second

        // Should handle burst of 10 requests
        limiter.acquire(10).await.unwrap();
        
        // Should be empty now
        assert_eq!(limiter.available_tokens().await, 0);
    }

    #[tokio::test]
    async fn test_hard_limits() {
        let limiter = RateLimiter::new(100, 100); // High token bucket limits
        
        // Add daily limit of 3 calls
        limiter.add_hard_limit("daily", 3, LimitPeriod::Day).await;

        // Should allow 3 calls
        for _ in 0..3 {
            limiter.acquire_one().await.unwrap();
        }

        // 4th call should fail
        let result = limiter.acquire_one().await;
        assert!(matches!(result, Err(RateLimitError::HardLimitExceeded { .. })));
    }

    #[tokio::test]
    async fn test_multiple_hard_limits() {
        let limiter = RateLimiter::new(100, 100);
        
        // Add both daily and hourly limits
        limiter.add_hard_limit("daily", 10, LimitPeriod::Day).await;
        limiter.add_hard_limit("hourly", 5, LimitPeriod::Hour).await;

        // Should be limited by the more restrictive hourly limit
        for _ in 0..5 {
            limiter.acquire_one().await.unwrap();
        }

        let result = limiter.acquire_one().await;
        assert!(matches!(result, Err(RateLimitError::HardLimitExceeded { .. })));
    }

    #[tokio::test]
    async fn test_hard_limit_status() {
        let limiter = RateLimiter::new(100, 100);
        limiter.add_hard_limit("daily", 10, LimitPeriod::Day).await;

        // Use some calls
        limiter.acquire(3).await.unwrap();

        let status = limiter.hard_limit_status().await;
        let daily_status = status.get("daily").unwrap();
        
        assert_eq!(daily_status.max_calls, 10);
        assert_eq!(daily_status.current_calls, 3);
        assert_eq!(daily_status.remaining_calls, 7);
    }
}

// Example usage and helper functions
impl RateLimiter {
    /// Convenience method to acquire a single token
    pub async fn acquire_one(&self) -> Result<(), RateLimitError> {
        self.acquire(1).await
    }

    /// Creates a rate limiter for common API scenarios with hard limits
    /// 
    /// # Arguments
    /// * `requests_per_second` - Token bucket refill rate
    /// * `burst_capacity` - Optional burst capacity (defaults to 2x requests_per_second)
    /// * `daily_limit` - Optional daily request limit
    /// * `monthly_limit` - Optional monthly request limit
    pub async fn for_api_with_limits(
        requests_per_second: u32, 
        burst_capacity: Option<u32>,
        daily_limit: Option<u32>,
        monthly_limit: Option<u32>
    ) -> Self {
        let capacity = burst_capacity.unwrap_or(requests_per_second * 2);
        let limiter = Self::new(capacity, requests_per_second);
        
        if let Some(daily) = daily_limit {
            limiter.add_hard_limit("daily", daily, LimitPeriod::Day).await;
        }
        
        if let Some(monthly) = monthly_limit {
            limiter.add_hard_limit("monthly", monthly, LimitPeriod::Month).await;
        }
        
        limiter
    }
}


/*
use rate_limiter::{RateLimiter, LimitPeriod};

#[tokio::main]
async fn main() {
    // Create a rate limiter: 10 requests/second, 20 burst, 1000/day, 25000/month
    let limiter = RateLimiter::for_api_with_limits(10, Some(20), Some(1000), Some(25000)).await;
    
    // Or create and add limits manually
    let limiter = RateLimiter::new(20, 10);
    limiter.add_hard_limit("daily", 1000, LimitPeriod::Day).await;
    limiter.add_hard_limit("monthly", 25000, LimitPeriod::Month).await;
    limiter.add_hard_limit("hourly", 100, LimitPeriod::Hour).await;
    
    // In your API call function:
    async fn make_api_call(limiter: &RateLimiter) -> Result<String, Box<dyn std::error::Error>> {
        // Wait for rate limit (both token bucket and hard limits)
        limiter.acquire_one().await?;
        
        // Make your actual API call
        let response = reqwest::get("https://api.example.com/data").await?;
        Ok(response.text().await?)
    }
    
    // Monitor hard limit status
    let status = limiter.hard_limit_status().await;
    for (name, limit_status) in status {
        println!("Limit {}: {}/{} used, {} remaining, resets in {:?}", 
            name, 
            limit_status.current_calls, 
            limit_status.max_calls,
            limit_status.remaining_calls,
            limit_status.reset_in
        );
    }
    
    // Example: Making multiple API calls with error handling
    for i in 0..1100 {
        match make_api_call(&limiter).await {
            Ok(_) => println!("Request {} succeeded", i),
            Err(e) => {
                println!("Request {} failed: {}", i, e);
                // Handle rate limit exceeded - maybe wait or break
                break;
            }
        }
    }
}
*/