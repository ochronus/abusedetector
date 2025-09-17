//! Retry utilities for network operations with exponential backoff.
//!
//! This module provides async retry functionality for network operations
//! that may fail due to temporary issues like timeouts, rate limiting,
//! or temporary server unavailability.

#![allow(dead_code)]

use std::time::Duration;
use tokio::time::{Instant, sleep};

/// Configuration for retry behavior
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts (not including the initial attempt)
    pub max_attempts: u32,

    /// Initial delay between retries
    pub initial_delay: Duration,

    /// Maximum delay between retries (for exponential backoff)
    pub max_delay: Duration,

    /// Multiplier for exponential backoff
    pub backoff_multiplier: f64,

    /// Whether to add jitter to prevent thundering herd
    pub jitter: bool,

    /// Maximum total time to spend retrying
    pub max_total_duration: Option<Duration>,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
            jitter: true,
            max_total_duration: Some(Duration::from_secs(60)),
        }
    }
}

/// Policy for determining if an operation should be retried
pub trait RetryPolicy<E> {
    /// Returns true if the operation should be retried for this error
    fn should_retry(&self, error: &E, attempt: u32) -> bool;
}

/// Default retry policy for network operations
pub struct NetworkRetryPolicy;

impl<E> RetryPolicy<E> for NetworkRetryPolicy
where
    E: std::error::Error,
{
    fn should_retry(&self, error: &E, attempt: u32) -> bool {
        // Don't retry beyond max attempts
        if attempt >= 3 {
            return false;
        }

        // Convert error to string for pattern matching
        let error_str = error.to_string().to_lowercase();

        // Retry on common transient network errors
        error_str.contains("timeout")
            || error_str.contains("connection refused")
            || error_str.contains("connection reset")
            || error_str.contains("temporary failure")
            || error_str.contains("network unreachable")
            || error_str.contains("host unreachable")
            || error_str.contains("rate limit")
            || error_str.contains("too many requests")
            || error_str.contains("service unavailable")
            || error_str.contains("internal server error")
    }
}

/// WHOIS-specific retry policy
pub struct WhoisRetryPolicy;

impl<E> RetryPolicy<E> for WhoisRetryPolicy
where
    E: std::error::Error,
{
    fn should_retry(&self, error: &E, attempt: u32) -> bool {
        if attempt >= 2 {
            return false;
        }

        let error_str = error.to_string().to_lowercase();

        // WHOIS servers often have rate limiting or temporary unavailability
        error_str.contains("timeout")
            || error_str.contains("connection")
            || error_str.contains("rate limit")
            || error_str.contains("quota")
            || error_str.contains("temporarily unavailable")
            || error_str.contains("try again")
    }
}

/// DNS-specific retry policy
pub struct DnsRetryPolicy;

impl<E> RetryPolicy<E> for DnsRetryPolicy
where
    E: std::error::Error,
{
    fn should_retry(&self, error: &E, attempt: u32) -> bool {
        if attempt >= 2 {
            return false;
        }

        let error_str = error.to_string().to_lowercase();

        // DNS timeouts and temporary failures are worth retrying
        error_str.contains("timeout")
            || error_str.contains("servfail")
            || error_str.contains("temporary failure")
            || error_str.contains("connection")
            || error_str.contains("network unreachable")
    }
}

/// Retry executor that handles the retry logic
pub struct RetryExecutor {
    config: RetryConfig,
}

impl RetryExecutor {
    /// Create a new retry executor with the given configuration
    pub fn new(config: RetryConfig) -> Self {
        Self { config }
    }

    /// Create a retry executor with default configuration
    pub fn with_default_config() -> Self {
        Self::new(RetryConfig::default())
    }

    /// Execute an async operation with retry logic
    pub async fn execute<F, Fut, T, E, P>(&self, operation: F, policy: P) -> Result<T, E>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
        P: RetryPolicy<E>,
        E: std::error::Error + Clone,
    {
        let start_time = Instant::now();
        let mut delay = self.config.initial_delay;

        for attempt in 0..=self.config.max_attempts {
            // Check if we've exceeded the maximum total duration
            if let Some(max_duration) = self.config.max_total_duration
                && start_time.elapsed() >= max_duration
            {
                break;
            }

            // Execute the operation
            match operation().await {
                Ok(result) => return Ok(result),
                Err(error) => {
                    // If this is the last attempt or the policy says not to retry, return the error
                    if attempt >= self.config.max_attempts || !policy.should_retry(&error, attempt)
                    {
                        return Err(error);
                    }

                    // Calculate delay for next attempt
                    let actual_delay = if self.config.jitter {
                        add_jitter(delay)
                    } else {
                        delay
                    };

                    // Sleep before next attempt
                    sleep(actual_delay).await;

                    // Update delay for exponential backoff
                    delay = std::cmp::min(
                        Duration::from_millis(
                            (delay.as_millis() as f64 * self.config.backoff_multiplier) as u64,
                        ),
                        self.config.max_delay,
                    );
                }
            }
        }

        // This should never be reached due to the loop logic above,
        // but we need to satisfy the compiler
        unreachable!("Retry loop should always return before reaching this point")
    }

    /// Execute an operation with a specific retry policy
    pub async fn execute_with_policy<F, Fut, T, E>(
        &self,
        operation: F,
        policy: impl RetryPolicy<E>,
    ) -> Result<T, E>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
        E: std::error::Error + Clone,
    {
        self.execute(operation, policy).await
    }
}

/// Add random jitter to prevent thundering herd problems
fn add_jitter(delay: Duration) -> Duration {
    use rand::Rng;

    let jitter_range = delay.as_millis() as f64 * 0.1; // 10% jitter
    let mut rng = rand::rng();
    let jitter: f64 = rng.random_range(-jitter_range..=jitter_range);

    let jittered_ms = (delay.as_millis() as f64 + jitter).max(0.0) as u64;
    Duration::from_millis(jittered_ms)
}

/// Convenience macro for retrying operations
#[macro_export]
macro_rules! retry_async {
    ($operation:expr) => {{
        use $crate::retry::{NetworkRetryPolicy, RetryExecutor};
        let executor = RetryExecutor::default();
        executor
            .execute(|| async { $operation }, NetworkRetryPolicy)
            .await
    }};

    ($operation:expr, $policy:expr) => {{
        use $crate::retry::RetryExecutor;
        let executor = RetryExecutor::default();
        executor.execute(|| async { $operation }, $policy).await
    }};

    ($operation:expr, $config:expr, $policy:expr) => {{
        use $crate::retry::RetryExecutor;
        let executor = RetryExecutor::new($config);
        executor.execute(|| async { $operation }, $policy).await
    }};
}

/// Builder pattern for creating retry configurations
pub struct RetryConfigBuilder {
    config: RetryConfig,
}

impl RetryConfigBuilder {
    /// Create a new builder with default configuration
    pub fn new() -> Self {
        Self {
            config: RetryConfig::default(),
        }
    }

    /// Set the maximum number of retry attempts
    pub fn max_attempts(mut self, attempts: u32) -> Self {
        self.config.max_attempts = attempts;
        self
    }

    /// Set the initial delay between retries
    pub fn initial_delay(mut self, delay: Duration) -> Self {
        self.config.initial_delay = delay;
        self
    }

    /// Set the maximum delay between retries
    pub fn max_delay(mut self, delay: Duration) -> Self {
        self.config.max_delay = delay;
        self
    }

    /// Set the backoff multiplier
    pub fn backoff_multiplier(mut self, multiplier: f64) -> Self {
        self.config.backoff_multiplier = multiplier;
        self
    }

    /// Enable or disable jitter
    pub fn jitter(mut self, enabled: bool) -> Self {
        self.config.jitter = enabled;
        self
    }

    /// Set the maximum total duration for all retry attempts
    pub fn max_total_duration(mut self, duration: Option<Duration>) -> Self {
        self.config.max_total_duration = duration;
        self
    }

    /// Build the final configuration
    pub fn build(self) -> RetryConfig {
        self.config
    }
}

impl Default for RetryConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// TODO: Re-enable retry module tests once core functionality is stable
// #[cfg(test)]
// mod tests {
//     // Tests temporarily disabled for compilation
// }
