//! Simple in-memory IP rate limiter.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct RateLimiter {
    max_per_window: u32,
    window: Duration,
    hits: Mutex<HashMap<String, (u32, Instant)>>,
}

impl RateLimiter {
    pub fn new(max_per_window: u32, window_secs: u64) -> Self {
        Self {
            max_per_window: max_per_window.max(1),
            window: Duration::from_secs(window_secs.max(1)),
            hits: Mutex::new(HashMap::new()),
        }
    }

    /// Returns Ok(()) if allowed, Err if limited.
    pub fn check(&self, key: &str) -> Result<(), String> {
        let mut g = self.hits.lock().map_err(|e| e.to_string())?;
        let now = Instant::now();
        let entry = g.entry(key.to_string()).or_insert((0, now));
        if now.duration_since(entry.1) > self.window {
            *entry = (0, now);
        }
        if entry.0 >= self.max_per_window {
            return Err(format!(
                "rate limited: max {} requests per {}s",
                self.max_per_window,
                self.window.as_secs()
            ));
        }
        entry.0 += 1;
        // opportunistic prune
        if g.len() > 50_000 {
            g.retain(|_, (_, t)| now.duration_since(*t) <= self.window);
        }
        Ok(())
    }
}
