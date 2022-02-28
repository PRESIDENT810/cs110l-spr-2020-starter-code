use std::collections::HashMap;
use std::time::Instant;

/// A rate limiter that limits the number of requests per minute.
///
/// RateLimit calculate ec using the following equation:
///
/// *ec = previous counter * ((time unit - time into the current counter) / time unit) + current counter*
///
/// If ec exceeds **max_requests_per_minute**, **should_accept** returns false.
struct RateLimit{
    /// The maximum number of requests allowed per minute.
    max_requests_per_minute: usize,
    /// The number of requests that came in the previous time window
    previous_counter: i32,
    /// The number of requests that came in the previous time window
    current_counter: i32,
    /// Start time when we start rate limiting
    start_time: Instant,
    /// Last minute
    previous_minute: i64,
}

impl RateLimit{
    /// Initial state:
    ///
    /// Previous window: \[-1 ~ 0\] min, with previous counter = 0
    ///
    /// Current window: \[0 ~ 1\] min, with current counter = 0
    ///
    /// **Invariant: current window = previous window + 1**
    fn new(max_requests_per_minute: usize) -> RateLimit{
        return RateLimit{
            max_requests_per_minute,
            previous_counter: 0,
            current_counter: 0,
            start_time: Instant::now(),
            previous_minute: -1,
        };
    }

    fn should_accept(&mut self) -> bool{
        // If max_requests_per_minute, rate limiting is disabled
        if self.max_requests_per_minute == 0{
            return true;
        }

        log::info!("[Before] previous counter: {}, current counter: {}, previous minute: {}", self.previous_counter, self.current_counter, self.previous_minute);
        let current_time = self.start_time.elapsed().as_secs() as i64;
        log::info!("[should_accept] current_time: {:?}", current_time);
        // let old_previous_minute = self.previous_minute;
        // let old_current_minute = old_previous_minute+1;
        let new_current_minute = current_time / 60;
        let seconds = (current_time % 60) as i32;

        // old_previous_minute: [n ~ n+1] min ( n = self.previous_minute )
        // old_current_minute: [n+1 ~ n+2] min
        // new_current_minute: [m ~ m+1] min, m >= n+3
        // Therefore, new_previous_minute: [m-1 ~ m] min, with m-1 >= n+2,
        // so there is no overlap between old_current_minute and new_previous_minute.
        // Reset self.previous_count to 0 and self.previous_minute to m-1
        if new_current_minute-self.previous_minute >= 3{
            self.previous_counter = 0;
            self.previous_minute = new_current_minute-1;
            self.current_counter = 1;
        }

        // old_previous_minute: [n ~ n+1] min ( n = self.previous_minute )
        // old_current_minute: [n+1 ~ n+2] min
        // new_current_minute: [m ~ m+1] min, m = n+2
        // Therefore, new_current_minute: [n+2 ~ n+3] min, new_previous_minute: [n+1 ~ n+2] min
        // so old_current_minute is new_previous_minute
        // Reset self.previous_count to self.current_count and self.previous_minute to m-1
        if new_current_minute-self.previous_minute == 2{
            self.previous_counter = self.current_counter;
            self.previous_minute = new_current_minute-1;
            self.current_counter = 1;
        }

        // old_previous_minute: [n ~ n+1] min ( n = self.previous_minute )
        // old_current_minute: [n+1 ~ n+2] min
        // new_current_minute: [m ~ m+1] min, m = n+1
        // Therefore, new_current_minute: [n+1 ~ n+2] min, new_previous_minute: [n+1 ~ n+2] min
        // so actually there is nothing changed
        if new_current_minute-self.previous_minute == 1{
            self.current_counter += 1;
        }

        // Calculate ec using the formula:
        // ec = previous counter * ((time unit - time into the current counter) / time unit) + current counter
        let ec = self.previous_counter * ( (60-seconds)/60 ) + self.current_counter;

        log::info!("[After] previous counter: {}, current counter: {}, previous minute: {}", self.previous_counter, self.current_counter, self.previous_minute);
        if ec > self.max_requests_per_minute as i32{
            return false;
        }
        return true;
    }
}

/// A thread-safe hashmap struct for accessing the rate limiters for each ip address.
pub struct RateLimitMap{
    /// The maximum number of requests allowed per minute.
    max_requests_per_minute: usize,
    /// The hashmap keeping track of each ip address's request counter
    rate_limit_map: HashMap<String, RateLimit>,
}

impl RateLimitMap{
    pub fn new(max_requests_per_minute: usize) -> RateLimitMap{
        return RateLimitMap{
            max_requests_per_minute,
            rate_limit_map: HashMap::new(),
        };
    }

    pub fn should_accept(&mut self, ip: String) -> bool{
        if !self.rate_limit_map.contains_key(&ip){
            self.rate_limit_map.insert(ip.clone(), RateLimit::new(self.max_requests_per_minute));
        }
        return self.rate_limit_map.get_mut(&ip).unwrap().should_accept();
    }
}