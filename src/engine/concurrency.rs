use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, AtomicU64, AtomicBool, Ordering};

/// 动态信号量调整的自适应流控状态 / Adaptive flow control state for dynamic semaphore adjustment
pub struct FlowControlState {
    pub max_permits: AtomicUsize,
    pub min_permits: usize,
    /// 自UNIX_EPOCH以来的最后调整时间戳（毫秒） / Last adjustment timestamp in milliseconds since UNIX_EPOCH
    /// 时钟回滚通过 adjust_flow_control 中的 saturating_sub 处理 / Clock rollback is handled by saturating_sub in adjust_flow_control
    pub last_adjustment_ms: AtomicU64,
    pub critical_latency_threshold_ns: u64,
    pub adjustment_interval_ms: u64,
}

impl FlowControlState {
    /// 动态调整 flow control permits 基于系统负载和延迟 / Adaptively adjust flow control permits based on system load and latency
    pub fn adjust(&self, permit_manager: &PermitManager, latest_latency: u64) {
        // Get current time in milliseconds
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // Use compare_exchange_weak in a loop for lock-free synchronization
        // saturating_sub handles clock rollback: if now < last, result is 0, we skip
        let mut last_ms = self.last_adjustment_ms.load(Ordering::Acquire);
        loop {
            // Check if adjustment interval has passed
            if now_ms.saturating_sub(last_ms) < self.adjustment_interval_ms {
                return;
            }

            // Try to update timestamp - only one thread will succeed
            match self.last_adjustment_ms.compare_exchange_weak(
                last_ms, now_ms, Ordering::AcqRel, Ordering::Relaxed
            ) {
                Ok(_) => break,  // Successfully acquired adjustment right
                Err(current) => {
                    // Another thread updated timestamp, reload and recheck
                    last_ms = current;
                    continue;
                }
            }
        }

        let inflight = permit_manager.inflight();
        let current_permits = permit_manager.max_permits();
        let dropped = permit_manager.dropped_requests();

        // Log permit pool health periodically / 定期记录permit pool健康状况
        if dropped > 0 {
            tracing::warn!(
                inflight = inflight,
                max = current_permits,
                dropped_total = dropped,
                latest_latency_ms = latest_latency / 1_000_000,
                "Permit pool health status"
            );
        }

        // Check for permit leakage and recover / 检查permit泄漏并恢复
        permit_manager.check_and_recover();

        // 决策逻辑：如果延迟高或进行中请求多，减少 permits
        // Decision logic: reduce permits if latency is high or inflight requests are many
        let should_reduce = latest_latency > self.critical_latency_threshold_ns
            || inflight > current_permits * 2 / 3;

        let should_increase = latest_latency < self.critical_latency_threshold_ns / 2
            && inflight < current_permits / 3;

        if should_reduce && current_permits > self.min_permits {
            let new_permits = (current_permits * 9 / 10).max(self.min_permits);
            permit_manager.set_max_permits(new_permits);
            tracing::info!(
                event = "flow_control_reduce",
                current_permits = current_permits,
                new_permits = new_permits,
                latest_latency_ms = latest_latency / 1_000_000,
                inflight = inflight,
                dropped = dropped,
                "reducing permits due to high latency or load"
            );
        } else if should_increase && current_permits < self.max_permits.load(Ordering::Relaxed) {
            let new_permits = (current_permits * 11 / 10).min(self.max_permits.load(Ordering::Relaxed));
            permit_manager.set_max_permits(new_permits);
            tracing::info!(
                event = "flow_control_increase",
                current_permits = current_permits,
                new_permits = new_permits,
                latest_latency_ms = latest_latency / 1_000_000,
                inflight = inflight,
                dropped = dropped,
                "increasing permits - system performing well"
            );
        }
    }
}


/// 动态流控的 Permit 管理器 / Permit manager for dynamic flow control feedback
pub struct PermitManager {
    // Current active permits (acquired) / 当前活跃 permits（已获得）
    pub(crate) active_permits: AtomicUsize,
    // Maximum permits that can be granted / 可授予的最大 permits
    max_permits: AtomicUsize,
    // Last recovery timestamp (ms) / 上次恢复时间戳（毫秒）
    last_recovery_ms: AtomicU64,
    // Count of dropped requests due to pool exhaustion / 因pool耗尽而丢弃的请求计数
    dropped_requests: AtomicU64,
}

impl PermitManager {
    pub fn new(initial_permits: usize) -> Self {
        Self {
            active_permits: AtomicUsize::new(0),
            max_permits: AtomicUsize::new(initial_permits),
            last_recovery_ms: AtomicU64::new(0),
            dropped_requests: AtomicU64::new(0),
        }
    }

    /// 创建一个无限制的PermitManager（用于rustdns风格的无流控模式）
    /// Create an unlimited PermitManager (for rustdns-style no-flow-control mode)
    pub fn new_unlimited() -> Self {
        Self {
            active_permits: AtomicUsize::new(0),
            max_permits: AtomicUsize::new(usize::MAX),
            last_recovery_ms: AtomicU64::new(0),
            dropped_requests: AtomicU64::new(0),
        }
    }
    
    /// Try to acquire a permit without blocking / 非阻塞地尝试获取 permit
    /// Returns a guard that holds Arc<PermitManager> to ensure permit is released
    pub fn try_acquire(self: &Arc<Self>) -> Option<PermitGuard> {
        loop {
            let active = self.active_permits.load(Ordering::Acquire);
            let max = self.max_permits.load(Ordering::Acquire);
            
            if active >= max {
                // Pool exhausted: increment counter and log / Pool耗尽：增加计数器并记录
                let dropped = self.dropped_requests.fetch_add(1, Ordering::Relaxed);
                
                // Log every 1000 dropped requests to avoid spam / 每1000个丢弃请求记录一次，避免刷屏
                if dropped % 1000 == 0 {
                    tracing::warn!(
                        active = active,
                        max = max,
                        dropped_total = dropped + 1,
                        "UDP permit pool exhausted, requests are being dropped"
                    );
                    
                    // Trigger recovery check if pool is exhausted / 如果pool耗尽，触发恢复检查
                    self.check_and_recover();
                }
                return None;
            }
            
            match self.active_permits.compare_exchange(
                active,
                active + 1,
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(PermitGuard::new(Arc::clone(self))),
                Err(_) => continue, // Retry on CAS failure / CAS 失败时重试
            }
        }
    }
    
    /// Get current inflight permits count / 获取当前进行中的 permits 数
    #[inline]
    pub fn inflight(&self) -> usize {
        self.active_permits.load(Ordering::Acquire)
    }

    /// Update max permits for dynamic adjustment / 更新最大 permits 用于动态调整
    #[inline]
    pub fn set_max_permits(&self, new_max: usize) {
        self.max_permits.store(new_max, Ordering::Release);
    }

    /// Get current max permits / 获取当前最大 permits
    #[inline]
    pub fn max_permits(&self) -> usize {
        self.max_permits.load(Ordering::Acquire)
    }

    /// Get total dropped requests count / 获取总丢弃请求数
    #[inline]
    pub fn dropped_requests(&self) -> u64 {
        self.dropped_requests.load(Ordering::Relaxed)
    }

    /// Check and recover from permit leakage / 检查并从permit泄漏中恢复
    /// This should be called periodically or when pool exhaustion is detected
    /// 应该定期调用或在检测到pool耗尽时调用
    pub fn check_and_recover(&self) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let last_ms = self.last_recovery_ms.load(Ordering::Relaxed);
        
        // Only recover once per minute to avoid excessive recovery attempts
        // 每分钟只恢复一次，避免过度恢复尝试
        if now_ms.saturating_sub(last_ms) < 60_000 {
            return;
        }

        // Try to update recovery timestamp / 尝试更新恢复时间戳
        match self.last_recovery_ms.compare_exchange_weak(
            last_ms, now_ms, Ordering::AcqRel, Ordering::Relaxed
        ) {
            Ok(_) => {
                // We won the race, perform recovery / 我们赢得了竞争，执行恢复
                let active = self.active_permits.load(Ordering::Acquire);
                let max = self.max_permits.load(Ordering::Acquire);
                
                // If active permits exceed max significantly, it indicates leakage
                // 如果活跃permits显著超过最大值，表示有泄漏
                if active > max {
                    tracing::error!(
                        active = active,
                        max = max,
                        "Detected permit leakage: active permits exceed max, forcing recovery"
                    );
                    
                    // Force reset to max to recover from leakage / 强制重置为最大值以从泄漏中恢复
                    self.active_permits.store(max, Ordering::Release);
                    
                    let dropped = self.dropped_requests.load(Ordering::Relaxed);
                    tracing::warn!(
                        recovered = active - max,
                        dropped_total = dropped,
                        "Permit pool recovered from leakage"
                    );
                } else if active == max {
                    // Pool is full but not leaked, log for monitoring / Pool满了但没泄漏，记录用于监控
                    let dropped = self.dropped_requests.load(Ordering::Relaxed);
                    tracing::warn!(
                        active = active,
                        max = max,
                        dropped_total = dropped,
                        "Permit pool is at capacity, consider increasing max_permits or checking upstream health"
                    );
                }
            }
            Err(_) => {
                // Another thread is performing recovery, skip / 另一个线程正在执行恢复，跳过
            }
        }
    }

    /// Manual force recovery (for debugging or emergency use) / 手动强制恢复（用于调试或紧急情况）
    #[cfg(debug_assertions)]
    pub fn force_recover(&self) {
        let active = self.active_permits.load(Ordering::Acquire);
        let max = self.max_permits.load(Ordering::Acquire);
        
        if active > max {
            self.active_permits.store(max, Ordering::Release);
            tracing::warn!(
                active = active,
                max = max,
                "Force recovered permit pool"
            );
        }
    }

    /// Simulate permit leakage for testing purposes / 模拟permit泄漏用于测试
    /// This is a test-only method that should not be used in production code
    /// 这是一个仅用于测试的方法，不应在生产代码中使用
    #[cfg(any(test, debug_assertions))]
    pub fn simulate_leak(&self, count: usize) {
        self.active_permits.fetch_add(count, Ordering::Release);
    }
}

/// RAII guard for automatic permit release / RAII 守卫用于自动 permit 释放
/// 
/// This guard ensures that permits are properly released even in panic scenarios
/// by using defensive programming techniques.
/// 该守卫通过使用防御性编程技术，确保即使在panic场景下也能正确释放permits。
pub struct PermitGuard {
    manager: Arc<PermitManager>,
    released: AtomicBool, // Track if already released to handle double-drop / 跟踪是否已释放以处理双重释放
}

impl PermitGuard {
    fn new(manager: Arc<PermitManager>) -> Self {
        Self {
            manager,
            released: AtomicBool::new(false),
        }
    }

    /// Manually release the permit early / 提前手动释放permit
    /// This is useful if you want to release the permit before the guard is dropped
    /// 如果你想在guard被drop之前释放permit，这很有用
    pub fn release(self: Arc<Self>) {
        // Mark as released and decrement / 标记为已释放并递减
        if self.released.compare_exchange(
            false, true, Ordering::AcqRel, Ordering::Relaxed
        ).is_ok() {
            self.manager.active_permits.fetch_sub(1, Ordering::Release);
        }
    }
}

impl Drop for PermitGuard {
    fn drop(&mut self) {
        // Use compare_exchange to handle potential double-drop scenarios
        // 使用compare_exchange处理潜在的双重释放场景
        if self.released.compare_exchange(
            false, true, Ordering::AcqRel, Ordering::Relaxed
        ).is_ok() {
            self.manager.active_permits.fetch_sub(1, Ordering::Release);
        }
    }
}
