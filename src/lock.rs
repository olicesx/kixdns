//! Lock abstraction layer.
//!
//! This module provides a unified interface for RwLock that can be easily switched
//! between std::sync::RwLock and parking_lot::RwLock for performance testing.
//!
//! 锁抽象层。提供 RwLock 的统一接口，可在 std::sync::RwLock 和 parking_lot::RwLock 之间切换。
//!
//! # Performance
//!
//! parking_lot::RwLock provides:
//! - ~3x faster read/write operations
//! - ~10x faster under contention
//! - Smaller memory footprint
//!
//! # Usage
//!
//! ```rust
//! # use kixdns::lock::RwLock;
//! # use std::sync::Arc;
//! #
//! let lock = Arc::new(RwLock::new(42));
//! {
//!     let r = lock.read();
//!     assert_eq!(*r, 42);
//! }
//! {
//!     let mut w = lock.write();
//!     *w = 100;
//! }
//! ```

// Use parking_lot for better performance
// 使用 parking_lot 获得更好的性能
pub use parking_lot::RwLock;

// Re-export guard types for convenience
// 重新导出 guard 类型以便使用
pub use parking_lot::{RwLockReadGuard, RwLockWriteGuard};

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_rwlock_basic_read() {
        let lock = RwLock::new(42);
        {
            let r = lock.read();
            assert_eq!(*r, 42);
        }
    }

    #[test]
    fn test_rwlock_basic_write() {
        let lock = RwLock::new(42);
        {
            let mut w = lock.write();
            *w = 100;
        }
        let r = lock.read();
        assert_eq!(*r, 100);
    }

    #[test]
    fn test_rwlock_concurrent_reads() {
        let lock = Arc::new(RwLock::new(42));
        let mut handles = vec![];

        for _ in 0..10 {
            let lock_clone = Arc::clone(&lock);
            let handle = thread::spawn(move || {
                let r = lock_clone.read();
                *r
            });
            handles.push(handle);
        }

        for handle in handles {
            assert_eq!(handle.join().unwrap(), 42);
        }
    }

    #[test]
    fn test_rwlock_read_write_blocking() {
        let lock = Arc::new(RwLock::new(42));
        let lock_clone = Arc::clone(&lock);

        // Spawn a thread that holds the read lock
        let read_handle = thread::spawn(move || {
            let r = lock_clone.read();
            // Hold the lock for a bit
            thread::sleep(std::time::Duration::from_millis(50));
            *r
        });

        // Give the read lock time to be acquired
        thread::sleep(std::time::Duration::from_millis(10));

        // Clone again for the write handle
        let lock_for_write = Arc::clone(&lock);
        // Try to acquire write lock (should block until read is released)
        let write_handle = thread::spawn(move || {
            let mut w = lock_for_write.write();
            *w = 100;
        });

        assert_eq!(read_handle.join().unwrap(), 42);
        write_handle.join().unwrap();

        let r = lock.read();
        assert_eq!(*r, 100);
    }

    #[test]
    fn test_rwlock_try_read() {
        let lock = RwLock::new(42);

        // Try read should succeed
        assert!(lock.try_read().is_some());

        // Acquire write lock
        let _w = lock.write();

        // Try read should fail now
        assert!(lock.try_read().is_none());
    }

    #[test]
    fn test_rwlock_try_write() {
        let lock = RwLock::new(42);

        // Try write should succeed
        assert!(lock.try_write().is_some());

        // Acquire another write lock
        let _w = lock.write();

        // Try write should fail now
        assert!(lock.try_write().is_none());
    }
}
