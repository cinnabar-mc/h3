use std::{
    sync::{Arc, Mutex},
    task::{Context, Poll, Wake, Waker},
};

/// The three independently awaited operations that share the original HTTP3 driver.
#[derive(Clone, Copy)]
pub(super) enum Role {
    Maintenance,
    Uni,
    Bi,
}

/// Fans actual connection wakes out to the finite set of original driver waiters.
#[derive(Default)]
pub(super) struct DriverWake {
    waiters: Mutex<[Option<(Arc<()>, Waker)>; 3]>,
}

impl DriverWake {
    /// Owns one role registration until its borrowed wait completes or is canceled.
    pub(super) fn waiter(self: &Arc<Self>, role: Role) -> Waiter<'_> {
        Waiter {
            driver: self,
            role,
            token: Arc::new(()),
        }
    }

    /// Releases the slot lock before invoking any caller-provided task wake.
    fn wake_waiters(&self) {
        let waiters = {
            let mut registered = self.waiters.lock().unwrap();
            std::mem::take(&mut *registered)
        };
        for (_, waker) in waiters.into_iter().flatten() {
            waker.wake();
        }
    }
}

impl Wake for DriverWake {
    fn wake(self: Arc<Self>) {
        self.wake_waiters();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wake_waiters();
    }
}

/// Keeps cancellation from unregistering a replacement waiter's task.
pub(super) struct Waiter<'a> {
    driver: &'a Arc<DriverWake>,
    role: Role,
    token: Arc<()>,
}

impl Waiter<'_> {
    /// Registers the original caller before polling shared input with one stable connection waker.
    pub(super) fn poll<T>(
        &self,
        cx: &mut Context<'_>,
        poll: impl FnOnce(&mut Context<'_>) -> Poll<T>,
    ) -> Poll<T> {
        let replaced = {
            let mut waiters = self.driver.waiters.lock().unwrap();
            waiters[self.role as usize].replace((Arc::clone(&self.token), cx.waker().clone()))
        };
        drop(replaced);
        let waker = Waker::from(Arc::clone(self.driver));
        let result = poll(&mut Context::from_waker(&waker));
        if result.is_ready() {
            self.unregister();
        }
        result
    }

    /// Removes only this wait's registration and drops its saved task outside the lock.
    fn unregister(&self) {
        let removed = {
            let mut waiters = self.driver.waiters.lock().unwrap();
            let slot = &mut waiters[self.role as usize];
            match slot {
                Some((token, _)) if Arc::ptr_eq(token, &self.token) => slot.take(),
                _ => None,
            }
        };
        drop(removed);
    }
}

impl Drop for Waiter<'_> {
    fn drop(&mut self) {
        self.unregister();
    }
}

#[cfg(test)]
mod tests;
