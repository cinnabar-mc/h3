use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

/// Records wake delivery without polling or scheduling another operation.
#[derive(Default)]
struct CountWake(AtomicUsize);

impl Wake for CountWake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn canceling_an_old_wait_preserves_its_replacement_and_releases_caller_wakers() {
    let driver = Arc::new(DriverWake::default());
    let stale = driver.waiter(Role::Uni);
    let replacement = driver.waiter(Role::Uni);
    let old_count = Arc::new(CountWake::default());
    let old_waker = Waker::from(Arc::clone(&old_count));
    let new_count = Arc::new(CountWake::default());
    let new_waker = Waker::from(Arc::clone(&new_count));
    assert!(stale
        .poll(&mut Context::from_waker(&old_waker), |_| {
            Poll::<()>::Pending
        })
        .is_pending());
    assert!(replacement
        .poll(&mut Context::from_waker(&new_waker), |_| {
            Poll::<()>::Pending
        })
        .is_pending());
    drop(stale);
    Waker::from(Arc::clone(&driver)).wake();
    assert_eq!(old_count.0.load(Ordering::SeqCst), 0);
    assert_eq!(new_count.0.load(Ordering::SeqCst), 1);

    assert!(replacement
        .poll(&mut Context::from_waker(&new_waker), |_| {
            Poll::<()>::Pending
        })
        .is_pending());
    let caller = Arc::downgrade(&new_count);
    drop((new_count, new_waker));
    drop(replacement);
    assert!(
        caller.upgrade().is_none(),
        "canceled wait retained its task"
    );
}

#[test]
fn shared_pending_polls_remain_quiet_until_the_driver_wakes_every_role() {
    let driver = Arc::new(DriverWake::default());
    let waits = [
        driver.waiter(Role::Maintenance),
        driver.waiter(Role::Uni),
        driver.waiter(Role::Bi),
    ];
    let counts: [_; 3] = std::array::from_fn(|_| Arc::new(CountWake::default()));
    for _ in 0..2 {
        for (waiter, count) in waits.iter().zip(&counts) {
            let waker = Waker::from(Arc::clone(count));
            assert!(waiter
                .poll(&mut Context::from_waker(&waker), |_| Poll::<()>::Pending)
                .is_pending());
        }
    }
    assert!(counts
        .iter()
        .all(|count| count.0.load(Ordering::SeqCst) == 0));
    let input = Waker::from(Arc::clone(&driver));
    input.wake_by_ref();
    assert!(counts
        .iter()
        .all(|count| count.0.load(Ordering::SeqCst) == 1));
    // A role already scheduled by input stays quiet until it polls and subscribes again.
    input.wake_by_ref();
    assert!(counts
        .iter()
        .all(|count| count.0.load(Ordering::SeqCst) == 1));

    let completed_waker = Waker::from(Arc::clone(&counts[2]));
    assert!(waits[2]
        .poll(&mut Context::from_waker(&completed_waker), |_| {
            Poll::Ready(())
        })
        .is_ready());
    input.wake_by_ref();
    assert_eq!(counts[2].0.load(Ordering::SeqCst), 1);
}
