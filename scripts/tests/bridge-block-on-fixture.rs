// Fixture for `scripts/check-bridge-block-on.py --self-test`. Never compiled.
//
// Function names carry the expected verdict: `flag_*` holds a blocking wait
// the gate must flag, `pass_*` production code that does not block and must
// not be flagged, and `test_*` test code the gate must not see. The gate is a
// whitelist, so a `ci-allow` directive exempts nothing.

fn flag_bare_block_on(rt: &tokio::runtime::Runtime) {
    rt.block_on(async {});
}

fn flag_multiline_block_on(rt: &tokio::runtime::Runtime) {
    let _ = rt
        .block_on(async { 1 });
}

fn flag_handle_block_on() {
    tokio::runtime::Handle::current().block_on(async {});
}

fn flag_block_on_in_macro(rt: &tokio::runtime::Runtime) {
    drop(vec![rt.block_on(async { 2 })]);
}

fn flag_block_on_in_closure(rt: &tokio::runtime::Runtime) {
    let run = || rt.block_on(async {});
    run();
}

#[cfg(feature = "testing")]
fn flag_testing_feature_is_not_test_code(rt: &tokio::runtime::Runtime) {
    rt.block_on(async {});
}

#[cfg(not(test))]
fn flag_cfg_not_test_is_production(rt: &tokio::runtime::Runtime) {
    rt.block_on(async {});
}

fn flag_old_trailing_directive(rt: &tokio::runtime::Runtime) {
    rt.block_on(async {}); // ci-allow: bridge-block-on: waits on no context actor
}

fn flag_old_directive_above(rt: &tokio::runtime::Runtime) {
    // ci-allow: bridge-block-on: the caller released the GIL
    rt.block_on(async {});
}

fn flag_block_in_place() {
    tokio::task::block_in_place(|| ());
}

fn flag_ufcs_handle_block_on(h: &tokio::runtime::Handle) {
    tokio::runtime::Handle::block_on(h, async {});
}

fn flag_futures_executor_block_on() {
    futures::executor::block_on(async {});
}

fn flag_renaming_use() {
    use tokio::task::block_in_place as bip;
    bip(|| ());
}

fn flag_method_value(rt: &tokio::runtime::Runtime) {
    let wait = tokio::runtime::Runtime::block_on::<std::future::Ready<()>>;
    wait(rt, std::future::ready(()));
}

fn flag_second_helper_outside_the_helper_file(rt: &tokio::runtime::Runtime) {
    fn drive(rt: &tokio::runtime::Runtime) {
        rt.block_on(async {});
    }
    drive(rt);
}

// `cfg_attr(test, ..)` changes attributes, not whether the item compiles.
#[cfg_attr(test, allow(dead_code))]
fn flag_cfg_attr_test_is_not_test_code(rt: &tokio::runtime::Runtime) {
    rt.block_on(async {});
}

// Compiles into every build with the `testing` feature.
#[cfg(any(test, feature = "testing"))]
fn flag_cfg_any_test_or_testing_is_production(rt: &tokio::runtime::Runtime) {
    rt.block_on(async {});
}

#[cfg(any(test, feature = "testing"))]
mod testing_or_test {
    fn flag_in_cfg_any_test_or_testing_module(rt: &tokio::runtime::Runtime) {
        rt.block_on(async {});
    }
}

fn flag_std_thread_sleep(d: std::time::Duration) {
    std::thread::sleep(d);
}

fn flag_thread_sleep_through_a_module_use(d: std::time::Duration) {
    use std::thread;
    thread::sleep(d);
}

fn flag_use_of_thread_sleep() {
    use std::thread::sleep as nap;
}

fn flag_use_list_of_thread_sleep() {
    use std::thread::{self, sleep};
}

fn flag_thread_sleep_in_a_macro(d: std::time::Duration) {
    drop(vec![std::thread::sleep(d)]);
}

fn flag_sync_channel_recv(rx: &std::sync::mpsc::Receiver<u8>) {
    let _ = rx.recv();
}

fn flag_sync_channel_recv_in_a_macro(rx: &std::sync::mpsc::Receiver<u8>) {
    drop(vec![rx.recv()]);
}

fn flag_ufcs_sync_channel_recv(rx: &std::sync::mpsc::Receiver<u8>) {
    let _ = std::sync::mpsc::Receiver::recv(rx);
}

fn flag_recv_timeout(rx: &std::sync::mpsc::Receiver<u8>, d: std::time::Duration) {
    let _ = rx.recv_timeout(d);
}

fn flag_recv_deadline(rx: &std::sync::mpsc::Receiver<u8>, at: std::time::Instant) {
    let _ = rx.recv_deadline(at);
}

fn flag_recv_timeout_in_a_closure(rx: &std::sync::mpsc::Receiver<u8>, d: std::time::Duration) {
    let wait = || rx.recv_timeout(d);
    let _ = wait();
}

fn flag_condvar_wait(cv: &std::sync::Condvar, m: &std::sync::Mutex<bool>) {
    let g = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let _ = cv.wait(g);
}

fn flag_ufcs_condvar_wait(cv: &std::sync::Condvar, m: &std::sync::Mutex<bool>) {
    let g = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let _ = std::sync::Condvar::wait(cv, g);
}

fn flag_condvar_wait_while(cv: &std::sync::Condvar, m: &std::sync::Mutex<bool>) {
    let g = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let _ = cv.wait_while(g, |ready| !*ready);
}

fn flag_condvar_wait_timeout(cv: &std::sync::Condvar, m: &std::sync::Mutex<bool>) {
    let g = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let _ = cv.wait_timeout(g, std::time::Duration::from_millis(1));
}

fn flag_condvar_wait_timeout_while(cv: &std::sync::Condvar, m: &std::sync::Mutex<bool>) {
    let g = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let _ = cv.wait_timeout_while(g, std::time::Duration::from_millis(1), |r| !*r);
}

fn flag_blocking_recv(rx: &mut tokio::sync::mpsc::Receiver<u8>) {
    let _ = rx.blocking_recv();
}

fn flag_blocking_send(tx: &tokio::sync::mpsc::Sender<u8>) {
    let _ = tx.blocking_send(1);
}

fn flag_blocking_lock(m: &tokio::sync::Mutex<u8>) {
    let _ = m.blocking_lock();
}

fn flag_blocking_lock_in_a_macro(m: &tokio::sync::Mutex<u8>) {
    drop(vec![*m.blocking_lock()]);
}

// A wait on another thread: `std::thread`'s `JoinHandle::join`.
fn flag_thread_join(h: std::thread::JoinHandle<()>) {
    let _ = h.join();
}

fn flag_ufcs_thread_join(h: std::thread::JoinHandle<()>) {
    let _ = std::thread::JoinHandle::join(h);
}

fn flag_thread_join_through_a_renaming_use() {
    use std::thread::JoinHandle as Worker;
    let h: Worker<()> = std::thread::spawn(|| ());
    let _ = Worker::join(h);
}

fn flag_thread_join_in_a_macro(h: std::thread::JoinHandle<()>) {
    drop(vec![h.join()]);
}

fn flag_ufcs_thread_join_in_a_macro(h: std::thread::JoinHandle<()>) {
    drop(vec![std::thread::JoinHandle::join(h)]);
}

fn flag_scoped_thread_join() {
    let _ = std::thread::scope(|s| {
        s.spawn(|| ())
            .join()
    });
}

fn flag_use_of_thread_scope() {
    use std::thread::scope;
}

// A wait on another thread: `std::thread::park` and `park_timeout`.
fn flag_thread_park() {
    std::thread::park();
}

fn flag_thread_park_timeout(d: std::time::Duration) {
    std::thread::park_timeout(d);
}

fn flag_thread_park_through_a_module_use() {
    use std::thread;
    thread::park();
}

fn flag_use_of_thread_park() {
    use std::thread::park;
}

fn flag_renaming_use_of_thread_park_timeout() {
    use std::thread::park_timeout as doze;
}

fn flag_use_list_of_thread_park() {
    use std::thread::{self, park};
}

fn flag_thread_park_in_a_macro() {
    drop(vec![std::thread::park()]);
}

fn flag_thread_park_timeout_in_a_macro(d: std::time::Duration) {
    drop(vec![std::thread::park_timeout(d)]);
}

fn flag_glob_use_of_thread() {
    use std::thread::*;
}

fn flag_nested_glob_use_of_thread() {
    use std::{thread::*};
}

fn pass_vec_join(v: &[String]) {
    let _ = v.join(",");
}

fn pass_vec_join_in_a_macro(v: &[String]) {
    drop(vec![v.join(",")]);
}

fn pass_ufcs_slice_join(v: &[String]) {
    let _ = <[String]>::join(v, ",");
}

fn pass_path_join() {
    let _ = std::path::Path::new("a").join("b");
}

async fn pass_awaited_tokio_join_handle(h: tokio::task::JoinHandle<u8>) {
    let _ = h.await;
}

async fn pass_awaited_tokio_join_handle_in_a_macro(h: tokio::task::JoinHandle<u8>) {
    drop(vec![h.await]);
}

async fn pass_join_set_join_next(set: &mut tokio::task::JoinSet<u8>) {
    while let Some(r) = set.join_next().await {
        drop(r);
    }
}

async fn pass_join_set_join_next_in_a_macro(set: &mut tokio::task::JoinSet<u8>) {
    drop(vec![set.join_next().await]);
}

async fn pass_tokio_join_macro() {
    let _ = tokio::join!(async { 1 }, async { 2 });
}

async fn pass_futures_join() {
    let _ = futures::future::join(async { 1 }, async { 2 }).await;
}

fn pass_thread_unpark(t: &std::thread::Thread) {
    t.unpark();
}

async fn pass_awaited_recv(rx: &mut tokio::sync::mpsc::Receiver<u8>) {
    let _ = rx.recv().await;
}

async fn pass_awaited_recv_in_a_macro(rx: &mut tokio::sync::mpsc::Receiver<u8>) {
    drop(vec![rx.recv().await]);
}

async fn pass_select_arm_recv(rx: &mut tokio::sync::mpsc::Receiver<u8>) {
    tokio::select! {
        v = rx.recv() => drop(v),
        () = tokio::time::sleep(std::time::Duration::from_millis(1)) => {}
    }
}

async fn pass_awaited_barrier_wait(b: &tokio::sync::Barrier) {
    let _ = b.wait().await;
}

async fn pass_tokio_sleep() {
    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
}

fn pass_try_recv(rx: &Receiver<u8>) {
    let _ = rx.try_recv();
}

fn flag_receiver_iter(rx: &Receiver<u8>) {
    for _ in rx.iter() {}
}

fn flag_field_receiver_into_iter(s: State) {
    let _: Vec<u8> = s.event_rx.into_iter().collect();
}

fn flag_receiver_iter_in_a_macro(rx: &Receiver<u8>) {
    drop(vec![rx.iter().count()]);
}

fn flag_for_loop_over_receiver(rx: Receiver<u8>) {
    for m in rx {
        drop(m);
    }
}

fn flag_for_loop_over_borrowed_receiver(receiver: &Receiver<u8>) {
    for m in &receiver {
        drop(m);
    }
}

fn flag_for_loop_over_field_receiver(&mut self) {
    for m in &mut self.cmd_rx {
        drop(m);
    }
}

fn flag_for_loop_over_receiver_in_a_macro(rx: Receiver<u8>) {
    run!({ for m in rx { drop(m); } });
}

fn pass_vec_iter(v: &[u8]) {
    for _ in v.iter() {}
    for _ in v {}
}

fn pass_receiver_try_iter(rx: &Receiver<u8>) {
    for _ in rx.try_iter() {}
}

fn flag_shutdown_timeout(rt: tokio::runtime::Runtime) {
    rt.shutdown_timeout(std::time::Duration::from_secs(1));
}

fn flag_thread_sleep_ms() {
    std::thread::sleep_ms(1);
}

fn flag_parking_lot_wait_for(cv: &parking_lot::Condvar, g: &mut parking_lot::MutexGuard<'_, u8>) {
    let _ = cv.wait_for(g, std::time::Duration::from_millis(1));
}

fn flag_parking_lot_wait_until(cv: &parking_lot::Condvar, g: &mut parking_lot::MutexGuard<'_, u8>) {
    let _ = cv.wait_until(g, std::time::Instant::now());
}

fn flag_parking_lot_wait_while_for(cv: &parking_lot::Condvar, g: &mut parking_lot::MutexGuard<'_, u8>) {
    cv.wait_while_for(g, |v| *v == 0, std::time::Duration::from_millis(1));
}

fn flag_parking_lot_wait_while_until(cv: &parking_lot::Condvar, g: &mut parking_lot::MutexGuard<'_, u8>) {
    cv.wait_while_until(g, |v| *v == 0, std::time::Instant::now());
}

fn flag_ufcs_condvar_wait_for(cv: &parking_lot::Condvar, g: &mut parking_lot::MutexGuard<'_, u8>) {
    let _ = parking_lot::Condvar::wait_for(cv, g, std::time::Duration::from_millis(1));
}

fn flag_condvar_wait_for_in_a_macro(cv: &parking_lot::Condvar, g: &mut parking_lot::MutexGuard<'_, u8>) {
    drop(vec![cv.wait_for(g, std::time::Duration::from_millis(1))]);
}

async fn pass_tokio_watch_wait_for(rx: &mut tokio::sync::watch::Receiver<u8>) {
    let _ = rx.wait_for(|v| *v == 1).await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(1), rx.wait_for(|v| *v == 1)).await;
    let _ = tokio::sync::watch::Receiver::wait_for(rx, |v| *v == 1).await;
}

async fn pass_tokio_watch_wait_for_in_a_macro(rx: &mut tokio::sync::watch::Receiver<u8>) {
    drop(vec![tokio::time::timeout(std::time::Duration::from_secs(1), rx.wait_for(|v| *v == 1))]);
}

fn flag_std_mpsc_path() {
    let (_tx, _rx) = std::sync::mpsc::channel::<u8>();
}

fn flag_std_mpsc_type(_rx: std::sync::mpsc::Receiver<u8>) {}

fn flag_bare_sync_mpsc_path() {
    let (_tx, _rx) = sync::mpsc::sync_channel::<u8>(1);
}

fn flag_std_mpsc_in_a_macro() {
    drop(vec![std::sync::mpsc::channel::<u8>()]);
}

fn flag_use_std_mpsc() {
    use std::sync::mpsc::channel;
}

fn flag_use_list_std_mpsc() {
    use std::sync::{Mutex, mpsc};
}

fn flag_glob_use_of_std_sync() {
    use std::sync::*;
}

fn flag_crossbeam_channel() {
    let (_tx, _rx) = crossbeam_channel::unbounded::<u8>();
}

fn flag_use_crossbeam_channel() {
    use crossbeam_channel::Receiver;
}

fn pass_tokio_mpsc() {
    use tokio::sync::{Mutex, mpsc};
    let (_tx, _rx) = tokio::sync::mpsc::channel::<u8>(1);
    drop(vec![tokio::sync::mpsc::unbounded_channel::<u8>()]);
}

fn pass_std_mutex_lock(m: &std::sync::Mutex<u8>) {
    use std::sync::{Arc, Mutex};
    let _ = m.lock();
}

#[cfg(all(test, feature = "testing"))]
fn test_cfg_all_test_and_testing(rt: &tokio::runtime::Runtime) {
    rt.block_on(async {});
    std::thread::sleep(std::time::Duration::from_millis(1));
}

#[cfg(test)]
fn test_cfg_test_fn_blocking_shapes(rx: &std::sync::mpsc::Receiver<u8>) {
    let _ = rx.recv_timeout(std::time::Duration::from_millis(1));
}

#[cfg(test)]
fn test_cfg_test_thread_join_and_park(h: std::thread::JoinHandle<()>) {
    let _ = h.join();
    std::thread::park();
}

#[test]
fn test_plain_test_fn() {
    tokio::runtime::Runtime::new().unwrap().block_on(async {});
}

#[tokio::test]
async fn test_tokio_test_fn() {
    let _ = tokio::runtime::Handle::current();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {});
}

#[cfg(test)]
mod helpers {
    fn test_in_cfg_test_module(rt: &tokio::runtime::Runtime) {
        rt.block_on(async {});
    }
}

// A module's name does not make it test code: without `cfg(test)` it
// compiles into production.
mod tests {
    fn flag_in_tests_module_without_cfg_test(rt: &tokio::runtime::Runtime) {
        rt.block_on(async {});
    }
}
