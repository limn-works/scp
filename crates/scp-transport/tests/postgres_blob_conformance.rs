//! Conformance tests for `PostgresBlobStore`.
//!
//! Applies the [`blob_store_conformance`] macro to the `PostgreSQL` blob store
//! (persistence spec §17.11). The tests need a live server named by
//! `DATABASE_URL` whose role may run `CREATE DATABASE`; each test opens its
//! own database there. CI's blob-backend step starts the server.
#![cfg(feature = "postgres-blob")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use scp_transport::native::postgres_blob::PostgresBlobStore;
use scp_transport::native::storage::ClockFn;
use sqlx::postgres::PgPoolOptions;

/// Creates a database no other test uses on the `DATABASE_URL` server and
/// returns its URL. Without `DATABASE_URL` the test fails rather than
/// passing with no server.
async fn isolated_database_url() -> String {
    let server = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL names the PostgreSQL server these tests run against");
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&server)
        .await
        .expect("connect to the DATABASE_URL server");
    let name = format!("scp_conf_{:016x}", rand::random::<u64>());
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&admin)
        .await
        .expect("create the test database");
    admin.close().await;
    let mut url = url::Url::parse(&server).expect("DATABASE_URL is a URL");
    url.set_path(&name);
    url.to_string()
}

async fn make_postgres_blob_store() -> (PostgresBlobStore, Arc<AtomicU64>) {
    let clock = Arc::new(AtomicU64::new(1_000_000));
    let clock_fn: ClockFn = {
        let c = clock.clone();
        Arc::new(move || c.load(Ordering::Relaxed))
    };
    let store = PostgresBlobStore::open_with_clock(&isolated_database_url().await, clock_fn)
        .await
        .expect("PostgreSQL store should open");
    (store, clock)
}

scp_testing::blob_store_conformance!(make_postgres_blob_store().await);
