//! A nostr relay on 127.0.0.1 that keeps events in memory, for local demos with the device
//! simulator (`just demo-sp-contacts`). Point the app at it with
//! `FROSTSNAP_NOSTR_RELAYS=ws://127.0.0.1:<port>`.
//!
//! `cargo run -p frostsnap_nostr --example local_relay -- [port]` (default 7777)

use nostr_relay_builder::prelude::*;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let port = match std::env::args().nth(1) {
        Some(port) => port.parse()?,
        None => 7777,
    };
    // The default of 60 events a minute per connection is too few for an app that republishes a
    // book or rejoins a channel.
    let builder = RelayBuilder::default().port(port).rate_limit(RateLimit {
        max_reqs: 500,
        notes_per_minute: 6000,
    });
    let relay = LocalRelay::new(builder);
    relay.run().await?;
    println!("RELAY URL {}", relay.url().await);
    tokio::signal::ctrl_c().await?;
    relay.shutdown();
    Ok(())
}
