//! Standalone, runnable egress gateway binary: a single process that binds
//! the DNS broker (loopback UDP+TCP) and the CONNECT egress broker
//! (loopback TCP), sharing one `PolicyEngine`, one injectable resolver, and
//! critically, one `AuthorizationCache`.
//!
//! This colocation is deliberate and load-bearing: the design's claim that
//! a CONNECT request can be satisfied by an authorization the DNS broker
//! already recorded (see `ConnectBroker::resolve_pinned`) is only true if
//! both brokers share the *same* cache instance. Running the DNS broker and
//! the CONNECT broker as two separate OS processes (as this spike's earlier
//! `dns-broker`/`egress-broker` binaries did) would give each its own,
//! disjoint `AuthorizationCache`, silently contradicting that claim. This
//! binary is therefore the one used by the live namespace harness and by
//! the "runnable local behavior" instructions in
//! `docs/egress-enforcement-spike.md`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use egress_enforcement_spike::authorization::AuthorizationCache;
use egress_enforcement_spike::connect_broker::{ConnectBroker, ConnectBrokerConfig};
use egress_enforcement_spike::dns_broker::{DnsBroker, DnsBrokerConfig};
use egress_enforcement_spike::fixture_file::{load_fixtures, load_policy};
use egress_enforcement_spike::policy::PolicyEngine;
use tokio::net::{TcpListener, UdpSocket};

#[derive(Parser, Debug)]
#[command(
    about = "Runnable local egress gateway (shared DNS + CONNECT brokers) for the egress-enforcement spike"
)]
struct Args {
    /// JSON network policy file.
    #[arg(long)]
    policy: PathBuf,
    /// JSON fixture resolution map file.
    #[arg(long)]
    fixtures: PathBuf,
    /// Loopback address for the DNS broker. UDP and TCP bind the same
    /// address/port.
    #[arg(long, default_value = "127.0.0.1:15053")]
    dns_listen: SocketAddr,
    /// Loopback address for the CONNECT egress broker.
    #[arg(long, default_value = "127.0.0.1:15080")]
    connect_listen: SocketAddr,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();

    let policy = match load_policy(&args.policy) {
        Ok(policy) => policy,
        Err(err) => {
            eprintln!("{{\"error\":\"{err}\"}}");
            return ExitCode::FAILURE;
        }
    };
    let engine = match PolicyEngine::compile(&policy) {
        Ok(engine) => Arc::new(engine),
        Err(err) => {
            eprintln!("{{\"error\":\"{err}\"}}");
            return ExitCode::FAILURE;
        }
    };
    let resolver = match load_fixtures(&args.fixtures) {
        Ok(resolver) => resolver,
        Err(err) => {
            eprintln!("{{\"error\":\"{err}\"}}");
            return ExitCode::FAILURE;
        }
    };

    let udp_socket = match UdpSocket::bind(args.dns_listen).await {
        Ok(socket) => socket,
        Err(err) => {
            eprintln!(
                "{{\"error\":\"failed to bind dns udp {}: {err}\"}}",
                args.dns_listen
            );
            return ExitCode::FAILURE;
        }
    };
    let tcp_listener = match TcpListener::bind(args.dns_listen).await {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!(
                "{{\"error\":\"failed to bind dns tcp {}: {err}\"}}",
                args.dns_listen
            );
            return ExitCode::FAILURE;
        }
    };
    let connect_listener = match TcpListener::bind(args.connect_listen).await {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!(
                "{{\"error\":\"failed to bind connect {}: {err}\"}}",
                args.connect_listen
            );
            return ExitCode::FAILURE;
        }
    };

    // The single shared authorization cache is what makes a CONNECT
    // request able to reuse a DNS-broker resolution (and vice versa).
    let authorizations = Arc::new(AuthorizationCache::new());

    let dns_broker = DnsBroker::new(
        Arc::clone(&engine),
        Arc::clone(&resolver),
        Arc::clone(&authorizations),
        DnsBrokerConfig::default(),
    );
    let connect_broker = ConnectBroker::new(
        engine,
        resolver,
        authorizations,
        ConnectBrokerConfig::default(),
    );

    println!(
        "{{\"status\":\"listening\",\"dns\":\"{}\",\"connect\":\"{}\"}}",
        args.dns_listen, args.connect_listen
    );

    let udp_task = {
        let dns_broker = Arc::clone(&dns_broker);
        tokio::spawn(async move { dns_broker.run_udp(udp_socket).await })
    };
    let dns_tcp_task = tokio::spawn(async move { dns_broker.run_tcp(tcp_listener).await });
    let connect_task = tokio::spawn(async move { connect_broker.run(connect_listener).await });

    let result = tokio::select! {
        result = udp_task => result,
        result = dns_tcp_task => result,
        result = connect_task => result,
    };

    match result {
        Ok(Ok(())) => ExitCode::SUCCESS,
        Ok(Err(err)) => {
            eprintln!("{{\"error\":\"gateway loop failed: {err}\"}}");
            ExitCode::FAILURE
        }
        Err(err) => {
            eprintln!("{{\"error\":\"gateway task panicked: {err}\"}}");
            ExitCode::FAILURE
        }
    }
}
