mod proxy;
mod response;
mod request;

use clap::Parser;

/// Contains information parsed from the command-line invocation of balancebeam. The Clap macros
/// provide a fancy way to automatically construct a command-line argument parser.
#[derive(Parser, Debug)]
#[clap(about = "Fun with load balancing")]
pub struct CmdOptions {
    #[clap(
        short,
        long,
        help = "IP/port to bind to",
        default_value = "0.0.0.0:1100"
    )]
    bind: String,
    #[clap(
        short,
        long,
        multiple_occurrences = true,
        help = "Upstream host to forward requests to"
    )]
    upstream: Vec<String>,
    #[clap(
        long,
        help = "Perform active health checks on this interval (in seconds)",
        default_value = "10"
    )]
    active_health_check_interval: usize,
    #[clap(
        long,
        help = "Path to send request to for active health checks",
        default_value = "/"
    )]
    active_health_check_path: String,
    #[clap(
        long,
        help = "Maximum number of requests to accept per IP per minute (0 = unlimited)",
        default_value = "0"
    )]
    max_requests_per_minute: usize,
}

#[tokio::main]
async fn main() {
    // Initialize the logging library. You can print log messages using the `log` macros:
    // https://docs.rs/log/0.4.8/log/ You are welcome to continue using print! statements; this
    // just looks a little prettier.
    if let Err(_) = std::env::var("RUST_LOG") {
        std::env::set_var("RUST_LOG", "debug");
    }
    pretty_env_logger::init();

    // Parse the command line arguments passed to this program
    let options = CmdOptions::parse();
    if options.upstream.len() < 1 {
        log::error!("At least one upstream server must be specified using the --upstream option.");
        std::process::exit(1);
    }

    let proxy = proxy::Proxy::new(options);
    proxy.start().await;
}
