mod auth;
mod config;
mod hal;
mod reconciler;
mod server;
mod telemetry;
mod upgrade;

use std::env;
use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_usage() {
    eprintln!("rv180wd {VERSION} - Cisco RV180W next-gen control plane daemon");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  rv180wd --boot            Apply persisted config to hardware/services at boot");
    eprintln!("  rv180wd --serve           Start HTTP/HTTPS control plane server");
    eprintln!("  rv180wd --factory-reset   Reset /data/rv180w state to factory defaults");
    eprintln!("  rv180wd --version         Print version");
}

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("--boot") => {
            match config::boot::apply_boot_config() {
                Ok(summary) => {
                    println!("[rv180wd] boot apply complete: {summary}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("[rv180wd] boot apply failed: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Some("--serve") => {
            let cfg = server::ServerOptions::from_env();
            match server::run(cfg) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("[rv180wd] server failed: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Some("--factory-reset") => {
            match config::store::factory_reset_default_paths() {
                Ok(()) => {
                    println!("[rv180wd] factory reset completed");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("[rv180wd] factory reset failed: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Some("--version") | Some("-V") => {
            println!("rv180wd {VERSION}");
            ExitCode::SUCCESS
        }
        Some("--help") | Some("-h") | None => {
            print_usage();
            if matches!(env::args().nth(1).as_deref(), Some("--help") | Some("-h") | None) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Some(other) => {
            eprintln!("[rv180wd] unknown argument: {other}");
            print_usage();
            ExitCode::FAILURE
        }
    }
}
