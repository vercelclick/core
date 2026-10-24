use clap::Parser;

pub mod backend;
pub mod cli;
pub mod command;
pub mod config;
pub mod service;
pub mod utils;

fn main() {
    let spass_cli = cli::Cli::parse();

    spass_cli.execute();
}
