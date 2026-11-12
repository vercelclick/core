/**
* To keep some of our secrets to ourselves for IP protection,
* We've opted to keep a majority of the logic in a private core package that this package inherits from
* Over time we do intend to opensource pieces of the core, or the full core logic.
**/
use clap::Parser;
use click_local::cli;

fn main() {
    let click_cli = cli::Cli::parse();

    click_cli.execute()
}
