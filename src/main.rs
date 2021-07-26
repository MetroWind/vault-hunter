#![allow(non_snake_case)]

use tokio;

#[macro_use]
mod error;
mod config;
mod vault_client;
mod hunter;

use error::Error;

#[tokio::main]
async fn main() -> Result<(), Error>
{
    let matches = clap::App::new("Vault Hunter")
        .version("0.1")
        .author("MetroWind <chris.corsair@gmail.com>")
        .about("Personal password manager on top of HashiCorp Vault.")
        .arg(clap::Arg::with_name("PATTERN")
             .help("Pattern to search for")
             .required(true)
             .index(1))
        .get_matches();

    let conf = if let Some(path) = hunter::findConfigFile()
    {
        config::Config::fromfile(&path)?
    }
    else
    {
        config::Config::default()
    };

    let mut client = vault_client::Client::new(&conf)?;
    client.login().await?;
    hunter::searchReveal(&client, matches.value_of("PATTERN").unwrap(), &conf)
        .await
}
