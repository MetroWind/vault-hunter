#![allow(non_snake_case)]

use tokio;

#[macro_use]
mod error;
mod config;
mod runtime_info;
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
             .required(false)
             .index(1))
        .arg(clap::Arg::with_name("token-info")
             .long("token-info").help("Print token info"))
        .arg(clap::Arg::with_name("logout")
             .long("logout").help("Logout before doing anything"))
        .arg(clap::Arg::with_name("list-mounts")
             .long("list-mounts").help("List mounts"))
        .get_matches();

    let conf = if let Some(path) = config::findConfigFile()
    {
        config::Config::fromfile(&path)?
    }
    else
    {
        config::Config::default()
    };

    if matches.is_present("logout")
    {
        let mut client = vault_client::Client::new(&conf)?;
        if client.loginUsingCachedToken().is_ok()
        {
            client.logout().await?;
        }
    }
    if matches.is_present("token-info")
    {
        let mut client = vault_client::Client::new(&conf)?;
        client.loginUsingCachedToken()?;
        let info: serde_json::Value = client.lookupToken().await?;
        println!("{}", serde_json::to_string_pretty(&info).unwrap());
        return Ok(());
    }
    if matches.is_present("list-mounts")
    {
        let mut client = vault_client::Client::new(&conf)?;
        client.login().await?;
        let data = client.listMounts().await?;
        println!("{}", serde_json::to_string_pretty(&data).unwrap());
        return Ok(());
    }

    // Key lookup
    if !matches.is_present("PATTERN")
    {
        return Err(rterr!("Expecting PATTERN"));
    }

    let mut client = vault_client::Client::new(&conf)?;
    client.login().await?;
    if conf.local_xml.is_some()
    {
        hunter::exportPasswords(&client, &conf).await?;
    }
    hunter::searchReveal(&client, matches.value_of("PATTERN").unwrap(), &conf)
        .await
}
