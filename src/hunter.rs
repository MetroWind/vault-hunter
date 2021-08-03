use std::io::{stdin,stdout,Write};
use std::process::Command;

use crate::vault_client::Client;
use crate::error::Error;
use crate::config::Config;

fn promptForInput(prompt: &str) -> Result<String, Error>
{
    let mut s = String::new();
    print!("{}", prompt);
    let _ = stdout().flush();
    stdin().read_line(&mut s).map_err(|_| rterr!("Failed to read line"))?;

    if let Some('\n')=s.chars().next_back()
    {
        s.pop();
    }
    if let Some('\r')=s.chars().next_back()
    {
        s.pop();
    }
    Ok(s)
}

fn clipboardCopy(content: &str, conf: &Config) -> Result<bool, Error>
{
    if conf.clipboardProg().is_none()
    {
        return Ok(false);
    }

    let clipboard_prog = conf.clipboardProg().unwrap();
    if Command::new(&clipboard_prog)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .stdin(std::process::Stdio::null())
        .spawn().is_err()
    {
        return Ok(false);
    }

    let mut proc = Command::new(clipboard_prog)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn().map_err(|e| rterr!("Failed to run {}: {}",
                                    conf.clipboard_prog.as_ref().unwrap(), e))?;
    {
        let proc_stdin = proc.stdin.as_mut().unwrap();
        proc_stdin.write_all(content.as_bytes()).map_err(
            |e| rterr!("Failed to write clipboard: {}", e))?;
    }
    let status = proc.wait().map_err(
        |_| rterr!("Clipboard program failed to run"))?;
    if status.success()
    {
        Ok(true)
    }
    else
    {
        let code_str = if let Some(code) = status.code()
        {
            code.to_string()
        }
        else
        {
            String::from("??")
        };
        Err(rterr!("Clipboard program failed with code: {}", code_str))
    }
}

async fn revealPath(client: &Client<'_>, path: String, conf: &Config) -> Result<(), Error>
{
    let data = client.get(&path).await?;
    for (key, value) in &data
    {
        if key != "Password"
        {
            println!("{}: {}", key, value);
        }
    }

    if let Some(password) = data.get("Password")
    {
        if clipboardCopy(password, conf)?
        {
            println!("Password copied to clipboard.");
        }
        else
        {
            println!("Password: {}", password);
        }
    }
    Ok(())
}

/// Search for an entry and reveal the key-value pair in a way that is
/// appropriate to the end-user.
pub async fn searchReveal(client: &Client<'_>, pattern: &str, conf: &Config) ->
    Result<(), Error>
{
    let paths = client.search(pattern).await?;
    if paths.is_empty()
    {
        return Ok(());
    }
    if paths.len() == 1
    {
        return revealPath(client, paths[0].to_string(), conf).await;
    }

    // Multiple search result
    for i in 0..paths.len()
    {
        println!("{}. {}", i, paths[i]);
    }
    println!("");
    let choice = loop
    {
        if let Ok(choice) = promptForInput("Which entry? ")?.parse::<usize>()
        {
            if choice < paths.len()
            {
                break choice;
            }
        }
        println!("Invalid input");
    };
    revealPath(client, paths[choice].to_string(), conf).await
}
