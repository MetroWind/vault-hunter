use std::io::{stdin,stdout,Write};
use std::process::Command;
use chrono::prelude::*;

use crate::vault_client::{Client, KeyOrDir, Path};
use crate::error::Error;
use crate::config::Config;
use crate::runtime_info::{getRuntimeInfo, setRuntimeInfo};

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
            std::thread::sleep(std::time::Duration::from_secs(1));
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

async fn exportEntry(client: &Client<'_>,
                     writer: &mut quick_xml::Writer<std::io::Cursor<Vec<u8>>>,
                     path: &str) -> Result<(), Error>
{
    let data = client.get(&path).await?;
    writer.create_element("entry").with_attribute(("path", path))
        .write_inner_content(|writer| {
            for (key, value) in &data
            {
                writer.create_element("kv").write_inner_content(|kv_writer| {
                    kv_writer.create_element("key").write_text_content(
                        quick_xml::events::BytesText::from_plain_str(key))?;
                    kv_writer.create_element("value").write_text_content(
                        quick_xml::events::BytesText::from_plain_str(value))?;
                    Ok(())
                })?;
            }
            Ok(())
        }).map_err(|e| rterr!("Failed to write entry: {}", e))?;
    return Ok(());
}

/// Export passwords as an XML string.
async fn passwordsToXML(client: &Client<'_>) -> Result<Vec<u8>, Error>
{
    let mut to_search: Vec<Path> = vec![Path::new(),];
    let mut writer = quick_xml::Writer::new_with_indent(
        std::io::Cursor::new(Vec::new()), 32, 2);

    // Breath-first search through all entries.
    while !to_search.is_empty()
    {
        let mut next_to_search: Vec<Path> = Vec::default();
        for path in &to_search
        {
            for item in client.list(&path.to_string()).await?
            {
                match item
                {
                    KeyOrDir::Key(name) =>
                    {
                        let full_path = path.pushed(&name);
                        exportEntry(client, &mut writer,
                                    &full_path.to_string()).await?;
                    },
                    KeyOrDir::Dir(name) =>
                    {
                        next_to_search.push(path.pushed(&name));
                    },
                }
            }
        }
        to_search = next_to_search;
    }

    Ok(writer.into_inner().into_inner())
}

/// Encrypt bytes with GPG to a file.
fn gpgEncrypt(data: Vec<u8>, filename: &str, user: &str) -> Result<(), Error>
{
    let mut proc = Command::new("gpg").args(
        ["--yes", "-r", user , "--encrypt", "-a", "-o",])
        .arg(filename).arg("-")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn().map_err(|e| rterr!("Failed to run GPG: {}", e))?;
    {
        let proc_stdin = proc.stdin.as_mut().unwrap();
        proc_stdin.write_all(&data).map_err(
            |e| rterr!("Failed to input to GPG: {}", e))?;
    }
    let status = proc.wait().map_err(|_| rterr!("GPG failed to run"))?;
    if status.success()
    {
        Ok(())
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
        Err(rterr!("GPG failed with code: {}", code_str))
    }
}

pub async fn exportPasswords(client: &Client<'_>, conf: &Config) ->
    Result<(), Error>
{
    let last_xml_time: DateTime<Utc> = if let Some(t_str) =
        getRuntimeInfo("last_xml_export_time", conf)?
    {
        t_str.parse().unwrap()
    }
    else
    {
        chrono::MIN_DATETIME
    };

    let now = Utc::now();
    if (now - last_xml_time).num_seconds() < conf.xml_export_period
    {
        return Ok(())
    }

    let gpg_user = if let Some(u) = &conf.gpg_user
    {
        u
    }
    else
    {
        return Err(rterr!("No GPG user provided."));
    };

    println!("Exporting XML...");
    let xml = passwordsToXML(client).await?;
    gpgEncrypt(xml, &conf.local_xml.as_ref().unwrap(), gpg_user)?;
    setRuntimeInfo("last_xml_export_time", Some(&now.to_rfc3339()), conf)
}
