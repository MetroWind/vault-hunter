use std::fs::File;
use std::io::BufReader;

use crate::error::Error;
use crate::config::Config;

/// Set a key-value in the runtime info file. If the file path
/// cannot be determined, do nothing and return Ok.
pub fn setRuntimeInfo(key: &str, value: Option<&str>, config: &Config) ->
    Result<(), Error>
{
    let mut data = serde_json::Value::default();
    if let Some(file_path) = config.runtimeInfoPath()
    {
        if file_path.exists()
        {
            let file = File::open(&file_path).map_err(
                |_| rterr!("Failed to open runtime info file"))?;
            let reader = BufReader::new(file);
            data = serde_json::from_reader(reader).map_err(
                |_| rterr!("Failed to read JSON from runtime info file"))?;
        }
        if let Some(v) = value
        {
            data[key] = serde_json::Value::String(v.to_owned());
        }
        else
        {
            data[key] = serde_json::Value::Null;
        }
        let file = File::create(file_path).map_err(
            |_| rterr!("Failed to open runtime info file"))?;
        serde_json::to_writer_pretty(file, &data).map_err(
            |_| rterr!("Failed to write runtime info"))?;
    }
    Ok(())
}

pub fn getRuntimeInfo(key: &str, config: &Config) ->
    Result<Option<String>, Error>
{
    if let Some(file_path) = config.runtimeInfoPath()
    {
        if file_path.exists()
        {
            let file = File::open(file_path).map_err(
                |_| rterr!("Failed to open runtime info file"))?;
            let reader = BufReader::new(file);
            let data: serde_json::Value = serde_json::from_reader(reader)
                .map_err(|_| error!(
                    RuntimeError,
                    "Failed to read JSON from runtime info file"))?;
            match data.get(key)
            {
                None => Ok(None),
                Some(v) => v.as_str().map(|s| Some(s.to_owned())).ok_or(
                    rterr!("Invalid runtime info")),
            }
        }
        else
        {
            Err(rterr!("No runtime info available"))
        }
    }
    else
    {
        Err(rterr!("No runtime info available"))
    }
}
