use std::env;
use std::path::Path;

use serde::Deserialize;

use crate::error::Error;

#[derive(Deserialize)]
pub struct Config
{
    /// CA certificates files for HTTPS
    pub ca_certs: Vec<String>,
    /// End point to the Vault HTTP API
    pub end_point: String,
    pub username: String,
    /// A program that copy the content of stdin to the OS’s
    /// clipboard. By default this `xclip` in Linux, and `pbcopy` in
    /// macOS. Password is piped to this program. If this is not
    /// found, the password is printed.
    pub clipboard_prog: Option<String>,
}

impl Config
{
    pub fn fromfile(path: &Path) -> Result<Self, Error>
    {
        let content = std::fs::read_to_string(path).map_err(
            |_| rterr!("Failed to read config file"))?;
        toml::from_str(&content).map_err(
            |e| rterr!("Failed to parse config file: {}", e))
    }

    pub fn clipboardProg(&self) -> Option<String>
    {
        if let Some(p) = &self.clipboard_prog
        {
            Some(p.to_owned())
        }
        else
        {
            match env::consts::OS
            {
                "linux" => Some(String::from("xclip")),
                "macos" => Some(String::from("pbcopy")),
                _ => None,
            }
        }
    }
}

impl Default for Config
{
    fn default() -> Self
    {
        Self {
            ca_certs: vec![
                String::from("/home/metrowind/ca-xeno-root.pem"),
                String::from("/home/metrowind/ca-xeno-inter.pem"),
            ],
            end_point: String::from("https://localhost/"),
            username: String::from("metrowind"),
            clipboard_prog: None,
        }
    }
}
