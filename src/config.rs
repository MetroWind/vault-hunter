use std::env;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::Error;

fn findConfigDir() -> Option<PathBuf>
{
    let dirname = "vault-hunter";
    if let Ok(path) = std::env::var("XDG_CONFIG_HOME")
    {
        if !path.is_empty()
        {
            let mut p = PathBuf::from(path);
            p.push(dirname);
            return Some(p);
        }
    }

    if let Ok(path) = std::env::var("HOME")
    {
        if !path.is_empty()
        {
            let mut p = PathBuf::from(path);
            p.push(".config");
            p.push(dirname);
            return Some(p);
        }
    }
    None
}

pub fn findConfigFile() -> Option<PathBuf>
{
    let basename = "config.toml";
    if let Some(mut p) = findConfigDir()
    {
        p.push(basename);
        if p.exists()
        {
            return Some(p);
        }
    }
    None
}

/// Return the default path of the runtime info file. Return what the
/// path should be if the files does not exist. Return None if the
/// path cannot be determined.
fn findRuntimeInfoFile() -> Option<PathBuf>
{
    let basename = "runtime.json";
    if let Some(mut p) = findConfigDir()
    {
        p.push(basename);
        return Some(p);
    }
    None
}

fn defaultXMLExportPeriod() -> i64 { 86400 }

#[derive(Deserialize)]
pub struct Config
{
    /// CA certificates files for HTTPS
    #[serde(default)]
    pub ca_certs: Vec<String>,
    /// End point to the Vault HTTP API
    pub end_point: String,
    /// The username. The userpass authentication in Vault
    /// automatically lowercase this. So it does not have to be
    /// all-lowercase in the config file.
    username: String,
    /// A program that copy the content of stdin to the OS’s
    /// clipboard. By default this `xclip` in Linux, and `pbcopy` in
    /// macOS. Password is piped to this program. If this is not
    /// found, the password is printed.
    pub clipboard_prog: Option<String>,
    /// Location of the cache file that stores the token. By default
    /// it’s $XDG_CONFIG_HOME/vault-hunter/runtime-info.json
    pub cache_path: Option<String>,
    /// Whether and where to regularly export a local encrypted XML of
    /// all the passwords.
    pub local_xml: Option<String>,
    /// Use this GPG user’s public key to encrypt the XML.
    pub gpg_user: Option<String>,
    /// Time period of XML export.
    #[serde(default = "defaultXMLExportPeriod")]
    pub xml_export_period: i64,
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

    /// The username in lowercase. The userpass authentication in
    /// Vault automatically lowercase this; however this is also used
    /// to construct URIs. Vault treats URI in a case-sensitive
    /// manner. So we lowercase the username internally for
    /// consistency.
    pub fn username(&self) -> String
    {
        self.username.to_lowercase()
    }

    /// Return the path of the runtime info file. Return what the path
    /// should be if the files does not exist. Return None if the path
    /// cannot be determined.
    pub fn runtimeInfoPath(&self) -> Option<PathBuf>
    {
        if let Some(p) = &self.cache_path
        {
            Some(PathBuf::from(p))
        }
        else
        {
            findRuntimeInfoFile()
        }
    }
}

impl Default for Config
{
    fn default() -> Self
    {
        Self {
            ca_certs: Vec::new(),
            end_point: String::from("https://localhost/"),
            username: String::from("metrowind"),
            clipboard_prog: None,
            cache_path: None,
            local_xml: None,
            gpg_user: None,
            xml_export_period: 86400,
        }
    }
}
