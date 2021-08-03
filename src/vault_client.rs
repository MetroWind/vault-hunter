use std::path::Path as StdPath;
use std::fs::File;
use std::io::Read;
use std::io::BufReader;
use std::fmt;
use std::str::FromStr;
use std::collections::HashMap;

use serde_json::{self, json};
use reqwest;
use rpassword;

use crate::error::Error;
use crate::config;

pub type StringMap = HashMap<String, String>;

fn readCert(filename: &str) -> Result<reqwest::Certificate, Error>
{
    let mut buf = Vec::new();
    File::open(filename)
        .map_err(|_| error!(RuntimeError, "Failed to open CA cert"))?
        .read_to_end(&mut buf)
        .map_err(|_| error!(RuntimeError, "Failed to read CA cert"))?;
    reqwest::Certificate::from_pem(&buf)
        .map_err(|_| error!(RuntimeError, "Invalid CA cert"))
}

pub enum HealthStatus
{
    Active,
    Standby,
    Recovery,
    Performance,
    Uninitialized,
    Sealed,
}

pub enum KeyOrDir
{
    Key(String), Dir(String),
}

impl HealthStatus
{
    pub fn fromHTTPStatus(status: u16) -> Result<Self, Error>
    {
        match status
        {
            200 => Ok(HealthStatus::Active),
            429 => Ok(HealthStatus::Standby),
            472 => Ok(HealthStatus::Recovery),
            473 => Ok(HealthStatus::Performance),
            501 => Ok(HealthStatus::Uninitialized),
            503 => Ok(HealthStatus::Sealed),
            _ => Err(error!(VaultError, "Invalid status code from health: {}",
                       status)),
        }
    }
}

impl fmt::Display for HealthStatus
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        write!(f, "{}",
               match self
               {
                   HealthStatus::Active => "active",
                   HealthStatus::Standby => "standby",
                   HealthStatus::Recovery => "recovery",
                   HealthStatus::Performance => "performance",
                   HealthStatus::Uninitialized => "uninitialized",
                   HealthStatus::Sealed => "sealed",
               })
    }
}

#[derive(Clone)]
pub struct Path
{
    components: Vec<String>,
}

impl Path
{
    pub fn new() -> Self
    {
        Self { components: Vec::default() }
    }

    pub fn push(&mut self, comp: &str)
    {
        self.components.push(comp.to_owned());
    }

    pub fn pushed(&self, comp: &str) -> Self
    {
        let mut p = self.clone();
        p.push(comp);
        p
    }
}

impl fmt::Display for Path
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        write!(f, "{}", self.components.join("/"))
    }
}


pub struct Client<'a>
{
    end_point: String,
    token: Option<String>,
    config: &'a config::Config,
    client: reqwest::Client,
}

impl<'a> Client<'a>
{
    pub fn new(conf: &'a config::Config) -> Result<Self, Error>
    {
        let mut builder = reqwest::Client::builder();
        for cert_file in &conf.ca_certs
        {
            builder = builder.add_root_certificate(readCert(cert_file)?);
        }
        let client = builder.build().map_err(
            |e| error!(RuntimeError, "Failed to build client: {}", e))?;

        Ok(Self {
            end_point: conf.end_point.clone(),
            token: None,
            config: conf,
            client: client,
        })
    }

    fn setRuntimeInfo(&self, key: &str, value: Option<&str>) -> Result<(), Error>
    {
        let file_path = StdPath::new("runtime.json");
        let mut data = serde_json::Value::default();
        if file_path.exists()
        {
            let file = File::open(file_path).map_err(
                |_| error!(RuntimeError, "Failed to open runtime info file"))?;
            let reader = BufReader::new(file);
            data = serde_json::from_reader(reader).map_err(
                |_| error!(RuntimeError, "Failed to read JSON from runtime info file"))?;
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
            |_| error!(RuntimeError, "Failed to open runtime info file"))?;
        serde_json::to_writer_pretty(file, &data).map_err(
            |_| error!(RuntimeError, "Failed to write runtime info"))?;
        Ok(())
    }

    fn getRuntimeInfo(&self, key: &str) -> Result<String, Error>
    {
        let file_path = StdPath::new("runtime.json");
        if file_path.exists()
        {
            let file = File::open(file_path).map_err(
                |_| error!(RuntimeError, "Failed to open runtime info file"))?;
            let reader = BufReader::new(file);
            let data: serde_json::Value = serde_json::from_reader(reader)
                .map_err(|_| error!(
                    RuntimeError,
                    "Failed to read JSON from runtime info file"))?;
            data[key].as_str().map(|s| s.to_owned()).ok_or(
                error!(RuntimeError, "Invalid runtime info"))
        }
        else
        {
            return Err(error!(RuntimeError, "No runtime info available"));
        }

    }

    fn buildReq(&self, method: reqwest::Method, url: &str) ->
        reqwest::RequestBuilder
    {
        if let Some(token) = &self.token
        {
            self.client.request(method, url).bearer_auth(token)
        }
        else
        {
            self.client.request(method, url)
        }
    }

    #[allow(dead_code)]
    pub async fn health(&self) -> Result<HealthStatus, Error>
    {
        let code = self.client.get(&format!("{}v1/sys/health", self.end_point))
            .send().await
            .map_err(|e| error!(HTTPError, "Failed to send request: {}", e))?
            .status().as_u16();
        HealthStatus::fromHTTPStatus(code)
    }

    /// Revoke the token if exists, and clear runtime info.
    #[allow(dead_code)]
    pub async fn logout(&mut self) -> Result<(), Error>
    {
        if self.token.is_none() { return Ok(()); }

        let res = self.buildReq(reqwest::Method::POST,
                                &format!("{}v1/auth/token/revoke-self",
                                         self.end_point))
            .send().await.map_err(
                |e| error!(HTTPError, "Failed to send logout request: {}", e))?;
        if res.status().as_u16() == 403
        {
            eprintln!("Invalid token. Maybe it has expired. Clearing token cache...");
        }
        else
        {
            res.error_for_status().map_err(
                |e| error!(VaultError, "Failed to logout: {}", e))?;
        }
        self.token = None;
        self.setRuntimeInfo("token", None)
    }

    /// Login using a username and a password. Acquire and cache a new
    /// token.
    async fn loginNew(&mut self, password: &str) -> Result<(), Error>
    {
        let res: serde_json::Value =
            self.client.post(&format!("{}v1/auth/userpass/login/{}",
                                      self.end_point, self.config.username))
            .json(&json!({"password": password, "token_max_ttl": 3600 * 24}))
            .send().await.map_err(
                |e| error!(HTTPError, "Failed to send login request: {}", e))?
            .json().await.map_err(
                |_| error!(RuntimeError, "Failed to parse JSON"))?;
        if let Some(msg) = res["errors"][0].as_str()
        {
            return Err(error!(VaultError, "Failed to login: {}", msg));
        }
        self.token = res["auth"]["client_token"].as_str().map(|t| t.to_owned());
        self.setRuntimeInfo("token", Some(&self.token.as_ref().unwrap()))?;

        Ok(())
    }

    pub async fn lookupToken(&self) -> Result<(), Error>
    {
        let res: serde_json::Value =
            self.buildReq(reqwest::Method::GET, &format!(
                "{}/v1/auth/token/lookup-self",self.end_point))
            .send().await.map_err(
                |e| error!(HTTPError, "Failed to send token lookup request: {}", e))?
            .json().await.map_err(
                |_| error!(RuntimeError, "Failed to parse JSON"))?;
        if let Some(msg) = res["errors"][0].as_str()
        {
            return Err(error!(VaultError, "Failed to lookup token: {}", msg));
        }
        Ok(())
    }

    fn loginUsingCachedToken(&mut self) -> Result<(), Error>
    {
        self.token = Some(self.getRuntimeInfo("token")?);
        Ok(())
    }

    pub async fn loginPromptPassword(&mut self) -> Result<(), Error>
    {
        let pass = rpassword::read_password_from_tty(Some("Password: "))
            .map_err(|_| error!(RuntimeError, "Failed to read password"))?;
        self.loginNew(&pass).await
    }

    pub async fn login(&mut self) -> Result<(), Error>
    {
        if self.loginUsingCachedToken().is_ok()
        {
            return Ok(());
        }
        if self.lookupToken().await.is_ok()
        {
            Ok(())
        }
        else
        {
            self.loginPromptPassword().await
        }
    }

    pub async fn list(&self, path: &str) -> Result<Vec<KeyOrDir>, Error>
    {
        let res: serde_json::Value =
            self.buildReq(reqwest::Method::from_str("LIST").unwrap(),
                          &format!("{}/v1/passwords/metadata/{}/{}",
                                   self.end_point, self.config.username, path))
            .send().await.map_err(
                |e| error!(HTTPError, "Failed to send login request: {}", e))?
            .json().await.map_err(
                |_| error!(RuntimeError, "Failed to parse JSON"))?;
        if let Some(msg) = res["errors"][0].as_str()
        {
            return Err(error!(VaultError, "Failed to list {}: {}", path, msg));
        }

        // Each item listed could be a key or a directory. As far as I
        // know the only way to tell is to see if there a tailing
        // slash.
        res["data"]["keys"].as_array().ok_or_else(
                || error!(RuntimeError, "List result is not a list"))?
            .iter().map(|v: &serde_json::Value| {
                let item = v.as_str().ok_or_else(
                    || error!(RuntimeError, "List item is not a string"))?;
                if item.ends_with('/')
                {
                    Ok(KeyOrDir::Dir(item[..item.len()-1].to_owned()))
                }
                else
                {
                    Ok(KeyOrDir::Key(item.to_owned()))
                }
            }).collect()
    }

    /// Retrieve the key-value paired stored at `path`.
    pub async fn get(&self, path: &str) -> Result<StringMap, Error>
    {
        // println!("Getting {}...", path);
        let mut res: serde_json::Value =
            self.buildReq(reqwest::Method::GET, &format!(
                "{}/v1/passwords/data/{}/{}", self.end_point, self.config.username,
                path))
            .send().await.map_err(
                |e| error!(HTTPError, "Failed to send get request: {}", e))?
            .json().await.map_err(
                |_| error!(RuntimeError, "Failed to parse JSON"))?;
        let result: StringMap = serde_json::from_value(res["data"]["data"].take())
            .map_err(|_| error!(RuntimeError, "Get result is not a dict"))?;
        Ok(result)
    }

    /// Recursively search though all entries in the engine, for all keys
    /// that contains `snippet`. Return a vector of key paths.
    pub async fn search(&self, snippet: &str) -> Result<Vec<Path>, Error>
    {
        let mut result: Vec<Path> = vec![];
        let mut to_search: Vec<Path> = vec![Path::new(),];

        // Breath-first search through all entries.
        while !to_search.is_empty()
        {
            let mut next_to_search: Vec<Path> = Vec::default();
            for path in &to_search
            {
                for item in self.list(&path.to_string()).await?
                {
                    match item
                    {
                        KeyOrDir::Key(name) =>
                        {
                            if name.to_lowercase().find(&snippet).is_some()
                            {
                                result.push(path.pushed(&name));
                            }
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
        Ok(result)
    }
}
