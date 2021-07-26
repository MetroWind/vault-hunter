use std::error::Error as StdError;
use std::fmt;

#[macro_export]
macro_rules! error
{
    ( $err_type:ident, $msg:literal $(, $x:expr)* ) =>
    {
        {
            Error::$err_type(format!($msg $(, $x)*))
        }
    };
}

// Construct a RuntimeError
#[macro_export]
macro_rules! rterr
{
    ($msg:literal) => { error!(RuntimeError, $msg) };
    ($msg:literal $(, $x:expr)+) =>
    {
        error!(RuntimeError, $msg $(, $x)+)
    };
}

#[derive(Debug, Clone, PartialEq)]
pub enum Error
{
    VaultError(String),
    HTTPError(String),
    RuntimeError(String),
}

impl fmt::Display for Error
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        match self
        {
            Error::VaultError(msg) => write!(f, "Vault error: {}", msg),
            Error::HTTPError(msg) => write!(f, "HTTP error: {}", msg),
            Error::RuntimeError(msg) => write!(f, "Runtime error: {}", msg),
        }
    }
}

impl StdError for Error
{
    fn source(&self) -> Option<&(dyn StdError + 'static)> {None}
}
