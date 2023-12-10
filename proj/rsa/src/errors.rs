pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    MessageNotASCII,
    InvalidKeyPair,
    MaskTooLong,
    MessageTooLong,
    IntergerTooLarge,
    OctetStringEmpty,
    InvalidBufferSize,
    DecryptionError,
}

impl std::error::Error for Error {}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg: &str = match self {
            Error::MessageNotASCII => "Message is not ASCII.",
            Error::InvalidKeyPair => "Invalid public key and secret key pair.",
            Error::MaskTooLong => "The mask is too long",
            Error::IntergerTooLarge => "Integer too large",
            Error::OctetStringEmpty => "The octet string is empty",
            Error::MessageTooLong => "The message is too long",
            Error::InvalidBufferSize => "Invalid buffer size",
            Error::DecryptionError => "Fail to decrypt",
        };
        f.write_str(msg)
    }
}
