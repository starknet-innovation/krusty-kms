//! Error types for TONGO protocol operations.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, KmsError>;

#[derive(Error, Debug)]
pub enum KmsError {
    #[error("Invalid public key format: {0}")]
    InvalidPublicKey(String),

    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),

    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("Invalid amount: {0}")]
    InvalidAmount(String),

    #[error("Insufficient balance: available={available}, required={required}")]
    InsufficientBalance { available: u128, required: u128 },

    #[error("Invalid derivation path: {0}")]
    InvalidDerivationPath(String),

    #[error("Hex decoding error: {0}")]
    HexError(#[from] hex::FromHexError),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Starknet crypto error: {0}")]
    StarknetCryptoError(String),

    #[error("Point at infinity")]
    PointAtInfinity,

    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    #[error("RPC error: {0}")]
    RpcError(String),

    #[error("Account not deployed at {0}")]
    AccountNotDeployed(String),

    #[error("Account already deployed at {0}")]
    AlreadyDeployed(String),

    #[error("Insufficient fee balance for deployment: {0}")]
    InsufficientFeeBalance(String),

    #[error("Invalid class hash: {0}")]
    InvalidClassHash(String),

    #[error("Contract not found: {0}")]
    ContractNotFound(String),

    #[error("Transaction error: {0}")]
    TransactionError(String),

    #[error("Transaction reverted: {0}")]
    TransactionReverted(String),

    #[error("Fee estimation failed: {0}")]
    FeeEstimationFailed(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Staking error: {0}")]
    StakingError(String),

    #[error("Controller error: {0}")]
    ControllerError(String),
}
