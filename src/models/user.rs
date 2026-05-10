use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub user_id: String,
    pub public_key: Vec<u8>,
    pub name: Option<String>,
    pub last_active: DateTime<Utc>,
    pub protocol_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceResponse {
    pub id: String,
    pub public_key: String, // hex
    pub name: Option<String>,
    pub last_active: String,
    pub protocol_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: String,
    pub event_type: String,
    pub metadata: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriendResponse {
    pub username: String,
    pub status: String,
    pub last_active: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxMessage {
    pub id: String,
    pub payload: Vec<u8>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultInviteResponse {
    pub id: String,
    pub vault_id: String,
    pub inviter_username: String,
    pub status: String,
    pub created_at: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMemberResponse {
    pub user_id: String,
    pub username: String,
    pub role: String,
    pub joined_at: String,
}
