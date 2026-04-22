use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use std::path::Path;
use tracing::info;
use chrono::{DateTime, Utc};
use crate::models::user::{DeviceResponse, AuditLogEntry};

pub type DbPool = Pool<SqliteConnectionManager>;

#[derive(Clone)]
pub struct ShareData {
    pub payload: Vec<u8>,
    pub expires_at: Option<DateTime<Utc>>,
    pub max_views: Option<i32>,
    pub view_count: i32,
}

pub struct Db {
    pool: DbPool,
}

impl Db {
    pub fn open<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let manager = SqliteConnectionManager::file(path);
        let pool = Pool::new(manager)?;
        let db = Self { pool };
        db.init_schema()?;
        Ok(db)
    }

    fn init_schema(&self) -> anyhow::Result<()> {
        info!("Initializing database schema...");
        let conn = self.pool.get()?;

        conn.execute_batch("
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                refresh_token TEXT UNIQUE NOT NULL,
                expires_at DATETIME NOT NULL,
                revoked BOOLEAN DEFAULT FALSE,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                public_key BLOB NOT NULL,
                name TEXT,
                last_active DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS friends (
                user_id_1 TEXT NOT NULL,
                user_id_2 TEXT NOT NULL,
                status TEXT NOT NULL, -- 'pending', 'confirmed'
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(user_id_1, user_id_2),
                FOREIGN KEY(user_id_1) REFERENCES users(id),
                FOREIGN KEY(user_id_2) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS mailbox (
                id TEXT PRIMARY KEY,
                target_device_id TEXT NOT NULL,
                payload BLOB NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(target_device_id) REFERENCES devices(id)
            );

            CREATE TABLE IF NOT EXISTS shares (
                id TEXT PRIMARY KEY,
                payload BLOB NOT NULL,
                expires_at DATETIME,
                max_views INTEGER,
                view_count INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS vault_members (
                vault_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                role TEXT NOT NULL, -- 'admin', 'editor', 'viewer'
                joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(vault_id, user_id),
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS vault_invites (
                id TEXT PRIMARY KEY,
                vault_id TEXT NOT NULL,
                inviter_id TEXT NOT NULL,
                invitee_id TEXT NOT NULL,
                role TEXT NOT NULL,
                status TEXT NOT NULL, -- 'pending', 'accepted', 'rejected'
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(inviter_id) REFERENCES users(id),
                FOREIGN KEY(invitee_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                metadata TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
        ")?;

        info!("Database schema initialized successfully.");
        Ok(())
    }

    // --- User Operations ---

    pub fn create_user(&self, username: &str, password_hash: &str) -> anyhow::Result<String> {
        let conn = self.pool.get()?;
        let id = uuid::Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO users (id, username, password_hash) VALUES (?1, ?2, ?3)",
            (&id, username, password_hash),
        )?;
        Ok(id)
    }

    pub fn get_user_by_username(&self, username: &str) -> anyhow::Result<Option<(String, String)>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT id, password_hash FROM users WHERE username = ?1")?;
        let mut rows = stmt.query([username])?;
        if let Some(row) = rows.next()? {
            Ok(Some((row.get(0)?, row.get(1)?)))
        } else {
            Ok(None)
        }
    }

    // --- Session Operations ---

    pub fn create_session(&self, user_id: &str, refresh_token: &str, expires_at: chrono::DateTime<chrono::Utc>) -> anyhow::Result<()> {
        let conn = self.pool.get()?;
        let id = uuid::Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO sessions (id, user_id, refresh_token, expires_at) VALUES (?1, ?2, ?3, ?4)",
            (&id, user_id, refresh_token, expires_at.to_rfc3339()),
        )?;
        Ok(())
    }

    pub fn get_session_by_token(&self, token: &str) -> anyhow::Result<Option<(String, DateTime<Utc>, bool)>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT user_id, expires_at, revoked FROM sessions WHERE refresh_token = ?1")?;
        let mut rows = stmt.query([token])?;

        if let Some(row) = rows.next()? {
            let user_id: String = row.get(0)?;
            let expires_at: String = row.get(1)?;
            let revoked: bool = row.get(2)?;
            
            let expires_at = DateTime::parse_from_rfc3339(&expires_at)
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|e| anyhow::anyhow!("Invalid date: {}", e))?;

            Ok(Some((user_id, expires_at, revoked)))
        } else {
            Ok(None)
        }
    }

    pub fn revoke_session(&self, token: &str) -> anyhow::Result<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "UPDATE sessions SET revoked = TRUE WHERE refresh_token = ?1",
            [token],
        )?;
        Ok(())
    }

    pub fn revoke_all_user_sessions(&self, user_id: &str) -> anyhow::Result<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "UPDATE sessions SET revoked = TRUE WHERE user_id = ?1",
            [user_id],
        )?;
        Ok(())
    }

    // --- Device Operations ---

    pub fn create_device(&self, user_id: &str, public_key: &[u8], name: Option<&str>) -> anyhow::Result<String> {
        let conn = self.pool.get()?;
        let id = uuid::Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO devices (id, user_id, public_key, name) VALUES (?1, ?2, ?3, ?4)",
            (&id, user_id, public_key, name),
        )?;
        Ok(id)
    }

    pub fn get_devices_by_user(&self, user_id: &str) -> anyhow::Result<Vec<DeviceResponse>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT id, public_key, name, last_active FROM devices WHERE user_id = ?1")?;
        let rows = stmt.query_map([user_id], |row| {
            let public_key: Vec<u8> = row.get(1)?;
            Ok(DeviceResponse {
                id: row.get(0)?,
                public_key: hex::encode(public_key),
                name: row.get(2)?,
                last_active: row.get(3)?,
            })
        })?;

        let mut devices = Vec::new();
        for device in rows {
            devices.push(device?);
        }
        Ok(devices)
    }

    pub fn delete_device(&self, device_id: &str, user_id: &str) -> anyhow::Result<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "DELETE FROM devices WHERE id = ?1 AND user_id = ?2",
            [device_id, user_id],
        )?;
        Ok(())
    }

    // --- Friend Operations ---

    pub fn create_friend_request(&self, user_id: &str, friend_id: &str) -> anyhow::Result<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT OR IGNORE INTO friends (user_id_1, user_id_2, status) VALUES (?1, ?2, 'pending')",
            [user_id, friend_id],
        )?;
        Ok(())
    }

    pub fn get_friends(&self, user_id: &str) -> anyhow::Result<Vec<crate::friends::FriendResponse>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("
            SELECT u.username, f.status, 
                   (SELECT MAX(last_active) FROM devices d WHERE d.user_id = u.id) as last_active
            FROM friends f
            JOIN users u ON (u.id = f.user_id_2 AND f.user_id_1 = ?1) OR (u.id = f.user_id_1 AND f.user_id_2 = ?1)
        ")?;
        let rows = stmt.query_map([user_id], |row| {
            Ok(crate::friends::FriendResponse {
                username: row.get(0)?,
                status: row.get(1)?,
                last_active: row.get(2)?,
            })
        })?;

        let mut friends = Vec::new();
        for friend in rows {
            friends.push(friend?);
        }
        Ok(friends)
    }

    pub fn confirm_friendship(&self, user_id_1: &str, user_id_2: &str) -> anyhow::Result<()> {
        let conn = self.pool.get()?;
        let (u1, u2) = if user_id_1 < user_id_2 { (user_id_1, user_id_2) } else { (user_id_2, user_id_1) };
        conn.execute(
            "UPDATE friends SET status = 'confirmed' WHERE user_id_1 = ?1 AND user_id_2 = ?2",
            [u1, u2],
        )?;
        Ok(())
    }

    pub fn delete_friend(&self, user_id_1: &str, user_id_2: &str) -> anyhow::Result<()> {
        let conn = self.pool.get()?;
        let (u1, u2) = if user_id_1 < user_id_2 { (user_id_1, user_id_2) } else { (user_id_2, user_id_1) };
        conn.execute(
            "DELETE FROM friends WHERE user_id_1 = ?1 AND user_id_2 = ?2",
            [u1, u2],
        )?;
        Ok(())
    }

    pub fn block_friend(&self, user_id: &str, blocked_user_id: &str) -> anyhow::Result<()> {
        let conn = self.pool.get()?;
        let (u1, u2) = if user_id < blocked_user_id { (user_id, blocked_user_id) } else { (blocked_user_id, user_id) };
        conn.execute(
            "UPDATE friends SET status = 'blocked' WHERE user_id_1 = ?1 AND user_id_2 = ?2",
            [u1, u2],
        )?;
        Ok(())
    }

    // --- Mailbox Operations ---

    pub fn enqueue_mailbox_message(&self, device_id: &str, payload: &[u8]) -> anyhow::Result<()> {
        let conn = self.pool.get()?;
        let id = uuid::Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO mailbox (id, target_device_id, payload) VALUES (?1, ?2, ?3)",
            (&id, device_id, payload),
        )?;
        Ok(())
    }

    pub fn get_mailbox_messages(&self, device_id: &str) -> anyhow::Result<Vec<crate::mailbox::MailboxMessage>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT id, payload, created_at FROM mailbox WHERE target_device_id = ?1 ORDER BY created_at ASC")?;
        let rows = stmt.query_map([device_id], |row| {
            Ok(crate::mailbox::MailboxMessage {
                id: row.get(0)?,
                payload: row.get(1)?,
                created_at: row.get(2)?,
            })
        })?;

        let mut messages = Vec::new();
        for msg in rows {
            messages.push(msg?);
        }
        Ok(messages)
    }

    pub fn clear_mailbox(&self, device_id: &str) -> anyhow::Result<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "DELETE FROM mailbox WHERE target_device_id = ?1",
            [device_id],
        )?;
        Ok(())
    }

    // --- Vault Operations ---

    pub fn create_vault_invite(&self, vault_id: &str, inviter_id: &str, invitee_username: &str, role: &str) -> anyhow::Result<String> {
        let conn = self.pool.get()?;
        
        // Find invitee user_id
        let invitee_id: String = conn.query_row(
            "SELECT id FROM users WHERE username = ?1",
            [invitee_username],
            |row| row.get(0),
        )?;

        let id = uuid::Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO vault_invites (id, vault_id, inviter_id, invitee_id, role, status) VALUES (?1, ?2, ?3, ?4, ?5, 'pending')",
            [&id, vault_id, inviter_id, &invitee_id, role],
        )?;
        
        Ok(id)
    }

    pub fn get_pending_vault_invites(&self, user_id: &str) -> anyhow::Result<Vec<crate::vaults::VaultInviteResponse>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("
            SELECT i.id, i.vault_id, u.username, i.status, i.created_at, i.role
            FROM vault_invites i
            JOIN users u ON u.id = i.inviter_id
            WHERE i.invitee_id = ?1 AND i.status = 'pending'
        ")?;
        
        let rows = stmt.query_map([user_id], |row| {
            Ok(crate::vaults::VaultInviteResponse {
                id: row.get(0)?,
                vault_id: row.get(1)?,
                inviter_username: row.get(2)?,
                status: row.get(3)?,
                created_at: row.get(4)?,
                role: row.get(5)?,
            })
        })?;

        let mut invites = Vec::new();
        for invite in rows {
            invites.push(invite?);
        }
        Ok(invites)
    }

    pub fn respond_to_vault_invite(&self, invite_id: &str, user_id: &str, status: &str) -> anyhow::Result<()> {
        let conn = self.pool.get()?;
        
        // Update invite status
        conn.execute(
            "UPDATE vault_invites SET status = ?1 WHERE id = ?2 AND invitee_id = ?3",
            [status, invite_id, user_id],
        )?;

        if status == "accepted" {
            // Get vault details
            let (vault_id, role): (String, String) = conn.query_row(
                "SELECT vault_id, role FROM vault_invites WHERE id = ?1",
                [invite_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;

            // Add to vault_members
            conn.execute(
                "INSERT OR IGNORE INTO vault_members (vault_id, user_id, role) VALUES (?1, ?2, ?3)",
                [vault_id, user_id.to_string(), role],
            )?;
        }
        
        Ok(())
    }

    pub fn get_vault_members(&self, vault_id: &str) -> anyhow::Result<Vec<crate::vaults::VaultMemberResponse>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("
            SELECT m.user_id, u.username, m.role, m.joined_at
            FROM vault_members m
            JOIN users u ON u.id = m.user_id
            WHERE m.vault_id = ?1
        ")?;
        
        let rows = stmt.query_map([vault_id], |row| {
            Ok(crate::vaults::VaultMemberResponse {
                user_id: row.get(0)?,
                username: row.get(1)?,
                role: row.get(2)?,
                joined_at: row.get(3)?,
            })
        })?;

        let mut members = Vec::new();
        for member in rows {
            members.push(member?);
        }
        Ok(members)
    }

    // --- Audit Log ---

    pub fn log_event(&self, user_id: &str, event_type: &str, metadata: Option<&str>) -> anyhow::Result<()> {
        let conn = self.pool.get()?;
        let id = uuid::Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO audit_logs (id, user_id, event_type, metadata) VALUES (?1, ?2, ?3, ?4)",
            (id, user_id, event_type, metadata),
        )?;
        Ok(())
    }

    pub fn get_audit_logs(&self, user_id: &str) -> anyhow::Result<Vec<AuditLogEntry>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT id, event_type, metadata, created_at FROM audit_logs WHERE user_id = ?1 ORDER BY created_at DESC")?;
        let rows = stmt.query_map([user_id], |row| {
            Ok(AuditLogEntry {
                id: row.get(0)?,
                event_type: row.get(1)?,
                metadata: row.get(2)?,
                created_at: row.get(3)?,
            })
        })?;

        let mut logs = Vec::new();
        for log in rows {
            logs.push(log?);
        }
        Ok(logs)
    }

    // --- Share Operations ---

    pub fn create_share(&self, payload: &[u8], expires_at: Option<chrono::DateTime<chrono::Utc>>, max_views: Option<i32>) -> anyhow::Result<String> {
        let conn = self.pool.get()?;
        let id = uuid::Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO shares (id, payload, expires_at, max_views) VALUES (?1, ?2, ?3, ?4)",
            (&id, payload, expires_at.map(|e| e.to_rfc3339()), max_views),
        )?;
        Ok(id)
    }

    pub fn get_share(&self, id: &str) -> anyhow::Result<Option<ShareData>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT payload, expires_at, max_views, view_count FROM shares WHERE id = ?1")?;
        let mut rows = stmt.query([id])?;
        if let Some(row) = rows.next()? {
            let payload: Vec<u8> = row.get(0)?;
            let expires_at_str: Option<String> = row.get(1)?;
            let expires_at = expires_at_str
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
                .map(|e| e.with_timezone(&chrono::Utc));
            let max_views: Option<i32> = row.get(2)?;
            let view_count: i32 = row.get(3)?;
            Ok(Some(ShareData {
                payload,
                expires_at,
                max_views,
                view_count,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn increment_share_view_count(&self, id: &str) -> anyhow::Result<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "UPDATE shares SET view_count = view_count + 1 WHERE id = ?1",
            [id],
        )?;
        Ok(())
    }

    pub fn delete_share(&self, id: &str) -> anyhow::Result<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "DELETE FROM shares WHERE id = ?1",
            [id],
        )?;
        Ok(())
    }
}
