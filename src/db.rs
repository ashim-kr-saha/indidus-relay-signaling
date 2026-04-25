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
            CREATE TABLE IF NOT EXISTS identities (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                root_public_key BLOB NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                identity_id TEXT NOT NULL,
                public_key BLOB NOT NULL,
                name TEXT,
                last_active DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(identity_id) REFERENCES identities(id)
            );

            CREATE TABLE IF NOT EXISTS friends (
                identity_id_1 TEXT NOT NULL,
                identity_id_2 TEXT NOT NULL,
                status TEXT NOT NULL, -- 'pending', 'confirmed', 'blocked'
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(identity_id_1, identity_id_2),
                FOREIGN KEY(identity_id_1) REFERENCES identities(id),
                FOREIGN KEY(identity_id_2) REFERENCES identities(id)
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
                owner_identity_id TEXT, -- For revocation
                expires_at DATETIME,
                max_views INTEGER,
                view_count INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(owner_identity_id) REFERENCES identities(id)
            );

            CREATE TABLE IF NOT EXISTS vault_members (
                vault_id TEXT NOT NULL,
                identity_id TEXT NOT NULL,
                role TEXT NOT NULL, -- 'admin', 'editor', 'viewer'
                joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(vault_id, identity_id),
                FOREIGN KEY(identity_id) REFERENCES identities(id)
            );

            CREATE TABLE IF NOT EXISTS vault_invites (
                id TEXT PRIMARY KEY,
                vault_id TEXT NOT NULL,
                inviter_identity_id TEXT NOT NULL,
                invitee_identity_id TEXT NOT NULL,
                role TEXT NOT NULL,
                status TEXT NOT NULL, -- 'pending', 'accepted', 'rejected'
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(inviter_identity_id) REFERENCES identities(id),
                FOREIGN KEY(invitee_identity_id) REFERENCES identities(id)
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id TEXT PRIMARY KEY,
                identity_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                metadata TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(identity_id) REFERENCES identities(id)
            );
        ")?;

        info!("Database schema initialized successfully.");
        Ok(())
    }

    // --- Identity Operations ---

    pub fn create_identity(&self, username: &str, root_public_key: &[u8]) -> anyhow::Result<String> {
        let conn = self.pool.get()?;
        let id = uuid::Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO identities (id, username, root_public_key) VALUES (?1, ?2, ?3)",
            (&id, username, root_public_key),
        )?;
        Ok(id)
    }

    pub fn get_identity_by_username(&self, username: &str) -> anyhow::Result<Option<(String, Vec<u8>)>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT id, root_public_key FROM identities WHERE username = ?1")?;
        let mut rows = stmt.query([username])?;
        if let Some(row) = rows.next()? {
            Ok(Some((row.get(0)?, row.get(1)?)))
        } else {
            Ok(None)
        }
    }

    pub fn get_identity_id_by_username(&self, username: &str) -> anyhow::Result<Option<String>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT id FROM identities WHERE username = ?1")?;
        let mut rows = stmt.query([username])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row.get(0)?))
        } else {
            Ok(None)
        }
    }

    // Session operations removed in v4.0 (Stateless Identity)

    // --- Device Operations ---

    pub fn create_device(&self, identity_id: &str, public_key: &[u8], name: Option<&str>) -> anyhow::Result<String> {
        let conn = self.pool.get()?;
        let id = uuid::Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO devices (id, identity_id, public_key, name) VALUES (?1, ?2, ?3, ?4)",
            (&id, identity_id, public_key, name),
        )?;
        Ok(id)
    }

    pub fn get_devices_by_identity(&self, identity_id: &str) -> anyhow::Result<Vec<DeviceResponse>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT id, public_key, name, last_active FROM devices WHERE identity_id = ?1")?;
        let rows = stmt.query_map([identity_id], |row| {
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

    pub fn get_identity_id_by_device_public_key(&self, public_key: &[u8]) -> anyhow::Result<Option<String>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT identity_id FROM devices WHERE public_key = ?1")?;
        let mut rows = stmt.query([public_key])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row.get(0)?))
        } else {
            // Also check identities table (Root Key)
            let mut stmt = conn.prepare("SELECT id FROM identities WHERE root_public_key = ?1")?;
            let mut rows = stmt.query([public_key])?;
            if let Some(row) = rows.next()? {
                Ok(Some(row.get(0)?))
            } else {
                Ok(None)
            }
        }
    }

    pub fn delete_device(&self, device_id: &str, identity_id: &str) -> anyhow::Result<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "DELETE FROM devices WHERE id = ?1 AND identity_id = ?2",
            [device_id, identity_id],
        )?;
        Ok(())
    }

    // --- Friend Operations ---

    pub fn create_friend_request(&self, identity_id: &str, friend_identity_id: &str) -> anyhow::Result<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT OR IGNORE INTO friends (identity_id_1, identity_id_2, status) VALUES (?1, ?2, 'pending')",
            [identity_id, friend_identity_id],
        )?;
        Ok(())
    }

    pub fn get_friends(&self, identity_id: &str) -> anyhow::Result<Vec<crate::friends::FriendResponse>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("
            SELECT i.username, f.status, 
                   (SELECT MAX(last_active) FROM devices d WHERE d.identity_id = i.id) as last_active
            FROM friends f
            JOIN identities i ON (i.id = f.identity_id_2 AND f.identity_id_1 = ?1) OR (i.id = f.identity_id_1 AND f.identity_id_2 = ?1)
        ")?;
        let rows = stmt.query_map([identity_id], |row| {
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

    pub fn confirm_friendship(&self, identity_id_1: &str, identity_id_2: &str) -> anyhow::Result<()> {
        let conn = self.pool.get()?;
        let (u1, u2) = if identity_id_1 < identity_id_2 { (identity_id_1, identity_id_2) } else { (identity_id_2, identity_id_1) };
        conn.execute(
            "UPDATE friends SET status = 'confirmed' WHERE identity_id_1 = ?1 AND identity_id_2 = ?2",
            [u1, u2],
        )?;
        Ok(())
    }

    pub fn delete_friend(&self, identity_id_1: &str, identity_id_2: &str) -> anyhow::Result<()> {
        let conn = self.pool.get()?;
        let (u1, u2) = if identity_id_1 < identity_id_2 { (identity_id_1, identity_id_2) } else { (identity_id_2, identity_id_1) };
        conn.execute(
            "DELETE FROM friends WHERE identity_id_1 = ?1 AND identity_id_2 = ?2",
            [u1, u2],
        )?;
        Ok(())
    }

    pub fn block_friend(&self, identity_id: &str, blocked_identity_id: &str) -> anyhow::Result<()> {
        let conn = self.pool.get()?;
        let (u1, u2) = if identity_id < blocked_identity_id { (identity_id, blocked_identity_id) } else { (blocked_identity_id, identity_id) };
        conn.execute(
            "UPDATE friends SET status = 'blocked' WHERE identity_id_1 = ?1 AND identity_id_2 = ?2",
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

    pub fn create_vault_invite(&self, vault_id: &str, inviter_identity_id: &str, invitee_username: &str, role: &str) -> anyhow::Result<String> {
        let conn = self.pool.get()?;
        
        // Find invitee identity_id
        let invitee_identity_id: String = conn.query_row(
            "SELECT id FROM identities WHERE username = ?1",
            [invitee_username],
            |row| row.get(0),
        )?;

        let id = uuid::Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO vault_invites (id, vault_id, inviter_identity_id, invitee_identity_id, role, status) VALUES (?1, ?2, ?3, ?4, ?5, 'pending')",
            [&id, vault_id, inviter_identity_id, &invitee_identity_id, role],
        )?;
        
        Ok(id)
    }

    pub fn get_pending_vault_invites(&self, identity_id: &str) -> anyhow::Result<Vec<crate::vaults::VaultInviteResponse>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("
            SELECT i.id, i.vault_id, iden.username, i.status, i.created_at, i.role
            FROM vault_invites i
            JOIN identities iden ON iden.id = i.inviter_identity_id
            WHERE i.invitee_identity_id = ?1 AND i.status = 'pending'
        ")?;
        
        let rows = stmt.query_map([identity_id], |row| {
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

    pub fn respond_to_vault_invite(&self, invite_id: &str, identity_id: &str, status: &str) -> anyhow::Result<()> {
        let conn = self.pool.get()?;
        
        // Update invite status
        conn.execute(
            "UPDATE vault_invites SET status = ?1 WHERE id = ?2 AND invitee_identity_id = ?3",
            [status, invite_id, identity_id],
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
                "INSERT OR IGNORE INTO vault_members (vault_id, identity_id, role) VALUES (?1, ?2, ?3)",
                [vault_id, identity_id.to_string(), role],
            )?;
        }
        
        Ok(())
    }

    pub fn get_vault_members(&self, vault_id: &str) -> anyhow::Result<Vec<crate::vaults::VaultMemberResponse>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("
            SELECT m.identity_id, iden.username, m.role, m.joined_at
            FROM vault_members m
            JOIN identities iden ON iden.id = m.identity_id
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

    pub fn log_event(&self, identity_id: &str, event_type: &str, metadata: Option<&str>) -> anyhow::Result<()> {
        let conn = self.pool.get()?;
        let id = uuid::Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO audit_logs (id, identity_id, event_type, metadata) VALUES (?1, ?2, ?3, ?4)",
            (id, identity_id, event_type, metadata),
        )?;
        Ok(())
    }

    pub fn get_audit_logs(&self, identity_id: &str) -> anyhow::Result<Vec<AuditLogEntry>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT id, event_type, metadata, created_at FROM audit_logs WHERE identity_id = ?1 ORDER BY created_at DESC")?;
        let rows = stmt.query_map([identity_id], |row| {
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

    pub fn create_share(&self, payload: &[u8], owner_identity_id: Option<&str>, expires_at: Option<chrono::DateTime<chrono::Utc>>, max_views: Option<i32>) -> anyhow::Result<String> {
        let conn = self.pool.get()?;
        let id = uuid::Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO shares (id, payload, owner_identity_id, expires_at, max_views) VALUES (?1, ?2, ?3, ?4, ?5)",
            (&id, payload, owner_identity_id, expires_at.map(|e| e.to_rfc3339()), max_views),
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
