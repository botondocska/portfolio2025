use std::collections::HashMap;

use actix_session::storage::{LoadError, SaveError, SessionKey, SessionStore, UpdateError};
use actix_web::cookie::time::Duration;
use anyhow::anyhow;
use chrono::Utc;
use rand::distributions::{Alphanumeric, DistString};
use sqlx::SqlitePool;

/**
Implementation of the [SessionStore] trait backed by SQLite database.
*/
#[derive(Clone)]
pub struct DatabaseSession {
    pool: SqlitePool,
}

impl DatabaseSession {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl SessionStore for DatabaseSession {
    async fn load(
        &self,
        session_key: &SessionKey,
    ) -> Result<Option<HashMap<String, String>>, LoadError> {
        let now = Utc::now().to_rfc3339();
        let key_str = session_key.as_ref();

        // Query the database for the session
        let result = sqlx::query!(
            r#"
            SELECT session_data
            FROM sessions
            WHERE session_key = ? AND expires_at > ?
            "#,
            key_str,
            now
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| LoadError::Other(anyhow!("Database error: {}", e)))?;

        // If session exists and hasn't expired, deserialize the data
        if let Some(row) = result {
            let session_state: HashMap<String, String> = serde_json::from_str(&row.session_data)
                .map_err(|e| LoadError::Deserialization(anyhow!("Failed to deserialize: {}", e)))?;
            Ok(Some(session_state))
        } else {
            Ok(None)
        }
    }

    async fn save(
        &self,
        session_state: HashMap<String, String>,
        ttl: &Duration,
    ) -> Result<SessionKey, SaveError> {
        // Generate a unique session key
        let session_key = loop {
            let key = Alphanumeric.sample_string(&mut rand::thread_rng(), 64);

            // Check if key already exists
            let exists =
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sessions WHERE session_key = ?")
                    .bind(&key)
                    .fetch_one(&self.pool)
                    .await
                    .map_err(|e| SaveError::Other(anyhow!("Database error: {}", e)))?;

            if exists == 0 {
                break key;
            }
        };

        // Calculate expiration time
        let expires_at = Utc::now()
            .checked_add_signed(chrono::Duration::nanoseconds(ttl.whole_nanoseconds() as i64))
            .ok_or_else(|| SaveError::Other(anyhow!("Invalid TTL")))?
            .to_rfc3339();

        // Serialize session data
        let session_data = serde_json::to_string(&session_state)
            .map_err(|e| SaveError::Serialization(anyhow!("Failed to serialize: {}", e)))?;

        // Insert into database
        sqlx::query!(
            r#"
            INSERT INTO sessions (session_key, session_data, expires_at)
            VALUES (?, ?, ?)
            "#,
            session_key,
            session_data,
            expires_at
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SaveError::Other(anyhow!("Database error: {}", e)))?;

        SessionKey::try_from(session_key)
            .map_err(|_| SaveError::Serialization(anyhow!("Invalid Session Key Error")))
    }
    async fn update(
        &self,
        session_key: SessionKey,
        session_state: HashMap<String, String>,
        ttl: &Duration,
    ) -> Result<SessionKey, UpdateError> {
        // Calculate new expiration time
        let expires_at = Utc::now()
            .checked_add_signed(chrono::Duration::nanoseconds(ttl.whole_nanoseconds() as i64))
            .ok_or_else(|| UpdateError::Other(anyhow!("Invalid TTL")))?
            .to_rfc3339();
        let key_str = session_key.as_ref();

        // Serialize session data
        let session_data = serde_json::to_string(&session_state)
            .map_err(|e| UpdateError::Serialization(anyhow!("Failed to serialize: {}", e)))?;

        // Update the session in database
        let result = sqlx::query!(
            r#"
            UPDATE sessions
            SET session_data = ?, expires_at = ?
            WHERE session_key = ?
            "#,
            session_data,
            expires_at,
            key_str
        )
        .execute(&self.pool)
        .await
        .map_err(|e| UpdateError::Other(anyhow!("Database error: {}", e)))?;

        if result.rows_affected() == 0 {
            return Err(UpdateError::Other(anyhow!(
                "Session not found with that key"
            )));
        }

        Ok(session_key)
    }

    async fn update_ttl(
        &self,
        session_key: &SessionKey,
        ttl: &Duration,
    ) -> Result<(), anyhow::Error> {
        // Calculate new expiration time
        let expires_at = Utc::now()
            .checked_add_signed(chrono::Duration::nanoseconds(ttl.whole_nanoseconds() as i64))
            .ok_or_else(|| anyhow!("Invalid TTL"))?
            .to_rfc3339();
        let key_str = session_key.as_ref();

        // Update only the expiration time
        sqlx::query!(
            r#"
            UPDATE sessions
            SET expires_at = ?
            WHERE session_key = ?
            "#,
            expires_at,
            key_str
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete(&self, session_key: &SessionKey) -> Result<(), anyhow::Error> {
        let key_str = session_key.as_ref();
        sqlx::query!("DELETE FROM sessions WHERE session_key = ?", key_str)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}

/*
use std::ops::Add;
use std::sync::Mutex;
use std::{collections::HashMap, sync::LazyLock};

use actix_session::storage::{LoadError, SaveError, SessionKey, SessionStore, UpdateError};
use actix_web::cookie::time::Duration;
use anyhow::anyhow;
use chrono::Utc;
use rand::distributions::{Alphanumeric, DistString};

/**
Static map where session states are stored
*/
static SESSION_STATES: LazyLock<Mutex<HashMap<String, State>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub(crate) struct State {
    session_state: HashMap<String, String>,
    valid_until: chrono::DateTime<Utc>,
}

/**
Implementation of the [SessionStore] trait of [actix_session].
*/
#[derive(Default)]
pub(crate) struct MemorySession;

impl SessionStore for MemorySession {
    async fn load(
        &self,
        session_key: &SessionKey,
    ) -> Result<Option<HashMap<String, String>>, LoadError> {
        let now = Utc::now();

        Ok(SESSION_STATES
            .lock()
            .map_err(|_| LoadError::Other(anyhow!("Poison Error")))?
            .get(session_key.as_ref())
            .filter(|&v| v.valid_until >= now)
            .map(|state| state.session_state.clone()))
    }

    async fn save(
        &self,
        session_state: HashMap<String, String>,
        ttl: &Duration,
    ) -> Result<SessionKey, SaveError> {
        let mut session_key;

        loop {
            session_key = Alphanumeric.sample_string(&mut rand::thread_rng(), 512);

            if !SESSION_STATES
                .lock()
                .map_err(|_| SaveError::Other(anyhow!("Poison Error")))?
                .contains_key(&session_key)
            {
                break;
            }
        }

        SESSION_STATES
            .lock()
            .map_err(|_| SaveError::Other(anyhow!("Poison Error")))?
            .insert(
                session_key.clone(),
                State {
                    session_state,
                    valid_until: Utc::now()
                        .add(chrono::Duration::nanoseconds(ttl.whole_nanoseconds() as i64)),
                },
            );

        SessionKey::try_from(session_key)
            .map_err(|_| SaveError::Serialization(anyhow!("Invalid Session Key Error")))
    }

    async fn update(
        &self,
        session_key: SessionKey,
        session_state: HashMap<String, String>,
        ttl: &Duration,
    ) -> Result<SessionKey, UpdateError> {
        if let Some(entry) = SESSION_STATES
            .lock()
            .map_err(|_| UpdateError::Other(anyhow!("Poison Error")))?
            .get_mut(session_key.as_ref())
        {
            entry.valid_until =
                Utc::now().add(chrono::Duration::nanoseconds(ttl.whole_nanoseconds() as i64));
            entry.session_state = session_state;

            Ok(session_key)
        } else {
            Err(UpdateError::Other(anyhow!(
                "Didn't found session with that key"
            )))
        }
    }

    async fn update_ttl(
        &self,
        session_key: &SessionKey,
        ttl: &Duration,
    ) -> Result<(), anyhow::Error> {
        if let Some(entry) = SESSION_STATES
            .lock()
            .map_err(|_| anyhow!("Poison Error"))?
            .get_mut(session_key.as_ref())
        {
            entry.valid_until =
                Utc::now().add(chrono::Duration::nanoseconds(ttl.whole_nanoseconds() as i64));
        }

        Ok(())
    }

    async fn delete(&self, session_key: &SessionKey) -> Result<(), anyhow::Error> {
        SESSION_STATES
            .lock()
            .map_err(|_| anyhow!("Poison Error"))?
            .remove(session_key.as_ref());

        Ok(())
    }
}
*/
