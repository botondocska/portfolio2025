-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY NOT NULL,  -- UUID stored as TEXT in SQLite
    email TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))  -- ISO8601 timestamp
);

-- Create index on email for faster lookups
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Create credentials table for storing WebAuthn passkeys
CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    credential_id TEXT NOT NULL UNIQUE,  -- Base64 encoded credential ID
    credential_data TEXT NOT NULL,  -- JSON-serialized Passkey data
    counter INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create index on user_id for faster lookups
CREATE INDEX IF NOT EXISTS idx_credentials_user_id ON credentials(user_id);

-- Create sessions table for storing session data
CREATE TABLE IF NOT EXISTS sessions (
    session_key TEXT PRIMARY KEY NOT NULL,
    session_data TEXT NOT NULL,  -- JSON-serialized session state
    expires_at TEXT NOT NULL,  -- ISO8601 timestamp
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Create index on expires_at for faster cleanup of expired sessions
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);