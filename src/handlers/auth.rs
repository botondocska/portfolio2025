use actix_session::Session;
use actix_web::web::{Data, Json, Path};
use actix_web::{HttpResponse, Result};
use askama::Template;
use sqlx::SqlitePool;
use tracing::{error, info};

use crate::handlers::{Error, WebResult};

#[derive(Template)]
#[template(path = "pages/login.html")]
struct LoginTemplate {}

pub async fn login_page() -> Result<HttpResponse> {
    let template = LoginTemplate {};
    let html = template.render().unwrap();

    Ok(HttpResponse::Ok().content_type("text/html").body(html))
}

/*
 * Webauthn RS auth handlers.
 * These files use webauthn to process the data received from each route, and are closely tied to actix_web
 */

// 1. Import the prelude - this contains everything needed for the server to function.
use webauthn_rs::prelude::*;

// 2. The first step a client (user) will carry out is requesting a credential to be
// registered. We need to provide a challenge for this. The work flow will be:
//
//          ┌───────────────┐     ┌───────────────┐      ┌───────────────┐
//          │ Authenticator │     │    Browser    │      │     Site      │
//          └───────────────┘     └───────────────┘      └───────────────┘
//                  │                     │                      │
//                  │                     │     1. Start Reg     │
//                  │                     │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶│
//                  │                     │                      │
//                  │                     │     2. Challenge     │
//                  │                     │◀ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┤
//                  │                     │                      │
//                  │  3. Select Token    │                      │
//             ─ ─ ─│◀ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                      │
//  4. Verify │     │                     │                      │
//                  │  4. Yield PubKey    │                      │
//            └ ─ ─▶│─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶                      │
//                  │                     │                      │
//                  │                     │  5. Send Reg Opts    │
//                  │                     │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶│─ ─ ─
//                  │                     │                      │     │ 5. Verify
//                  │                     │                      │         PubKey
//                  │                     │                      │◀─ ─ ┘
//                  │                     │                      │─ ─ ─
//                  │                     │                      │     │ 6. Persist
//                  │                     │                      │       Credential
//                  │                     │                      │◀─ ─ ┘
//                  │                     │                      │
//                  │                     │                      │
//
// In this step, we are responding to the start reg(istration) request, and providing
// the challenge to the browser.
// Registration handler - Start
pub(crate) async fn start_register(
    email: Path<String>,
    session: Session,
    pool: Data<SqlitePool>,
    webauthn: Data<Webauthn>,
) -> WebResult<Json<CreationChallengeResponse>> {
    info!("Start register for email: {}", email);
    let email_str = email.as_str();
    // Query database to see if user already exists
    let existing_user = sqlx::query!("SELECT id FROM users WHERE email = ?", email_str)
        .fetch_optional(pool.get_ref())
        .await
        .map_err(|e| {
            error!("Database error: {:?}", e);
            Error::Database(e)
        })?;

    // Use existing UUID or generate a new one
    let user_unique_id = if let Some(user) = existing_user {
        Uuid::parse_str(&user.id).map_err(|e| {
            error!("Failed to parse UUID: {:?}", e);
            Error::CorruptSession
        })?
    } else {
        Uuid::new_v4()
    };

    // Remove any previous registrations that may have occurred from the session
    session.remove("reg_state");

    // Query existing credentials to exclude them
    let user_id_str = user_unique_id.to_string();
    let credential_rows = sqlx::query!(
        "SELECT credential_id FROM credentials WHERE user_id = ?",
        user_id_str
    )
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Database error: {:?}", e);
        Error::Database(e)
    })?;

    let exclude_credentials: Vec<CredentialID> = credential_rows
        .into_iter()
        .map(|row| CredentialID::from(row.credential_id.as_bytes().to_vec()))
        .collect();

    let exclude_credentials = if exclude_credentials.is_empty() {
        None
    } else {
        Some(exclude_credentials)
    };

    let (ccr, reg_state) = webauthn
        .start_passkey_registration(user_unique_id, &email, &email, exclude_credentials)
        .map_err(|e| {
            info!("challenge_register -> {:?}", e);
            Error::BadRequest(e)
        })?;

    // Store registration state in session
    if let Err(err) = session.insert("reg_state", (email.as_str(), user_unique_id, reg_state)) {
        error!("Failed to save reg_state to session storage!");
        return Err(Error::SessionInsert(err));
    };

    info!("Registration challenge created successfully!");
    Ok(Json(ccr))
}

// 3. The browser has completed it's steps and the user has created a public key
// on their device. Now we have the registration options sent to us, and we need
// to verify these and persist them.

pub(crate) async fn finish_register(
    req: Json<RegisterPublicKeyCredential>,
    session: Session,
    pool: Data<SqlitePool>,
    webauthn: Data<Webauthn>,
) -> WebResult<HttpResponse> {
    let (email, user_unique_id, reg_state): (String, Uuid, PasskeyRegistration) =
        match session.get("reg_state")? {
            Some((email, user_unique_id, reg_state)) => (email, user_unique_id, reg_state),
            None => return Err(Error::CorruptSession),
        };

    session.remove("reg_state");

    let passkey = webauthn
        .finish_passkey_registration(&req, &reg_state)
        .map_err(|e| {
            info!("challenge_register -> {:?}", e);
            Error::BadRequest(e)
        })?;

    // Start a transaction to ensure atomicity
    let mut tx = pool.begin().await.map_err(|e| {
        error!("Failed to start transaction: {:?}", e);
        Error::Database(e)
    })?;

    // Insert or ignore user (in case of race condition)
    let user_id_str = user_unique_id.to_string();
    sqlx::query!(
        "INSERT OR IGNORE INTO users (id, email) VALUES (?, ?)",
        user_id_str,
        email
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        error!("Failed to insert user: {:?}", e);
        Error::Database(e)
    })?;

    // Serialize the passkey to JSON
    let credential_data = serde_json::to_string(&passkey).map_err(|e| {
        error!("Failed to serialize passkey: {:?}", e);
        Error::Serialization
    })?;

    // Get credential ID as string (it's already a string internally)
    let cred_id_bytes = passkey.cred_id().as_ref();
    let credential_id = String::from_utf8_lossy(cred_id_bytes).to_string();

    // Insert the credential
    sqlx::query!(
        "INSERT INTO credentials (user_id, credential_id, credential_data) VALUES (?, ?, ?)",
        user_id_str,
        credential_id,
        credential_data,
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        error!("Failed to insert credential: {:?}", e);
        Error::Database(e)
    })?;

    // Commit the transaction
    tx.commit().await.map_err(|e| {
        error!("Failed to commit transaction: {:?}", e);
        Error::Database(e)
    })?;

    info!("Registration completed successfully for user: {}", email);
    Ok(HttpResponse::Ok().finish())
}

// 4. Now that our public key has been registered, we can authenticate a user and verify
// that they are the holder of that security token. The work flow is similar to registration.
//
//          ┌───────────────┐     ┌───────────────┐      ┌───────────────┐
//          │ Authenticator │     │    Browser    │      │     Site      │
//          └───────────────┘     └───────────────┘      └───────────────┘
//                  │                     │                      │
//                  │                     │     1. Start Auth    │
//                  │                     │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶│
//                  │                     │                      │
//                  │                     │     2. Challenge     │
//                  │                     │◀ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┤
//                  │                     │                      │
//                  │  3. Select Token    │                      │
//             ─ ─ ─│◀ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                      │
//  4. Verify │     │                     │                      │
//                  │    4. Yield Sig     │                      │
//            └ ─ ─▶│─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶                      │
//                  │                     │    5. Send Auth      │
//                  │                     │        Opts          │
//                  │                     │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶│─ ─ ─
//                  │                     │                      │     │ 5. Verify
//                  │                     │                      │          Sig
//                  │                     │                      │◀─ ─ ┘
//                  │                     │                      │
//                  │                     │                      │
//
// The user indicates the wish to start authentication and we need to provide a challenge.

pub(crate) async fn start_authentication(
    email: Path<String>,
    session: Session,
    pool: Data<SqlitePool>,
    webauthn: Data<Webauthn>,
) -> WebResult<Json<RequestChallengeResponse>> {
    info!("Start Authentication for email: {}", email);
    let email_str = email.as_str();
    // Remove any previous authentication that may have occurred from the session
    session.remove("auth_state");

    // Look up user by email
    let user = sqlx::query!("SELECT id FROM users WHERE email = ?", email_str)
        .fetch_optional(pool.get_ref())
        .await
        .map_err(|e| {
            error!("Database error: {:?}", e);
            Error::Database(e)
        })?
        .ok_or(Error::UserNotFound)?;

    let user_unique_id = Uuid::parse_str(&user.id).map_err(|e| {
        error!("Failed to parse UUID: {:?}", e);
        Error::CorruptSession
    })?;

    // Fetch all credentials for this user
    let credentials = sqlx::query!(
        "SELECT credential_data FROM credentials WHERE user_id = ?",
        user.id
    )
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Database error: {:?}", e);
        Error::Database(e)
    })?;

    if credentials.is_empty() {
        return Err(Error::UserHasNoCredentials);
    }

    // Deserialize passkeys from JSON
    let passkeys: Vec<Passkey> = credentials
        .into_iter()
        .filter_map(|row| {
            serde_json::from_str(&row.credential_data)
                .map_err(|e| {
                    error!("Failed to deserialize passkey: {:?}", e);
                    e
                })
                .ok()
        })
        .collect();

    if passkeys.is_empty() {
        return Err(Error::UserHasNoCredentials);
    }

    let (rcr, auth_state) = webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|e| {
            info!("challenge_authenticate -> {:?}", e);
            Error::BadRequest(e)
        })?;

    // Store auth state in session
    session.insert("auth_state", (user_unique_id, auth_state))?;

    Ok(Json(rcr))
}

// 5. The browser and user have completed their part of the processing. Only in the
// case that the webauthn authenticate call returns Ok, is authentication considered
// a success. If the browser does not complete this call, or *any* error occurs,
// this is an authentication failure.

pub(crate) async fn finish_authentication(
    auth: Json<PublicKeyCredential>,
    session: Session,
    pool: Data<SqlitePool>,
    webauthn: Data<Webauthn>,
) -> WebResult<HttpResponse> {
    let (user_unique_id, auth_state): (Uuid, PasskeyAuthentication) =
        session.get("auth_state")?.ok_or(Error::CorruptSession)?;

    session.remove("auth_state");

    let auth_result = webauthn
        .finish_passkey_authentication(&auth, &auth_state)
        .map_err(|e| {
            info!("challenge_authenticate -> {:?}", e);
            Error::BadRequest(e)
        })?;

    let user_id_str = user_unique_id.to_string();

    // Fetch all credentials for this user
    let credentials = sqlx::query!(
        "SELECT id, credential_data FROM credentials WHERE user_id = ?",
        user_id_str
    )
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Database error: {:?}", e);
        Error::Database(e)
    })?;

    if credentials.is_empty() {
        return Err(Error::UserHasNoCredentials);
    }

    // Update the credential that was used
    for row in credentials {
        let mut passkey: Passkey = serde_json::from_str(&row.credential_data).map_err(|e| {
            error!("Failed to deserialize passkey: {:?}", e);
            Error::Serialization
        })?;

        // Try to update this credential with the auth result
        passkey.update_credential(&auth_result);

        // Serialize back to JSON
        let updated_credential_data = serde_json::to_string(&passkey).map_err(|e| {
            error!("Failed to serialize updated passkey: {:?}", e);
            Error::Serialization
        })?;

        // Update in database
        sqlx::query!(
            "UPDATE credentials SET credential_data = ? WHERE id = ?",
            updated_credential_data,
            row.id
        )
        .execute(pool.get_ref())
        .await
        .map_err(|e| {
            error!("Failed to update credential: {:?}", e);
            Error::Database(e)
        })?;
    }

    info!("Authentication Successful!");
    Ok(HttpResponse::Ok().finish())
}
