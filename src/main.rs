use actix_files as fs;
use actix_session::SessionMiddleware;
use actix_web::{
    App, HttpServer,
    cookie::{Key, SameSite},
    middleware::Logger,
    web::{self, JsonConfig},
};
use sqlx::sqlite::SqlitePoolOptions;
//use tracing::{info, error};

use crate::handlers::auth::{
    finish_authentication, finish_register, login_page, start_authentication, start_register,
};
use crate::session::DatabaseSession;
use crate::startup::startup;

mod handlers;
mod session;
mod startup;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    if std::env::var("RUST_LOG").is_err() {
        unsafe {
            std::env::set_var("RUST_LOG", "INFO");
        }
    }
    tracing_subscriber::fmt::init();

    // Load DATABASE_URL from environment
    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:portfolio.db".to_string());

    // Create database connection pool
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to connect to database");

    tracing::info!("Database connected successfully");

    // Run migrations (ensure database schema is up to date)
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    tracing::info!("Migrations completed successfully");

    // Generate secret key for cookies
    // IMPORTANT: In production, load this from environment variable or secure config
    // and keep it consistent across restarts
    let key = Key::generate();

    // Initialize webauthn
    let webauthn = startup();

    // Clone pool for the closure
    let pool_clone = pool.clone();

    HttpServer::new(move || {
        App::new()
            // Middleware
            .wrap(Logger::default())
            .wrap(
                SessionMiddleware::builder(DatabaseSession::new(pool_clone.clone()), key.clone())
                    .cookie_name("webauthnrs".to_string())
                    .cookie_same_site(SameSite::Strict)
                    .cookie_http_only(true)
                    .cookie_secure(true) // Set to true in production with HTTPS
                    .build(),
            )
            .app_data(JsonConfig::default())
            .app_data(webauthn.clone())
            .app_data(web::Data::new(pool_clone.clone()))
            // Serve static files (CSS, JS)
            .service(fs::Files::new("/static", "./static"))
            // Routes
            .route("/login", web::get().to(login_page))
            .route("/", web::get().to(login_page)) // For now, redirect to login
            // API routes for WebAuthn
            .route("/register_start/{username}", web::post().to(start_register))
            .route("/register_finish", web::post().to(finish_register))
            .route(
                "/login_start/{username}",
                web::post().to(start_authentication),
            )
            .route("/login_finish", web::post().to(finish_authentication))
    })
    .bind(("127.0.0.1", 3443))?
    .run()
    .await
}
