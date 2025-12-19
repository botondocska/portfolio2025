use actix_web::web::Data;

/*
 * Webauthn RS server side app state and setup code.
 */

// Configure the Webauthn instance by using the WebauthnBuilder. This defines
// the options needed for your site, and has some implications. One of these is that
// you can NOT change your rp_id (relying party id), without invalidating all
// webauthn credentials. Remember, rp_id is derived from your URL origin, meaning
// that it is your effective domain name.

use webauthn_rs::prelude::*;

pub(crate) fn startup() -> Data<Webauthn> {
    // Load from environment variables
    let rp_id = std::env::var("RP_ID").expect("RP_ID must be set in .env file");

    let rp_origin = std::env::var("RP_ORIGIN").expect("RP_ORIGIN must be set in .env file");

    let rp_origin = Url::parse(&rp_origin).expect("RP_ORIGIN must be a valid URL");

    let builder = WebauthnBuilder::new(&rp_id, &rp_origin).expect("Invalid Webauthn configuration");

    // Now, with the builder you can define other options.
    // Set a "nice" relying party name. Has no security properties and
    // may be changed in the future.
    let builder = builder.rp_name("Actix-web webauthn-rs");

    // Consume the builder and create our webauthn instance.
    // Webauthn has no mutable inner state, so Arc (Data) and read only is sufficient.
    Data::new(builder.build().expect("Failed to build Webauthn instance"))
}
