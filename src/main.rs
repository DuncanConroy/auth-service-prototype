#![feature(option_result_contains)]
#[macro_use]
extern crate rocket;

use std::error::Error;
use std::thread::sleep;
use std::time::Duration;

use josekit::jwe::{JweHeader, ECDH_ES};
use josekit::jwt::JwtPayload;
use josekit::{jwt, JoseError, Value};
use rocket::form::validate::Contains;
use rocket::http::ext::IntoCollection;
use rocket::http::hyper::{Response, StatusCode};
use rocket::http::StatusClass::ClientError;
use rocket::http::{Method, Status};
use rocket::outcome::Outcome::{Failure, Success};
use rocket::request::{FromRequest, Outcome};
use rocket::response::status;
use rocket::serde::json::serde_json::json;
use rocket::serde::{json::Json, Deserialize};
use rocket::Request;
use rocket_cors::{AllowedHeaders, AllowedOrigins};

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
struct Login<'r> {
    username: &'r str,
    password: &'r str,
}

#[post("/", data = "<login>")]
async fn login(login: Json<Login<'_>>) -> status::Custom<String> {
    if !check_login(login.0).await {
        return status::Custom(Status::Forbidden, "".into());
    }

    let jwt = sign_jwt().expect("Couldn't sign jwt");
    status::Custom(Status::Ok, jwt)
}

async fn check_login(login: Login<'_>) -> bool {
    sleep(Duration::from_millis(500));
    login.username == "admin" && login.password == "admin"
}

#[derive(Debug)]
struct JwtKey {
    payload: JwtPayload,
    header: JweHeader,
}

#[async_trait]
impl<'r> FromRequest<'r> for JwtKey {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let key = request.headers().get_one("Authorization");

        if key.is_some() {
            let jwt = key.unwrap().trim_start_matches("Bearer ");
            println!("jwt: {:?}", jwt);
            // Decrypting JWT
            let private_key = std::fs::read(PRIVATE_KEY).unwrap();
            let decrypter = ECDH_ES.decrypter_from_pem(&private_key).unwrap();
            let decrypted = jwt::decode_with_decrypter(&jwt, &decrypter);
            if decrypted.is_ok() {
                let (payload, header) = decrypted.unwrap();
                return Success(JwtKey { payload, header });
            }
        }

        return Failure((Status::Forbidden, ()));
    }
}

#[get("/")]
async fn dashboard(jwt_key: JwtKey) -> status::Custom<String> {
    println!("payload:{}, header:{}", jwt_key.payload, jwt_key.header);
    let authz = jwt_key.payload.claim("authz");
    if has_access(authz).contains(&true) {
        return status::Custom(Status::Ok, "user A, User B".into());
    }

    status::Custom(Status::Forbidden, "".into())
}

fn has_access(authz: Option<&Value>) -> Option<bool> {
    let x = authz?
        .as_array()?
        .iter()
        .any(|it| it.as_str().unwrap_or("").eq("dashboard.viewer"));
    Some(x)
}

#[rocket::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let path: String = PUBLIC_KEY.into();
    println!("{}", path);

    let allowed_origins = AllowedOrigins::some_regex(&["http://localhost.*"]);

    // You can also deserialize this
    let cors = rocket_cors::CorsOptions {
        allowed_origins,
        allowed_methods: vec![Method::Get, Method::Post]
            .into_iter()
            .map(From::from)
            .collect(),
        allowed_headers: AllowedHeaders::some(&["Authorization", "Accept", "content-type"]),
        allow_credentials: true,
        ..Default::default()
    }
    .to_cors()?;

    rocket::build()
        .attach(cors)
        .mount("/login", routes![login])
        .mount("/dashboard", routes![dashboard])
        .launch()
        .await
        .expect("Couldn't launch rocket.");

    Ok(())
}

const PRIVATE_KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/private.pem");
const PUBLIC_KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/public.pem");

fn sign_jwt() -> Result<String, JoseError> {
    let mut header = JweHeader::new();
    header.set_token_type("JWT");
    header.set_content_encryption("A128CBC-HS256");

    let mut payload = JwtPayload::new();
    payload.set_subject("subject");
    payload.set_claim(
        "authz",
        Some(json!(vec![
            "user.admin",
            "battery.admin",
            "dashboard.viewer"
        ])),
    );

    // Encrypting JWT
    let public_key = std::fs::read(PUBLIC_KEY).unwrap();
    let encrypter = ECDH_ES.encrypter_from_pem(&public_key)?;
    let jwt = jwt::encode_with_encrypter(&payload, &header, &encrypter);

    jwt
}
