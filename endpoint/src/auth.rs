use std::collections::HashSet;
use std::ops::Deref;

/*
 * Copyright (c) Martin Pompéry
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the crate's root directory of this source tree.
 */

#![allow(renamed_and_removed_lints)]

use jsonwebtoken::errors::Result;
use jsonwebtoken::{Algorithm, TokenData};
use jsonwebtoken::{DecodingKey, EncodingKey};
use jsonwebtoken::{Header, Validation};

use rocket::http::Status;
use rocket::outcome::Outcome;
use rocket::request::{self, FromRequest, Request};
use rocket::response::status;
use rocket::serde::{Deserialize, Serialize};

use rocket_okapi::okapi::map;
use rocket_okapi::okapi::openapi3::{
    Object, SecurityRequirement, SecurityScheme, SecuritySchemeData,
};
use rocket_okapi::{
    gen::OpenApiGenerator,
    request::{OpenApiFromRequest, RequestHeaderInput},
};
use rsa::pkcs8::EncodePrivateKey;
use rsa::pkcs8::EncodePublicKey;
use rsa::{pkcs8::LineEnding, RsaPrivateKey, RsaPublicKey};

const KEY_BITS: usize = 3072;

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct KeyPair {
    pub priv_key: String,
    pub pub_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct UserToken {
    pub username: String,
}

#[derive(Debug, PartialEq)]
pub struct OAuth2ClientCredentials {
    pub id: String,
    pub secret: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub enum OAuth2TokenType {
    #[serde(rename = "bearer")]
    Bearer,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct OAuth2TokenReply {
    pub access_token: String,
    pub token_type: OAuth2TokenType,
    pub scope: Option<String>,
    //pub expires_in: u32,
}

#[derive(rocket::form::FromForm)]
pub struct OAuth2ClientCredentialsBody<'r> {
    pub grant_type: &'r str,
    pub scope: Option<&'r str>,
}

#[derive(Debug)]
pub enum UserTokenError {
    //Missing,
    Invalid,
    Missing,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for OAuth2ClientCredentials {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        if let Some(auth_header) = req.headers().get_one("Authorization") {
            let split = auth_header.split_whitespace().collect::<Vec<_>>();
            if split.len() != 2 {
                return Outcome::Failure((Status::BadRequest, ()));
            }
            let (basic, payload) = (split[0], split[1]);
            if basic != "Basic" {
                return Outcome::Failure((Status::Unauthorized, ()));
            }
            if let Some(credentials) = decode_basic_auth(payload) {
                return Outcome::Success(credentials);
            }
        }

        Outcome::Failure((Status::BadRequest, ()))
    }
}

fn decode_basic_auth(raw_auth_info: &str) -> Option<OAuth2ClientCredentials> {
    if let Ok(auth_info) = base64::decode(raw_auth_info) {
        if let Ok(decoded_str) = String::from_utf8(auth_info) {
            let username_password = decoded_str.split(':').collect::<Vec<_>>();
            if username_password.len() == 2 {
                let credentials = OAuth2ClientCredentials {
                    id: String::from(username_password[0]),
                    secret: String::from(username_password[1]),
                };
                return Some(credentials);
            }
        }
    }

    None
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for UserToken {
    type Error = status::Custom<UserTokenError>;

    async fn from_request(
        req: &'r Request<'_>,
    ) -> request::Outcome<Self, status::Custom<UserTokenError>> {
        if let Some(authen_header) = req.headers().get_one("Authorization") {
            println!(
                "request state: {:?}",
                req.rocket().state::<KeyPair>().unwrap()
            );
            let authen_str = authen_header.to_string();
            if authen_str.starts_with("Bearer") {
                let token = authen_str[6..authen_str.len()].trim();
                let pub_key = &req.rocket().state::<KeyPair>().unwrap().pub_key;
                if let Ok(token_data) = decode_token(token.to_string(), pub_key.to_string()) {
                    return Outcome::Success(token_data.claims);
                }
            }

            Outcome::Failure((
                Status::BadRequest,
                status::Custom(Status::BadRequest, UserTokenError::Invalid),
            ))
        } else {
            Outcome::Failure((
                Status::Unauthorized,
                status::Custom(Status::Unauthorized, UserTokenError::Missing),
            ))
        }
    }
}

// const MY_NOT_SO_SECRET_KEY: &[u8; 8] = b"abcdefgh";

pub fn generate_keys() -> KeyPair {
    let mut rng = rand::thread_rng();

    let private_key = RsaPrivateKey::new(&mut rng, KEY_BITS).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);

    let priv_key = private_key
        .to_pkcs8_pem(LineEnding::default())
        .expect("could not serialize private key")
        .deref()
        .clone();
    let pub_key = public_key
        .to_public_key_pem(LineEnding::default())
        .expect("could not serialize public key");

    KeyPair { priv_key, pub_key }
}

fn decode_token(token: String, pub_key: String) -> Result<TokenData<UserToken>> {
    let mut v = Validation::new(Algorithm::RS256);
    v.validate_exp = false;
    v.required_spec_claims = HashSet::new();

    jsonwebtoken::decode::<UserToken>(
        &token,
        &DecodingKey::from_rsa_pem(pub_key.as_bytes()).unwrap(),
        &v,
    )
}

pub fn encode_token(u: &UserToken, priv_key: String) -> Result<String> {
    let header = Header::new(Algorithm::RS256);

    jsonwebtoken::encode(
        &header,
        u,
        &EncodingKey::from_rsa_pem(priv_key.as_bytes()).unwrap(),
    )
}

impl<'a> OpenApiFromRequest<'a> for UserToken {
    fn from_request_input(
        _gen: &mut OpenApiGenerator,
        _name: String,
        _required: bool,
    ) -> rocket_okapi::Result<RequestHeaderInput> {
        // Setup global requirement for Security scheme
        let security_scheme = SecurityScheme {
            description: Some("OAuth2 Client Credentials Grant (RFC6749 4.4)".to_owned()),
            // Setup data requirements.
            // In this case the header `Authorization: mytoken` needs to be set.
            data: SecuritySchemeData::OAuth2 {
                flows: rocket_okapi::okapi::openapi3::OAuthFlows::ClientCredentials {
                    token_url: "/2/auth/token".into(),
                    refresh_url: None,
                    scopes: map! {
                        "footprint:list".to_owned() => "Ability to list footprints".to_owned(),
                        "footprint:read".to_owned() => "Ability to access individual footprints".to_owned(),
                    },
                    extensions: Default::default(),
                },
            },
            extensions: Object::default(),
        };
        // Add the requirement for this route/endpoint
        // This can change between routes.
        let mut security_req = SecurityRequirement::new();
        // Each security requirement needs to be met before access is allowed.
        security_req.insert("BearerAuth".to_owned(), Vec::new());
        // These vvvvvvv-----^^^^^^^^ values need to match exactly!
        Ok(RequestHeaderInput::Security(
            "BearerAuth".to_owned(),
            security_scheme,
            security_req,
        ))
    }
}

#[test]
fn decode_basic_auth_test() {
    assert_eq!(
        Some(OAuth2ClientCredentials {
            id: "martin".into(),
            secret: "secret".into()
        }),
        decode_basic_auth(&base64::encode(b"martin:secret"))
    );
}
