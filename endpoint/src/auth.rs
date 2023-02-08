use std::collections::HashMap;

use axum::body::{Bytes, HttpBody};
use axum::extract::multipart::MultipartRejection;
use axum::extract::{FromRequest, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{Request, StatusCode};
use axum::{async_trait, BoxError};
/*
 * Copyright (c) Martin Pompéry
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the crate's root directory of this source tree.
 */
use jsonwebtoken::errors::Result;
use jsonwebtoken::TokenData;
use jsonwebtoken::{DecodingKey, EncodingKey};
use jsonwebtoken::{Header, Validation};
use serde::{Deserialize, Serialize};

/*use rocket::http::Status;
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
};*/

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserToken {
    pub username: String,
}

#[derive(Debug, PartialEq)]
pub struct OAuth2ClientCredentials {
    pub id: String,
    pub secret: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum OAuth2TokenType {
    #[serde(rename = "bearer")]
    Bearer,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OAuth2TokenReply {
    pub access_token: String,
    pub token_type: OAuth2TokenType,
    pub scope: Option<String>,
    //pub expires_in: u32,
}

#[derive(Debug)]
pub struct OAuth2ClientCredentialsBody {
    pub grant_type: String,
    pub scope: Option<String>,
}

/*
while let Some(mut field) = body.next_field().await.unwrap() {
        let name = field.name().unwrap().to_string();
        let data = field.bytes().await.unwrap();

        println!("Length of `{}` is {} bytes", name, data.len());
    } */

#[async_trait]
impl<S, B> FromRequest<S, B> for OAuth2ClientCredentialsBody
where
    S: Send + Sync,
    B: HttpBody + Send + 'static,
    B::Data: Into<Bytes>,
    B::Error: Into<BoxError>,
{
    type Rejection = StatusCode;

    async fn from_request(
        req: Request<B>,
        state: &S,
    ) -> std::result::Result<Self, Self::Rejection> {
        if let Ok(mut multipart) = axum::extract::Multipart::from_request(req, state).await {
            let mut fields = HashMap::new();
            while let Some(field) = multipart
                .next_field()
                .await
                .or(Err(StatusCode::BAD_REQUEST))?
            {
                let name = field.name().unwrap_or_default().to_string();
                let data = field.text().await.or(Err(StatusCode::BAD_REQUEST))?;

                fields.insert(name, data);
            }
            if let Some(grant_type) = fields.get("grant_type") {
                return Ok(OAuth2ClientCredentialsBody {
                    grant_type: grant_type.clone(),
                    scope: fields.get("scope").cloned(),
                });
            }
        }
        Err(StatusCode::BAD_REQUEST)
    }
}

/*#[async_trait]
    impl<S, B> FromRequest<S, B> for OAuth2ClientCredentialsBody
    where
        S: Send + Sync,
    {
    type Rejection = StatusCode;

    /*async fn from_request(
        parts: &mut Parts,
        state: &S,
    ) -> std::result::Result<Self, Self::Rejection> {
        if let Some(auth_header) = parts.headers.get("Authorization") {
            if let Ok(auth_header) = auth_header.to_str() {
                let split = auth_header.split_whitespace().collect::<Vec<_>>();
                if split.len() != 2 {
                    return Err(StatusCode::BAD_REQUEST);
                }
                let (basic, payload) = (split[0], split[1]);
                if basic != "Basic" {
                    return Err(StatusCode::UNAUTHORIZED);
                }
                if let Some(credentials) = decode_basic_auth(payload) {
                    return Ok(credentials);
                }
            }
        }
        Err(StatusCode::BAD_REQUEST)
    }*/
}*/

#[derive(Debug)]
pub enum UserTokenError {
    //Missing,
    Invalid,
    Missing,
}

/*
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
}*/

#[async_trait]
impl<S> FromRequestParts<S> for OAuth2ClientCredentials
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> std::result::Result<Self, Self::Rejection> {
        if let Some(auth_header) = parts.headers.get("Authorization") {
            if let Ok(auth_header) = auth_header.to_str() {
                let split = auth_header.split_whitespace().collect::<Vec<_>>();
                if split.len() != 2 {
                    return Err(StatusCode::BAD_REQUEST);
                }
                let (basic, payload) = (split[0], split[1]);
                if basic != "Basic" {
                    return Err(StatusCode::UNAUTHORIZED);
                }
                if let Some(credentials) = decode_basic_auth(payload) {
                    return Ok(credentials);
                }
            }
        }
        Err(StatusCode::BAD_REQUEST)
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

/*#[rocket::async_trait]
impl<'r> FromRequest<'r> for UserToken {
    type Error = status::Custom<UserTokenError>;

    async fn from_request(
        req: &'r Request<'_>,
    ) -> request::Outcome<Self, status::Custom<UserTokenError>> {
        if let Some(authen_header) = req.headers().get_one("Authorization") {
            let authen_str = authen_header.to_string();
            if authen_str.starts_with("Bearer") {
                let token = authen_str[6..authen_str.len()].trim();
                if let Ok(token_data) = decode_token(token.to_string()) {
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
}*/

const MY_NOT_SO_SECRET_KEY: &[u8; 8] = b"abcdefgh";

fn decode_token(token: String) -> Result<TokenData<UserToken>> {
    let v = Validation {
        validate_exp: false,
        ..Default::default()
    };
    jsonwebtoken::decode::<UserToken>(&token, &DecodingKey::from_secret(MY_NOT_SO_SECRET_KEY), &v)
}

pub fn encode_token(u: &UserToken) -> Result<String> {
    jsonwebtoken::encode(
        &Header::default(),
        u,
        &EncodingKey::from_secret(MY_NOT_SO_SECRET_KEY),
    )
}

/*impl<'a> OpenApiFromRequest<'a> for UserToken {
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
}*/
