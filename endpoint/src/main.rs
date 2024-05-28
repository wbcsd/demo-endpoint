/*
 * Copyright (c) Martin Pompéry
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the crate's root directory of this source tree.
 */
#[macro_use]
extern crate rocket;

#[macro_use]
extern crate lazy_static;
mod api_types;
mod auth;
mod error;
mod openid_conf;
mod sample_data;

use pact_data_model::*;
use auth::{load_keys, UserToken};
use chrono::{DateTime, Utc};
use either::Either;
use std::cmp::min;

use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, Jwk, JwkSet, KeyAlgorithm, PublicKeyUse,
    RSAKeyParameters,
};
use okapi::openapi3::{Object, Parameter, ParameterValue};
use rocket::form::Form;
use rocket::request::FromRequest;
use rocket::Error as RocketError;

use rocket::serde::json::Json;
use rocket::State;
use rocket_okapi::request::{OpenApiFromRequest, RequestHeaderInput};
use rocket_okapi::settings::OpenApiSettings;
use rocket_okapi::swagger_ui::{make_swagger_ui, SwaggerUIConfig};
use rocket_okapi::{get_openapi_route, openapi, openapi_get_routes_spec};

use api_types::*;
use openid_conf::OpenIdConfiguration;
use rsa::traits::PublicKeyParts;
use sample_data::PCF_DEMO_DATA;
use Either::Left;

#[cfg(test)]
use rocket::local::blocking::Client;

use crate::auth::KeyPair;

// minimum number of results to return from Action `ListFootprints`
const ACTION_LIST_FOOTPRINTS_MIN_RESULTS: usize = 10;

const AUTH_USERNAME: &str = "hello";
const AUTH_PASSWORD: &str = "pathfinder";

const API_URL: &str = "https://api.pathfinder.sine.dev";

/// endpoint to retrieve the OpenId configuration document with the token_endpoint
#[get("/2/.well-known/openid-configuration")]
fn openid_configuration() -> Json<OpenIdConfiguration> {
    let openid_conf = OpenIdConfiguration {
        token_endpoint: format!("{API_URL}/2/auth/token"),
        issuer: url::Url::parse(API_URL).unwrap(),
        authorization_endpoint: format!("{API_URL}/2/auth/token"),
        jwks_uri: format!("{API_URL}/2/jwks"),
        response_types_supported: vec![format!("token")],
        subject_types_supported: vec![format!("public")],
        id_token_signing_alg_values_supported: vec![format!("RS256")],
    };
    Json(openid_conf)
}

/// endpoint to retrieve the Json Web Key Set to verify the token's signature
#[get("/2/jwks")]
fn jwks(state: &State<KeyPair>) -> Json<JwkSet> {
    let pub_key = &state.pub_key;

    let jwks = JwkSet {
        keys: vec![Jwk {
            common: CommonParameters {
                public_key_use: Some(PublicKeyUse::Signature),
                key_operations: None,
                key_algorithm: Some(KeyAlgorithm::RS256),
                key_id: Some("Public key".to_string()),
                x509_url: None,
                x509_chain: None,
                x509_sha1_fingerprint: None,
                x509_sha256_fingerprint: None,
            },
            algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
                key_type: jsonwebtoken::jwk::RSAKeyType::RSA,
                n: base64::encode_config(pub_key.n().to_bytes_be(), base64::URL_SAFE_NO_PAD),
                e: base64::encode_config(pub_key.e().to_bytes_be(), base64::URL_SAFE_NO_PAD),
            }),
        }],
    };

    Json(jwks)
}

/// endpoint to create an oauth2 client credentials grant (RFC 6749 4.4)
#[post("/token", data = "<body>")]
fn oauth2_create_token(
    req: auth::OAuth2ClientCredentials,
    body: Form<auth::OAuth2ClientCredentialsBody<'_>>,
    state: &State<KeyPair>,
) -> Either<Json<auth::OAuth2TokenReply>, error::OAuth2ErrorMessage> {
    if req.id == AUTH_USERNAME && req.secret == AUTH_PASSWORD {
        let access_token =
            auth::encode_token(&auth::UserToken { username: req.id }, state).unwrap();

        let reply = auth::OAuth2TokenReply {
            access_token,
            token_type: auth::OAuth2TokenType::Bearer,
            scope: body.scope.map(String::from),
        };
        Either::Left(Json(reply))
    } else {
        Either::Right(error::OAuth2ErrorMessage {
            error_description: "Invalid client credentials",
            error: "invalid_client",
        })
    }
}

#[derive(Debug)]
pub struct Host<'r>(Option<&'r str>);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Host<'r> {
    type Error = ();

    async fn from_request(
        request: &'r rocket::Request<'_>,
    ) -> rocket::request::Outcome<Self, Self::Error> {
        rocket::request::Outcome::Success(Host(request.headers().get("Host").next()))
    }
}

impl<'r> OpenApiFromRequest<'r> for Host<'r> {
    fn from_request_input(
        _gen: &mut rocket_okapi::gen::OpenApiGenerator,
        _name: String,
        _required: bool,
    ) -> rocket_okapi::Result<RequestHeaderInput> {
        Ok(RequestHeaderInput::None)
    }
}

#[derive(Debug)]
pub struct Filter<'r>(Option<&'r str>);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Filter<'r> {
    type Error = ();

    async fn from_request(
        request: &'r rocket::Request<'_>,
    ) -> rocket::request::Outcome<Self, Self::Error> {
        rocket::request::Outcome::Success(Filter(
            request
                .query_value("$filter")
                .map(|r| r.unwrap_or_default()),
        ))
    }
}

impl<'r> OpenApiFromRequest<'r> for Filter<'r> {
    fn from_request_input(
        gen: &mut rocket_okapi::gen::OpenApiGenerator,
        _name: String,
        _required: bool,
    ) -> rocket_okapi::Result<RequestHeaderInput> {
        let schema = gen.json_schema::<String>();
        Ok(RequestHeaderInput::Parameter(Parameter {
            name: "$filter".to_owned(),
            location: "query".to_owned(),
            description: Some("Syntax as defined by the ODatav4 specification".to_owned()),
            required: false,
            deprecated: false,
            allow_empty_value: true,
            value: ParameterValue::Schema {
                style: None,
                explode: None,
                allow_reserved: false,
                schema,
                example: None,
                examples: None,
            },
            extensions: Object::default(),
        }))
    }
}

fn filtered_data(filter: Option<&'_ str>) -> Result<Vec<ProductFootprint>, String> {
    // This implementation of OData v4 $filter syntax only works for the subset supported by the
    // PACT spec and should be considered merely a demo implemenation. Real implementations should
    // use a proper parser instead.
    let Some(filter) = filter else {
        return Ok(PCF_DEMO_DATA.to_vec());
    };
    let filter = filter.replace(['(', ')'], " ");
    let conjunctions = filter.split(" and ").collect::<Vec<_>>();
    let mut pfs = PCF_DEMO_DATA.to_vec();
    for c in conjunctions {
        let c = c.trim();
        if c.starts_with("productIds/any productId: productId eq ")
            || c.starts_with("companyIds/any companyId: companyId eq ")
        {
            let value = c.split(" eq ").last().unwrap();
            let value = value[1..value.len() - 1].to_string();
            let mut retained = vec![];
            for pf in pfs.into_iter() {
                let is_match = if c.starts_with("productIds") {
                    pf.product_ids.0.iter().any(|id| id.0 == value)
                } else {
                    pf.company_ids.0.iter().any(|id| id.0 == value)
                };
                if is_match {
                    retained.push(pf);
                }
            }
            pfs = retained;
        } else {
            let parts = c
                .split(' ')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>();
            if parts.len() != 3 {
                return Err(format!(
                    "Not a valid condition, expected 3 parts, but found: {parts:?}"
                ));
            }
            let property = parts[0];
            let operator = parts[1];
            let value = parts[2];
            if !value.starts_with('\'') && value.ends_with('\'') {
                return Err(format!(
                    "Value must be a string enclosed in '...', but found: {value}"
                ));
            }
            let value = value[1..value.len() - 1].to_string();
            let mut retained = vec![];
            match operator {
                "eq" => {
                    for pf in pfs.into_iter() {
                        let is_eq = match property {
                            "created" => pf.created.to_string() == value,
                            "updated" => pf
                                .updated
                                .map(|v| v.to_string() == value)
                                .unwrap_or_default(),
                            "productCategoryCpc" => pf.product_category_cpc.0 == value,
                            "pcf/geographyCountry" => pf
                                .clone()
                                .pcf
                                .geographic_scope
                                .map(|v| {
                                    v.geography_country()
                                        .map(|v| v == value)
                                        .unwrap_or_default()
                                })
                                .unwrap_or_default(),
                            "pcf/referencePeriodStart" => {
                                pf.pcf.reference_period_start.to_string() == value
                            }
                            "pcf/referencePeriodEnd" => {
                                pf.pcf.reference_period_end.to_string() == value
                            }
                            _ => {
                                return Err(format!("Unsupported property {property}"));
                            }
                        };
                        if is_eq {
                            retained.push(pf);
                        }
                    }
                }
                operator => {
                    let Ok(value) = value.parse::<DateTime<Utc>>() else {
                        return Err(format!("Not a valid datetime: {value}"));
                    };
                    for pf in pfs.into_iter() {
                        let v = match property {
                            "created" => Some(pf.created),
                            "updated" => pf.updated,
                            "pcf/referencePeriodStart" => Some(pf.pcf.reference_period_start),
                            "pcf/referencePeriodEnd" => Some(pf.pcf.reference_period_end),
                            _ => {
                                return Err(format!("Unsupported property {property}"));
                            }
                        };
                        if let Some(v) = v {
                            let is_match = match operator {
                                "lt" => v < value,
                                "le" => v <= value,
                                "gt" => v > value,
                                "ge" => v >= value,
                                _ => {
                                    return Err(format!("Unsupported operator {operator}"));
                                }
                            };
                            if is_match {
                                retained.push(pf);
                            }
                        }
                    }
                }
            }
            pfs = retained;
        }
    }
    Ok(pfs)
}

#[get("/2/footprints?<limit>&<offset>", format = "json")]
fn get_list(
    auth: Option<UserToken>,
    limit: usize,
    offset: usize,
    filter: Filter,
    host: Host,
) -> Either<PfListingResponse, error::BadRequest> {
    if auth.is_none() {
        return Either::Right(Default::default());
    }

    let data = match filtered_data(filter.0) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("{e}");
            return Either::Right(Default::default());
        }
    };

    if offset > data.len() {
        return Either::Right(Default::default());
    }

    let max_limit = data.len() - offset;
    let limit = min(limit, max_limit);

    let next_offset = offset + limit;
    let footprints = Json(PfListingResponseInner {
        data: data[offset..offset + limit].to_vec(),
    });

    if next_offset < data.len() {
        let host = host
            .0
            .map(|host| {
                if host.starts_with("127.0.0.1:") || host.starts_with("localhost:") {
                    format!("http://{host}")
                } else {
                    format!("https://{host}")
                }
            })
            .unwrap_or_default();
        let link =
            format!("<{host}/2/footprints?offset={next_offset}&limit={limit}>; rel=\"next\"");
        Left(PfListingResponse::Cont(
            footprints,
            rocket::http::Header::new("link", link),
        ))
    } else {
        Left(PfListingResponse::Finished(footprints))
    }
}

#[openapi]
#[get("/2/footprints?<limit>", format = "json", rank = 2)]
fn get_footprints(
    auth: Option<UserToken>,
    limit: Option<usize>,
    filter: Filter,
    host: Host,
) -> Either<PfListingResponse, error::BadRequest> {
    let limit = limit.unwrap_or(ACTION_LIST_FOOTPRINTS_MIN_RESULTS);
    let offset = 0;
    get_list(auth, limit, offset, filter, host)
}



#[openapi]
#[get("/2/footprints/<id>", format = "json", rank = 1)]
fn get_pcf(
    id: PfIdParam,
    auth: Option<UserToken>,
) -> Either<Json<ProductFootprintResponse>, error::BadRequest> {
    if auth.is_some() {
        PCF_DEMO_DATA
            .iter()
            .find(|pf| pf.id == id.0)
            .map(|pcf| Left(Json(ProductFootprintResponse { data: pcf.clone() })))
            .unwrap_or_else(|| Either::Right(Default::default()))
    } else {
        Either::Right(Default::default())
    }
}

#[get("/2/footprints/<_id>", format = "json", rank = 2)]
fn get_pcf_unauth(_id: &str) -> error::BadRequest {
    Default::default()
}

#[openapi]
#[post("/2/events", data = "<event>", format = "json")]
fn post_event(
    auth: UserToken,
    event: Option<rocket::serde::json::Json<PathfinderEvent>>,
) -> EventsApiResponse {
    let _auth = auth; // ignore auth is not used;

    println!("data = {event:#?}");

    let res = if let Some(event) = event {
        match event.data {
            PathfinderEventData::PFUpdateEvent(_) => EventsApiResponse::Ok(()),
            PathfinderEventData::PFRequestEvent(_) => {
                EventsApiResponse::NotImpl(Default::default())
            }
        }
    } else {
        EventsApiResponse::BadReq(error::BadRequest::default())
    };

    println!("returning with: {res:#?}");

    res
}

#[post("/2/events", rank = 2)]
fn post_event_fallback() -> EventsApiResponse {
    EventsApiResponse::NoAuth(error::BadRequest::default())
}

#[get("/")]
fn index() -> rocket::response::Redirect {
    rocket::response::Redirect::to("/swagger-ui/")
}

#[catch(400)]
fn bad_request() -> error::BadRequest {
    Default::default()
}

#[catch(default)]
fn default_handler() -> error::BadRequest {
    Default::default()
}

const OPENAPI_PATH: &str = "../openapi.json";

fn create_server(key_pair: KeyPair) -> rocket::Rocket<rocket::Build> {
    let settings = OpenApiSettings::default();
    let (mut openapi_routes, openapi_spec) =
        openapi_get_routes_spec![settings: get_pcf, get_footprints, post_event];

    openapi_routes.push(get_openapi_route(openapi_spec, &settings));

    rocket::build()
        .mount("/", openapi_routes)
        .mount("/", routes![index])
        .mount("/", routes![get_list, get_pcf_unauth, post_event_fallback])
        .mount("/", routes![openid_configuration, jwks])
        .mount("/2/auth", routes![oauth2_create_token])
        .mount(
            "/swagger-ui/",
            make_swagger_ui(&SwaggerUIConfig {
                url: OPENAPI_PATH.to_owned(),
                ..Default::default()
            }),
        )
        .manage(key_pair)
        .register("/", catchers![bad_request, default_handler])
}

#[rocket::main]
async fn main() -> Result<(), RocketError> {
    let rocket = create_server(load_keys());
    let _ = rocket.launch().await?;
    Ok(())
}

#[cfg(test)]
const EXAMPLE_HOST: &str = "api.pathfinder.sine.dev";

#[cfg(test)]
lazy_static! {
    static ref TEST_KEYPAIR: KeyPair = load_keys();
}

// tests the /v2/auth/token endpoint
#[test]
fn post_auth_action_test() {
    use std::collections::HashMap;

    let auth_uri = "/2/auth/token";

    let client = &Client::tracked(create_server(TEST_KEYPAIR.clone())).unwrap();

    // invalid credentials
    {
        let credentials = base64::encode("hello:wrong_password");
        let basic_auth = format!("Basic {credentials}");
        let resp = client
            .post(auth_uri)
            .header(rocket::http::Header::new("Host", EXAMPLE_HOST))
            .header(rocket::http::Header::new("Authorization", basic_auth))
            .header(rocket::http::Header::new(
                "Content-Type",
                "application/x-www-form-urlencoded",
            ))
            .body("grant_type=client_credentials")
            .dispatch();

        assert_eq!(
            rocket::http::ContentType::JSON,
            resp.content_type().unwrap()
        );
        assert_eq!(rocket::http::Status::BadRequest, resp.status());

        let error_response: HashMap<String, String> = resp.into_json().unwrap();
        assert_eq!(
            HashMap::from([
                ("error".to_string(), "invalid_client".to_string()),
                (
                    "error_description".to_string(),
                    "Invalid client credentials".to_string()
                )
            ]),
            error_response
        );
    }

    // valid credentials
    {
        let credentials = base64::encode(format!("{}:{}", AUTH_USERNAME, AUTH_PASSWORD));
        let basic_auth = format!("Basic {credentials}");

        let resp = client
            .post(auth_uri)
            .header(rocket::http::Header::new("Host", EXAMPLE_HOST))
            .header(rocket::http::Header::new("Authorization", basic_auth))
            .header(rocket::http::Header::new(
                "Content-Type",
                "application/x-www-form-urlencoded",
            ))
            .body("grant_type=client_credentials")
            .dispatch();

        assert_eq!(
            rocket::http::ContentType::JSON,
            resp.content_type().unwrap()
        );
        assert_eq!(rocket::http::Status::Ok, resp.status());
    }
}

#[test]
fn verify_token_signature_test() {
    use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
    use std::collections::HashSet;

    let client = &Client::tracked(create_server(TEST_KEYPAIR.clone())).unwrap();

    let token = UserToken {
        username: "hello".to_string(),
    };

    let key_pair = client.rocket().state::<KeyPair>().unwrap();

    let jwt = auth::encode_token(&token, key_pair).ok().unwrap();

    let response = client.get("/2/jwks").dispatch();

    let jwks: JwkSet = response.into_json().unwrap();

    let jwk = jwks.keys.first().unwrap();

    let decoding_key = DecodingKey::from_jwk(jwk).unwrap();

    let mut v = Validation::new(Algorithm::RS256);
    v.validate_exp = false;
    v.required_spec_claims = HashSet::from(["username".to_string()]);

    assert_eq!(
        token.username,
        decode::<auth::UserToken>(&jwt, &decoding_key, &v)
            .unwrap()
            .claims
            .username
    );
}

#[test]
fn get_list_test() {
    let client = &Client::tracked(create_server(TEST_KEYPAIR.clone())).unwrap();

    let token = UserToken {
        username: "hello".to_string(),
    };

    let key_pair = client.rocket().state::<KeyPair>().unwrap();

    let jwt = auth::encode_token(&token, key_pair).ok().unwrap();
    let bearer_token = format!("Bearer {jwt}");

    let get_list_uri = "/2/footprints";

    // test auth
    {
        let resp = client
            .get(get_list_uri)
            .header(rocket::http::Header::new("Authorization", bearer_token))
            .header(rocket::http::Header::new("Host", EXAMPLE_HOST))
            .dispatch();

        assert_eq!(rocket::http::Status::Ok, resp.status());
        assert_eq!(
            PfListingResponseInner {
                data: PCF_DEMO_DATA.to_vec()
            },
            resp.into_json().unwrap()
        );
    }

    // test unauth
    {
        let resp = client
            .get(get_list_uri)
            .header(rocket::http::Header::new("Host", EXAMPLE_HOST))
            .dispatch();
        assert_eq!(rocket::http::Status::BadRequest, resp.status());
    }
}

#[test]
fn get_list_with_filter_eq_test() {
    let client = &Client::tracked(create_server(TEST_KEYPAIR.clone())).unwrap();

    let token = UserToken {
        username: "hello".to_string(),
    };

    let key_pair = client.rocket().state::<KeyPair>().unwrap();

    let jwt = auth::encode_token(&token, key_pair).ok().unwrap();
    let bearer_token = format!("Bearer {jwt}");

    let get_list_with_limit_uri = "/2/footprints?$filter=pcf/geographyCountry+eq+'FR'";

    let resp = client
        .get(get_list_with_limit_uri)
        .header(rocket::http::Header::new("Authorization", bearer_token))
        .header(rocket::http::Header::new("Host", EXAMPLE_HOST))
        .dispatch();

    assert_eq!(rocket::http::Status::Ok, resp.status());
    let json: PfListingResponseInner = resp.into_json().unwrap();
    assert_eq!(json.data.len(), 1);
}

#[test]
fn get_list_with_filter_lt_test() {
    let client = &Client::tracked(create_server(TEST_KEYPAIR.clone())).unwrap();

    let token = UserToken {
        username: "hello".to_string(),
    };

    let key_pair = client.rocket().state::<KeyPair>().unwrap();

    let jwt = auth::encode_token(&token, key_pair).ok().unwrap();

    let bearer_token = format!("Bearer {jwt}");

    let get_list_with_limit_uri = "/2/footprints?$filter=updated+lt+'2023-06-27T13:00:00.000Z'";

    let resp = client
        .get(get_list_with_limit_uri)
        .header(rocket::http::Header::new("Authorization", bearer_token))
        .header(rocket::http::Header::new("Host", EXAMPLE_HOST))
        .dispatch();

    assert_eq!(rocket::http::Status::Ok, resp.status());
    let json: PfListingResponseInner = resp.into_json().unwrap();
    assert_eq!(json.data.len(), 1);
}

#[test]
fn get_list_with_filter_eq_and_lt_test() {
    let client = &Client::tracked(create_server(TEST_KEYPAIR.clone())).unwrap();

    let token = UserToken {
        username: "hello".to_string(),
    };

    let key_pair = client.rocket().state::<KeyPair>().unwrap();

    let jwt = auth::encode_token(&token, key_pair).ok().unwrap();
    let bearer_token = format!("Bearer {jwt}");

    let get_list_with_limit_uri = "/2/footprints?$filter=(pcf/geographyCountry+eq+'FR')+and+(updated+lt+'2023-06-27T12:12:04.000Z')";

    let resp = client
        .get(get_list_with_limit_uri)
        .header(rocket::http::Header::new("Authorization", bearer_token))
        .header(rocket::http::Header::new("Host", EXAMPLE_HOST))
        .dispatch();

    assert_eq!(rocket::http::Status::Ok, resp.status());
    let json: PfListingResponseInner = resp.into_json().unwrap();
    assert_eq!(json.data.len(), 1);
}

#[test]
fn get_list_with_filter_any_test() {
    let client = &Client::tracked(create_server(TEST_KEYPAIR.clone())).unwrap();

    let token = UserToken {
        username: "hello".to_string(),
    };

    let key_pair = client.rocket().state::<KeyPair>().unwrap();

    let jwt = auth::encode_token(&token, key_pair).ok().unwrap();
    let bearer_token = format!("Bearer {jwt}");

    let get_list_with_limit_uri =
        "/2/footprints?$filter=productIds/any(productId:(productId+eq+'urn:gtin:4712345060507'))";

    let resp = client
        .get(get_list_with_limit_uri)
        .header(rocket::http::Header::new(
            "Authorization",
            bearer_token.clone(),
        ))
        .header(rocket::http::Header::new("Host", EXAMPLE_HOST))
        .dispatch();

    assert_eq!(rocket::http::Status::Ok, resp.status());
    let json: PfListingResponseInner = resp.into_json().unwrap();
    assert_eq!(json.data.len(), 1);

    let get_list_with_limit_uri =
        "/2/footprints?$filter=productIds/any(productId:(productId+eq+'urn:gtin:12345'))";

    let resp = client
        .get(get_list_with_limit_uri)
        .header(rocket::http::Header::new("Authorization", bearer_token))
        .header(rocket::http::Header::new("Host", EXAMPLE_HOST))
        .dispatch();

    assert_eq!(rocket::http::Status::Ok, resp.status());
    let json: PfListingResponseInner = resp.into_json().unwrap();
    assert_eq!(json.data.len(), 0);
}

#[test]
fn get_list_with_limit_test() {
    let client = &Client::tracked(create_server(TEST_KEYPAIR.clone())).unwrap();

    let token = UserToken {
        username: "hello".to_string(),
    };

    let key_pair = client.rocket().state::<KeyPair>().unwrap();

    let jwt = auth::encode_token(&token, key_pair).ok().unwrap();
    let bearer_token = format!("Bearer {jwt}");

    let get_list_with_limit_uri = "/2/footprints?limit=3";
    let expected_next_link1 = "/2/footprints?offset=3&limit=3";

    {
        let resp = client
            .get(get_list_with_limit_uri)
            .header(rocket::http::Header::new(
                "Authorization",
                bearer_token.clone(),
            ))
            .header(rocket::http::Header::new("Host", EXAMPLE_HOST))
            .dispatch();

        assert_eq!(rocket::http::Status::Ok, resp.status());
        let link_header = resp.headers().get("link").next().unwrap().to_string();
        assert_eq!(
            link_header,
            format!("<https://api.pathfinder.sine.dev{expected_next_link1}>; rel=\"next\"")
        );
        let json: PfListingResponseInner = resp.into_json().unwrap();
        assert_eq!(json.data.len(), 3);
    }

    {
        let resp = client
            .get(expected_next_link1)
            .header(rocket::http::Header::new("Authorization", bearer_token))
            .header(rocket::http::Header::new("Host", EXAMPLE_HOST))
            .dispatch();

        assert_eq!(rocket::http::Status::Ok, resp.status());
        assert_eq!(resp.headers().get("link").next(), None);
        let json: PfListingResponseInner = resp.into_json().unwrap();
        assert_eq!(json.data.len(), 1);
    }
}

#[test]
fn post_events_test() {
    let client = &Client::tracked(create_server(TEST_KEYPAIR.clone())).unwrap();

    let token = UserToken {
        username: "hello".to_string(),
    };

    let key_pair = client.rocket().state::<KeyPair>().unwrap();

    let jwt = auth::encode_token(&token, key_pair).ok().unwrap();
    let bearer_token = format!("Bearer {jwt}");

    let post_events_uri = "/2/events";

    // test GET request to POST endpoint
    {
        let resp = client
            .get(post_events_uri)
            .header(rocket::http::Header::new(
                "Authorization",
                bearer_token.clone(),
            ))
            .dispatch();
        assert_eq!(rocket::http::Status::BadRequest, resp.status());
    }

    // test unauth request
    {
        let resp = client.post(post_events_uri).dispatch();
        assert_eq!(rocket::http::Status::BadRequest, resp.status());
    }

    // test authenticated request with OK body
    {
        use chrono::prelude::*;
        use uuid::uuid;
        let time = Utc.ymd(2022, 05, 31).and_hms(17, 31, 00);
        let event = PathfinderEvent {
            specversion: "1.0".to_owned(),
            id: "123".to_owned(),
            source: "https://example.com".to_owned(),
            time,
            data: PathfinderEventData::PFUpdateEvent(
                PFUpdateEventBody {
                    pf_ids: vec![
                        PfId(uuid!("52B87062-1506-455C-B521-5212212959A8")),
                        PfId(uuid!("8C5D709E-F3A0-4B90-889D-91BF2A68FA19")),
                    ],
                }
                .into(),
            ),
        };
        let resp = client
            .post(post_events_uri)
            .header(rocket::http::Header::new("Authorization", bearer_token))
            .json(&event)
            .dispatch();
        assert_eq!(rocket::http::Status::Ok, resp.status());
    }
}

#[test]
fn get_pcf_test() {
    let client = &Client::tracked(create_server(TEST_KEYPAIR.clone())).unwrap();

    let token = UserToken {
        username: "hello".to_string(),
    };

    let key_pair = client.rocket().state::<KeyPair>().unwrap();

    let jwt = auth::encode_token(&token, key_pair).ok().unwrap();
    let bearer_token = format!("Bearer {jwt}");

    // test auth
    for pf in PCF_DEMO_DATA.iter() {
        let get_pcf_uri = format!("/2/footprints/{}", pf.id.0);

        let resp = client
            .get(get_pcf_uri.clone())
            .header(rocket::http::Header::new(
                "Authorization",
                bearer_token.clone(),
            ))
            .dispatch();

        assert_eq!(rocket::http::Status::Ok, resp.status());
        assert_eq!(
            ProductFootprintResponse { data: pf.clone() },
            resp.into_json().unwrap()
        );
    }

    // test unuath
    {
        let get_pcf_uri = format!("/2/footprints/{}", PCF_DEMO_DATA[2].id.0);
        let resp = client.get(get_pcf_uri).dispatch();
        assert_eq!(rocket::http::Status::BadRequest, resp.status());
    }

    // test malformed PCF ID
    {
        let get_pcf_uri = "/2/footprints/abc";
        let resp = client
            .get(get_pcf_uri)
            .header(rocket::http::Header::new(
                "Authorization",
                bearer_token.clone(),
            ))
            .dispatch();
        assert_eq!(rocket::http::Status::BadRequest, resp.status());
    }
    // test unknown PCF ID
    {
        let get_pcf_uri = "/2/footprints/16d8e365-698f-4694-bcad-a56e06a45afd";
        let resp = client
            .get(get_pcf_uri)
            .header(rocket::http::Header::new("Authorization", bearer_token))
            .dispatch();
        assert_eq!(rocket::http::Status::BadRequest, resp.status());
    }
}
