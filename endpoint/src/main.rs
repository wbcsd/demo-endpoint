/*
 * Copyright (c) Martin Pompéry
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the crate's root directory of this source tree.
 */
#[macro_use]
extern crate lazy_static;
//mod api_types;
mod auth;
//mod datamodel;
//mod error;
//mod sample_data;

use std::cmp::min;

use auth::UserToken;
use either::Either;
/*use rocket::catch;
use rocket::form::Form;
use rocket::request::FromRequest;
use rocket::serde::json::Json;
use rocket_okapi::rapidoc::{
    make_rapidoc, GeneralConfig, HideShowConfig, RapiDocConfig, Theme, UiConfig,
};
use rocket_okapi::settings::{OpenApiSettings, UrlObject};
use rocket_okapi::swagger_ui::{make_swagger_ui, SwaggerUIConfig};
use rocket_okapi::{get_openapi_route, openapi, openapi_get_routes_spec};*/

//use api_types::*;
//use datamodel::PfId;
//use error::AccessDenied;
//use sample_data::PCF_DEMO_DATA;
//use Either::Left;

/*#[cfg(test)]
use rocket::local::blocking::Client;*/

// minimum number of results to return from Action `ListFootprints`
const ACTION_LIST_FOOTPRINTS_MIN_RESULTS: usize = 10;

const EXAMPLE_HOST: &str = "api.example.com";

/// endpoint to create an oauth2 client credentials grant (RFC 6749 4.4)
/*#[post("/token", data = "<body>")]
fn oauth2_create_token(
    req: auth::OAuth2ClientCredentials,
    body: Form<auth::OAuth2ClientCredentialsBody<'_>>,
) -> Either<Json<auth::OAuth2TokenReply>, error::AccessDenied> {
    if req.id == "hello" && req.secret == "pathfinder" {
        let access_token = auth::encode_token(&auth::UserToken { username: req.id }).unwrap();

        let reply = auth::OAuth2TokenReply {
            access_token,
            token_type: auth::OAuth2TokenType::Bearer,
            scope: body.scope.map(String::from),
        };
        Either::Left(Json(reply))
    } else {
        Either::Right(Default::default())
    }
}*/

/*#[derive(Debug)]
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

#[get("/2/footprints?<limit>&<offset>", format = "json")]
fn get_list(
    auth: Option<UserToken>,
    limit: usize,
    offset: usize,
    host: Host,
) -> Either<PfListingResponse, error::AccessDenied> {
    if auth.is_none() {
        return Either::Right(Default::default());
    }

    if offset >= PCF_DEMO_DATA.len() {
        return Either::Right(Default::default());
    }

    let data = &PCF_DEMO_DATA;
    let max_limit = data.len() - offset;
    let limit = min(limit, max_limit);

    let next_offset = offset + limit;
    let footprints = Json(PfListingResponseInner {
        data: data[offset..offset + limit].to_vec(),
    });

    if next_offset < data.len() {
        let host = host
            .0
            .map(|host| format!("https://{host}"))
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
#[get("/2/footprints?<limit>&<filter>", format = "json", rank = 2)]
fn get_footprints(
    auth: Option<UserToken>,
    limit: Option<usize>,
    filter: Option<FilterString>,
) -> Either<PfListingResponse, error::AccessDenied> {
    // ignore that filter is not implemented as we cannot rename the function parameter
    // as this would propagate through to the OpenAPI document
    let _filter_is_ignored = filter;
    let limit = limit.unwrap_or(ACTION_LIST_FOOTPRINTS_MIN_RESULTS);
    let offset = 0;

    get_list(auth, limit, offset, Host(Some(EXAMPLE_HOST)))
}

#[openapi]
#[get("/2/footprints/<id>", format = "json", rank = 1)]
fn get_pcf(
    id: PfId,
    auth: Option<UserToken>,
) -> Either<Json<ProductFootprintResponse>, error::AccessDenied> {
    if auth.is_some() {
        PCF_DEMO_DATA
            .iter()
            .find(|pf| pf.id == id)
            .map(|pcf| Left(Json(ProductFootprintResponse { data: pcf.clone() })))
            .unwrap_or_else(|| Either::Right(Default::default()))
    } else {
        Either::Right(Default::default())
    }
}

#[get("/2/footprints/<_id>", format = "json", rank = 2)]
fn get_pcf_unauth(_id: &str) -> error::AccessDenied {
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
    EventsApiResponse::NoAuth(error::AccessDenied::default())
}

#[catch(400)]
fn bad_request() -> error::BadRequest {
    Default::default()
}

#[catch(default)]
fn default_handler() -> error::AccessDenied {
    Default::default()
}*/

const OPENAPI_PATH: &str = "../openapi.json";

/*fn create_server() -> rocket::Rocket<rocket::Build> {
    let settings = OpenApiSettings::default();
    let (mut openapi_routes, openapi_spec) =
        openapi_get_routes_spec![settings: get_pcf, get_footprints, post_event];

    openapi_routes.push(get_openapi_route(openapi_spec, &settings));

    rocket::build()
        .mount("/", openapi_routes)
        .mount("/", routes![get_list, get_pcf_unauth, post_event_fallback])
        .mount("/2/auth", routes![oauth2_create_token])
        .mount(
            "/swagger-ui/",
            make_swagger_ui(&SwaggerUIConfig {
                url: OPENAPI_PATH.to_owned(),
                ..Default::default()
            }),
        )
        .mount(
            "/rapidoc/",
            make_rapidoc(&RapiDocConfig {
                general: GeneralConfig {
                    spec_urls: vec![UrlObject::new("General", OPENAPI_PATH)],
                    ..Default::default()
                },
                ui: UiConfig {
                    theme: Theme::Dark,
                    ..Default::default()
                },
                hide_show: HideShowConfig {
                    allow_spec_url_load: false,
                    allow_spec_file_load: false,
                    ..Default::default()
                },
                ..Default::default()
            }),
        )
        .register("/", catchers![bad_request, default_handler])
}*/

/*#[rocket::main]
async fn main() -> Result<(), LambdaError> {
    let rocket = create_server();
    if is_running_on_lambda() {
        // Launch on AWS Lambda
        launch_rocket_on_lambda(rocket).await?;
    } else {
        // Launch local server
        let _ = rocket.launch().await?;
    }
    Ok(())
}*/

use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use lambda_web::{is_running_on_lambda, run_hyper_on_lambda, LambdaError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Serialize, Deserialize, JsonSchema, PartialEq, Debug)]
/// Response with an error code of `AccessDenied`. See Chapter "Error Codes" of the Tech Specs for mor details.
pub(crate) struct AccessDenied {
    pub(crate) message: &'static str,
    pub(crate) code: &'static str,
}

impl Default for AccessDenied {
    fn default() -> Self {
        Self {
            message: "Access Denied",
            code: "AccessDenied",
        }
    }
}

async fn oauth2_create_token(
    auth: auth::OAuth2ClientCredentials,
    body: auth::OAuth2ClientCredentialsBody,
) -> Response {
    if auth.id == "hello" && auth.secret == "pathfinder" {
        let access_token = auth::encode_token(&auth::UserToken { username: auth.id }).unwrap();

        let reply = auth::OAuth2TokenReply {
            access_token,
            token_type: auth::OAuth2TokenType::Bearer,
            scope: body.scope.map(String::from),
        };
        (StatusCode::OK, Json(reply)).into_response()
    } else {
        (StatusCode::FORBIDDEN, Json(AccessDenied::default())).into_response()
    }
}

#[tokio::main]
async fn main() -> Result<(), LambdaError> {
    // build our application with a route
    let app = Router::new().route("/token", post(oauth2_create_token));

    if is_running_on_lambda() {
        // Run app on AWS Lambda
        run_hyper_on_lambda(app).await?;
    } else {
        // Run app on local server
        let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
        axum::Server::bind(&addr)
            .serve(app.into_make_service())
            .await?;
    }
    Ok(())
}

/*#[test]
fn get_list_test() {
    let token = UserToken {
        username: "hello".to_string(),
    };
    let jwt = auth::encode_token(&token).ok().unwrap();
    let bearer_token = format!("Bearer {jwt}");
    let client = &Client::tracked(create_server()).unwrap();

    let get_list_uri = "/2/footprints";

    // test auth
    {
        let resp = client
            .get(get_list_uri.clone())
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
        assert_eq!(rocket::http::Status::Forbidden, resp.status());
    }
}

#[test]
fn get_list_with_limit_test() {
    let token = UserToken {
        username: "hello".to_string(),
    };
    let jwt = auth::encode_token(&token).ok().unwrap();
    let bearer_token = format!("Bearer {jwt}");
    let client = &Client::tracked(create_server()).unwrap();

    let get_list_with_limit_uri = "/2/footprints?limit=3";
    let expected_next_link1 = "/2/footprints?offset=3&limit=3";
    let expected_next_link2 = "/2/footprints?offset=6&limit=3";

    {
        let resp = client
            .get(get_list_with_limit_uri.clone())
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
            format!("<https://api.example.com{expected_next_link1}>; rel=\"next\"")
        );
        let json: PfListingResponseInner = resp.into_json().unwrap();
        assert_eq!(json.data.len(), 3);
    }

    {
        let resp = client
            .get(expected_next_link1)
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
            format!("<https://api.example.com{expected_next_link2}>; rel=\"next\"")
        );
        let json: PfListingResponseInner = resp.into_json().unwrap();
        assert_eq!(json.data.len(), 3);
    }

    {
        let resp = client
            .get(expected_next_link2)
            .header(rocket::http::Header::new("Authorization", bearer_token))
            .header(rocket::http::Header::new("Host", EXAMPLE_HOST))
            .dispatch();

        assert_eq!(rocket::http::Status::Ok, resp.status());
        assert_eq!(resp.headers().get("link").next(), None);
        let json: PfListingResponseInner = resp.into_json().unwrap();
        assert_eq!(json.data.len(), 2);
    }
}

#[test]
fn post_events_test() {
    let token = UserToken {
        username: "hello".to_string(),
    };
    let jwt = auth::encode_token(&token).ok().unwrap();
    let bearer_token = format!("Bearer {jwt}");
    let client = &Client::tracked(create_server()).unwrap();

    let post_events_uri = "/2/events";

    // test GET request to POST endpoint
    {
        let resp = client
            .get(post_events_uri.clone())
            .header(rocket::http::Header::new(
                "Authorization",
                bearer_token.clone(),
            ))
            .dispatch();
        assert_eq!(rocket::http::Status::Forbidden, resp.status());
    }

    // test unauth request
    {
        let resp = client.post(post_events_uri.clone()).dispatch();
        assert_eq!(rocket::http::Status::Forbidden, resp.status());
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
            .post(post_events_uri.clone())
            .header(rocket::http::Header::new("Authorization", bearer_token))
            .json(&event)
            .dispatch();
        assert_eq!(rocket::http::Status::Ok, resp.status());
    }
}

#[test]
fn get_pcf_test() {
    let token = UserToken {
        username: "hello".to_string(),
    };
    let jwt = auth::encode_token(&token).ok().unwrap();
    let bearer_token = format!("Bearer {jwt}");
    let client = &Client::tracked(create_server()).unwrap();

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
        assert_eq!(rocket::http::Status::Forbidden, resp.status());
    }

    // test malformed PCF ID
    {
        let get_pcf_uri = "/2/footprints/abc";
        let resp = client
            .get(get_pcf_uri.clone())
            .header(rocket::http::Header::new(
                "Authorization",
                bearer_token.clone(),
            ))
            .dispatch();
        assert_eq!(rocket::http::Status::Forbidden, resp.status());
    }
    // test unknown PCF ID
    {
        let get_pcf_uri = "/2/footprints/16d8e365-698f-4694-bcad-a56e06a45afd";
        let resp = client
            .get(get_pcf_uri.clone())
            .header(rocket::http::Header::new("Authorization", bearer_token))
            .dispatch();
        assert_eq!(rocket::http::Status::Forbidden, resp.status());
    }
}*/
