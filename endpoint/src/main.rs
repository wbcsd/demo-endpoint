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
mod datamodel;
mod error;
mod sample_data;

use std::cmp::min;

use auth::UserToken;
use either::Either;
use lambda_web::{is_running_on_lambda, launch_rocket_on_lambda, LambdaError};
use rocket::catch;
use rocket::form::Form;
use rocket::http::Header;
use rocket::serde::json::Json;
use rocket_okapi::rapidoc::{
    make_rapidoc, GeneralConfig, HideShowConfig, RapiDocConfig, Theme, UiConfig,
};
use rocket_okapi::response::OpenApiResponderInner;
use rocket_okapi::settings::{OpenApiSettings, UrlObject};
use rocket_okapi::swagger_ui::{make_swagger_ui, SwaggerUIConfig};
use rocket_okapi::{get_openapi_route, openapi, openapi_get_routes_spec};

use api_types::{PCFListingResponse, ProductFootprintResponse};
use datamodel::PfId;
use sample_data::PCF_DEMO_DATA;
use Either::Left;

#[cfg(test)]
use rocket::local::blocking::Client;

/// endpoint to create an oauth2 client credentials grant (RFC 6749 4.4)
#[post("/token", data = "<body>")]
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
}

#[derive(Debug)]
struct PCFListingResponseWithNextLink {
    json: Json<PCFListingResponse>,
    link: Option<String>,
}

impl<'r, 'o: 'r> rocket::response::Responder<'r, 'o> for PCFListingResponseWithNextLink {
    fn respond_to(self, r: &'r rocket::Request<'_>) -> rocket::response::Result<'o> {
        let mut build = rocket::response::Response::build_from(self.json.respond_to(r).unwrap());
        if let Some(link) = self.link {
            build.merge(
                rocket::Response::build()
                    .header(Header::new("link", link))
                    .finalize(),
            );
        }
        build
            .status(rocket::http::Status::Ok)
            .header(rocket::http::ContentType::JSON)
            .ok()
    }
}

impl OpenApiResponderInner for PCFListingResponseWithNextLink {
    fn responses(
        gen: &mut rocket_okapi::gen::OpenApiGenerator,
    ) -> rocket_okapi::Result<okapi::openapi3::Responses> {
        <Json<PCFListingResponse>>::responses(gen)
    }
}

#[openapi]
#[get("/0/footprints?<limit>&<offset>", format = "json")]
fn get_list(
    auth: Option<UserToken>,
    limit: Option<usize>,
    offset: Option<usize>,
) -> Either<PCFListingResponseWithNextLink, error::AccessDenied> {
    if auth.is_some() {
        let data = PCF_DEMO_DATA.to_vec();
        let offset = offset.unwrap_or_default();
        let max_limit = data.len() - offset;
        let limit = min(limit.unwrap_or(max_limit), max_limit);
        if offset < data.len() {
            let next_offset = offset + limit;
            let link = if next_offset < data.len() {
                Some(format!("<https://api.example.com/0/footprints?offset={next_offset}&limit={limit}>; rel=\"next\""))
            } else {
                None
            };
            let json = Json(PCFListingResponse {
                data: data[offset..offset + limit].to_vec(),
            });
            Left(PCFListingResponseWithNextLink { json, link })
        } else {
            Either::Right(Default::default())
        }
    } else {
        Either::Right(Default::default())
    }
}

#[openapi]
#[get("/0/footprints/<id>", format = "json", rank = 1)]
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

#[get("/0/footprints/<_id>", format = "json", rank = 2)]
fn get_pcf_unauth(_id: &str) -> error::AccessDenied {
    Default::default()
}

#[catch(400)]
fn bad_request() -> error::BadRequest {
    Default::default()
}

#[catch(default)]
fn default_handler() -> error::AccessDenied {
    Default::default()
}

const OPENAPI_PATH: &str = "../openapi.json";

fn create_server() -> rocket::Rocket<rocket::Build> {
    let settings = OpenApiSettings::default();
    let (mut openapi_routes, openapi_spec) = openapi_get_routes_spec![settings: get_pcf, get_list];

    openapi_routes.push(get_openapi_route(openapi_spec, &settings));

    rocket::build()
        .mount("/", openapi_routes)
        .mount("/", routes![get_pcf_unauth])
        .mount("/0/auth", routes![oauth2_create_token])
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
}

#[rocket::main]
async fn main() -> Result<(), LambdaError> {
    let rocket = create_server();
    if is_running_on_lambda() {
        // Launch on AWS Lambda
        launch_rocket_on_lambda(rocket).await?;
    } else {
        // Launch local server
        rocket.launch().await?;
    }
    Ok(())
}

#[test]
fn get_list_test() {
    let token = UserToken {
        username: "hello".to_string(),
    };
    let jwt = auth::encode_token(&token).ok().unwrap();
    let bearer_token = format!("Bearer {jwt}");
    let client = &Client::tracked(create_server()).unwrap();

    let get_list_uri = "/0/footprints";

    // test auth
    {
        let resp = client
            .get(get_list_uri.clone())
            .header(rocket::http::Header::new("Authorization", bearer_token))
            .dispatch();

        assert_eq!(rocket::http::Status::Ok, resp.status());
        assert_eq!(
            PCFListingResponse {
                data: PCF_DEMO_DATA.to_vec()
            },
            resp.into_json().unwrap()
        );
    }

    // test unauth
    {
        let resp = client.get(get_list_uri).dispatch();
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

    let get_list_with_limit_uri = "/0/footprints?limit=3";
    let expected_next_link1 = "/0/footprints?offset=3&limit=3";
    let expected_next_link2 = "/0/footprints?offset=6&limit=3";

    {
        let resp = client
            .get(get_list_with_limit_uri.clone())
            .header(rocket::http::Header::new(
                "Authorization",
                bearer_token.clone(),
            ))
            .dispatch();

        assert_eq!(rocket::http::Status::Ok, resp.status());
        let link_header = resp.headers().get("link").next().unwrap().to_string();
        assert_eq!(
            link_header,
            format!("<https://api.example.com{expected_next_link1}>; rel=\"next\"")
        );
        let json: PCFListingResponse = resp.into_json().unwrap();
        assert_eq!(json.data.len(), 3);
    }

    {
        let resp = client
            .get(expected_next_link1)
            .header(rocket::http::Header::new(
                "Authorization",
                bearer_token.clone(),
            ))
            .dispatch();

        assert_eq!(rocket::http::Status::Ok, resp.status());
        let link_header = resp.headers().get("link").next().unwrap().to_string();
        assert_eq!(
            link_header,
            format!("<https://api.example.com{expected_next_link2}>; rel=\"next\"")
        );
        let json: PCFListingResponse = resp.into_json().unwrap();
        assert_eq!(json.data.len(), 3);
    }

    {
        let resp = client
            .get(expected_next_link2)
            .header(rocket::http::Header::new("Authorization", bearer_token))
            .dispatch();

        assert_eq!(rocket::http::Status::Ok, resp.status());
        assert_eq!(resp.headers().get("link").next(), None);
        let json: PCFListingResponse = resp.into_json().unwrap();
        assert_eq!(json.data.len(), 2);
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
        let get_pcf_uri = format!("/0/footprints/{}", pf.id.0);

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
        let get_pcf_uri = format!("/0/footprints/{}", PCF_DEMO_DATA[2].id.0);
        let resp = client.get(get_pcf_uri).dispatch();
        assert_eq!(rocket::http::Status::Forbidden, resp.status());
    }

    // test malformed PCF ID
    {
        let get_pcf_uri = "/0/footprints/abc";
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
        let get_pcf_uri = "/0/footprints/16d8e365-698f-4694-bcad-a56e06a45afd";
        let resp = client
            .get(get_pcf_uri.clone())
            .header(rocket::http::Header::new("Authorization", bearer_token))
            .dispatch();
        assert_eq!(rocket::http::Status::Forbidden, resp.status());
    }
}
