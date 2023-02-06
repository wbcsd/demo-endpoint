/*
 * Copyright (c) Martin Pompéry
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the crate's root directory of this source tree.
 */
//! Use Case 001 REST API-related type definitions
use crate::datamodel::ProductFootprint;
use rocket::serde::json::Json;
use rocket::{
    http::Header,
    serde::{Deserialize, Serialize},
};
use rocket_okapi::response::OpenApiResponderInner;
use schemars::JsonSchema;

#[derive(FromForm)]
pub(crate) struct FilterString<'r> {
    _filter: &'r str,
}

#[derive(Debug, Responder)]
pub(crate) enum PfListingResponse {
    Finished(Json<PfListingResponseInner>),
    Cont(Json<PfListingResponseInner>, Header<'static>),
}

#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema, PartialEq)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
/// HTTP Body of Action `GetFootprint`
pub(crate) struct ProductFootprintResponse {
    pub(crate) data: ProductFootprint,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
/// HTTP Body of Action `ListFootprints`
pub(crate) struct PfListingResponseInner {
    pub(crate) data: Vec<ProductFootprint>,
}

fn openapi_link_header() -> okapi::openapi3::Header {
    okapi::openapi3::Header {
        description: Some(
            "Link header to next result set. See Tech Specs section 6.6.1".to_owned(),
        ),
        value: okapi::openapi3::ParameterValue::Schema {
            style: None,
            explode: None,
            allow_reserved: false,
            example: Some(
                "https://api.example.com/2/footprints?[...]"
                    .to_owned()
                    .into(),
            ),
            examples: None,
            schema: okapi::openapi3::SchemaObject {
                instance_type: Some(schemars::schema::InstanceType::String.into()),
                ..Default::default()
            },
        },
        required: false,
        deprecated: false,
        allow_empty_value: false,
        extensions: Default::default(),
    }
}

impl<'r> schemars::JsonSchema for FilterString<'r> {
    fn schema_name() -> String {
        "FilterString".to_owned()
    }

    fn json_schema(_: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        let mut schema = schemars::schema::SchemaObject::default();
        schema.instance_type = Some(schemars::schema::InstanceType::String.into());
        schema.string = Some(
            schemars::schema::StringValidation {
                min_length: Some(1),
                ..Default::default()
            }
            .into(),
        );
        schema.metadata = Some(
            schemars::schema::Metadata {
                description: Some(
                    "OData V4 conforming filter string. See Action ListFootprints's Request Syntax chapter".to_owned(),
                ),
                ..Default::default()
            }
            .into(),
        );
        schema.into()
    }
}

impl OpenApiResponderInner for PfListingResponse {
    fn responses(
        gen: &mut rocket_okapi::gen::OpenApiGenerator,
    ) -> rocket_okapi::Result<okapi::openapi3::Responses> {
        use okapi::openapi3::RefOr;

        let mut responses: okapi::openapi3::Responses =
            <Json<PfListingResponseInner>>::responses(gen)?;

        match &mut responses.responses["200"] {
            RefOr::Object(response) => {
                let header = openapi_link_header();
                let header = RefOr::Object(header);
                response.headers.insert("link".to_owned(), header);
            }
            _ => {
                panic!("expected object");
            }
        }

        Ok(responses)
    }
}
