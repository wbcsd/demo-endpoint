/*
 * Copyright (c) Martin Pompéry
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the crate's root directory of this source tree.
 */
//! Use Case 001 REST API-related type definitions
use crate::datamodel::ProductFootprint;
use rocket::serde::{Deserialize, Serialize};
use schemars::JsonSchema;

#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema, PartialEq)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
/// HTTP Body of Action `GetFootprint`
pub(crate) struct ProductFootprintResponse {
    pub(crate) data: ProductFootprint,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
/// HTTP Body of Action `ListFootprints`
pub(crate) struct PCFListingResponse {
    pub(crate) data: Vec<ProductFootprint>,
}
