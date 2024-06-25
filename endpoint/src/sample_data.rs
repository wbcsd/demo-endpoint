/*
 * Copyright (c) Martin Pompéry
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the crate's root directory of this source tree.
 */
use chrono::prelude::*;
use pact_data_model::*;
use rust_decimal_macros::dec;
use uuid::uuid;

lazy_static!(
    static ref EXAMPLE_1: ProductFootprint = ProductFootprint {
        id: PfId(uuid!("91715e5e-fd0b-4d1c-8fab-76290c46e6ed")),
        spec_version: SpecVersionString::from("2.0.0".to_string()),
        preceding_pf_ids: None,
        version: VersionInteger(1),
        created: Utc.with_ymd_and_hms(2022, 3, 1, 9, 32, 20).unwrap(),
        updated: None,
        status: PfStatus::Active,
        status_comment: None,
        validity_period_start: Some(Utc.with_ymd_and_hms(2022, 3, 1, 9, 32, 20).unwrap()),
        validity_period_end: Some(Utc.with_ymd_and_hms(2024, 12, 31, 00, 00, 00).unwrap()),
        company_name: String::from("My Corp").into(),
        company_ids: CompanyIdSet(vec![Urn::from("urn:uuid:69585GB6-56T9-6958-E526-6FDGZJHU1326".to_string()), Urn::from("urn:epc:id:sgln:562958.00000.4".to_string())]),
        product_description: "Bio-Ethanol 98%, corn feedstock (bulk - no packaging)".to_string(),
        product_ids: ProductIdSet(vec![Urn::from("urn:gtin:5695872369587".to_string())]),
        product_category_cpc: String::from("6398").into(),
        product_name_company: String::from("Green Ethanol").into(),
        comment: "".into(),
        pcf: CarbonFootprint {
            declared_unit: DeclaredUnit::Liter,
            unitary_product_amount: dec!(1).into(),
            p_cf_excluding_biogenic: dec!(1.63).into(),
            p_cf_including_biogenic: Some(dec!(1.85).into()),
            fossil_ghg_emissions: dec!(1.5).into(),
            fossil_carbon_content: dec!(0).into(),
            biogenic_carbon_content: dec!(0.41).into(),
            d_luc_ghg_emissions: Some(dec!(0.8).into()),
            land_management_ghg_emissions: Some(dec!(0.6).into()),
            other_biogenic_ghg_emissions: Some(dec!(0.4).into()),
            i_luc_ghg_emissions: Some(dec!(0).into()),
            biogenic_carbon_withdrawal: Some(dec!(-1.5).into()),
            aircraft_ghg_emissions: Some(dec!(0.2).into()),
            characterization_factors: CharacterizationFactors::Ar6,
            ipcc_characterization_factors_sources: IpccCharacterizationFactorsSources::from(vec![String::from("AR6").into()]),
            cross_sectoral_standards_used: CrossSectoralStandardSet(vec![CrossSectoralStandard::Ghgp, CrossSectoralStandard::ISO14067]),
            product_or_sector_specific_rules: ProductOrSectorSpecificRuleSet(vec![
                ProductOrSectorSpecificRule {
                    operator: ProductOrSectorSpecificRuleOperator::Other,
                    rule_names: vec![String::from("The Product Carbon Footprint Guideline for the Chemical Industry, v.2.0").into()].into(),
                    other_operator_name: Some(String::from("Tfs").into())
                }]),
            biogenic_accounting_methodology: Some(BiogenicAccountingMethodology::Ghpg),
            boundary_processes_description: String::from("1) Material acquisition and preprocessing, including growth of corn 2) Production: fuel consumption, electricity consumption, water consumption, process-generated direct emissions 3) Distribution and storage: transportation of the finished product from manufacturing site to storage site"),
            reference_period_start: Utc.with_ymd_and_hms(2021, 1, 1, 00, 00, 00).unwrap(),
            reference_period_end: Utc.with_ymd_and_hms(2022, 1, 1, 00, 00, 00).unwrap(),
            geographic_scope: Some(GeographicScope::Regional { geography_region_or_subregion: UNRegionOrSubregion::WesternEurope }),
            secondary_emission_factor_sources: Some(EmissionFactorDSSet(vec![EmissionFactorDS {
                name: String::from("Ecoinvent").into(),
                version: String::from("3.1").into(),
            }])),
            exempted_emissions_percent: ExemptedEmissionsPercent(0.0),
            exempted_emissions_description: "".to_string(),
            packaging_emissions_included: false,
            packaging_ghg_emissions: None,
            allocation_rules_description: Some("Using mass allocation following the product specific rule as per PACT Framework decision-making tree".to_string()),
            uncertainty_assessment_description: Some("A model of corn production is involved in predicting emissions from the production of the corn feedstock. Emissions of N2O due to application of nitrogen fertilizers are based on a linear modeling of interactions of the fertilizer with the soil and plant systems. As these interactions are more complicated than the model assumes, there is uncertainty regarding the emissions resulting from this model".to_string()),
            primary_data_share: Some(Percent::from(12.9)),
            dqi: Some(DataQualityIndicators {
                coverage_percent: Percent::from(78.0),
                technological_d_q_r: 1.6.into(),
                temporal_d_q_r: 2.6.into(),
                geographical_d_q_r: 1.8.into(),
                completeness_d_q_r: 1.7.into(),
                reliability_d_q_r: 2.1.into()
            }),
            assurance: Some(Assurance::default()),
        },
        extensions: None
    };
    static ref EXAMPLE_2: ProductFootprint = ProductFootprint {
        id: PfId(uuid!("61ff98c0-9e13-47d9-bb13-0b5381468165")),
        spec_version: SpecVersionString::from("2.0.0".to_string()),
        preceding_pf_ids: None,
        version: VersionInteger(1),
        created: Utc.with_ymd_and_hms(2022, 2, 22, 10, 47, 32).unwrap(),
        updated: None,
        status: PfStatus::Active,
        status_comment: None,
        validity_period_start: Some(Utc.with_ymd_and_hms(2022, 2, 22, 10, 47, 32).unwrap()),
        validity_period_end: Some(Utc.with_ymd_and_hms(2024, 12, 31, 00, 00, 00).unwrap()),
        company_name: String::from("My Corp").into(),
        company_ids: CompanyIdSet(vec![Urn::from("urn:uuid:51131FB5-42A2-4267-A402-0ECFEFAD1619".to_string()), Urn::from("urn:epc:id:sgln:4063973.00000.8".to_string())]),
        product_description: "12L Bottle of bio-Ethanol 98%, corn feedstock (including 100% fossil plastic packaging)".to_string(),
        product_ids: ProductIdSet(vec![Urn::from("urn:gtin:4712345060507".to_string())]),
        product_category_cpc: String::from("3342").into(),
        product_name_company: String::from("Green Ethanol").into(),
        comment: "".into(),
        pcf: CarbonFootprint {
            declared_unit: DeclaredUnit::Liter,
            unitary_product_amount: dec!(12).into(),
            p_cf_excluding_biogenic: dec!(1.75).into(),
            p_cf_including_biogenic: Some(dec!(1.97).into()),
            fossil_ghg_emissions: dec!(1.5).into(),
            fossil_carbon_content: dec!(0).into(),
            biogenic_carbon_content: dec!(0.41).into(),
            d_luc_ghg_emissions: Some(dec!(0.8).into()),
            land_management_ghg_emissions: Some(dec!(0.6).into()),
            other_biogenic_ghg_emissions: Some(dec!(0.4).into()),
            i_luc_ghg_emissions: Some(dec!(0).into()),
            biogenic_carbon_withdrawal: Some(dec!(-1.5).into()),
            aircraft_ghg_emissions: Some(dec!(0.2).into()),
            characterization_factors: CharacterizationFactors::Ar6,
            ipcc_characterization_factors_sources: IpccCharacterizationFactorsSources::from(vec![String::from("AR6").into()]),
            cross_sectoral_standards_used: CrossSectoralStandardSet(vec![CrossSectoralStandard::Ghgp, CrossSectoralStandard::ISO14067]),
            product_or_sector_specific_rules: ProductOrSectorSpecificRuleSet(vec![
                ProductOrSectorSpecificRule {
                    operator: ProductOrSectorSpecificRuleOperator::Other,
                    rule_names: vec![String::from("The Product Carbon Footprint Guideline for the Chemical Industry, v.2.0").into()].into(),
                    other_operator_name: Some(String::from("Tfs").into())
                }]),
            biogenic_accounting_methodology: Some(BiogenicAccountingMethodology::Ghpg),
            boundary_processes_description: String::from("1) Material acquisition and preprocessing, including growth of corn 2) Production: fuel consumption, electricity consumption, water consumption, process-generated direct emissions 3) Distribution and storage: transportation of the finished product from manufacturing site to storage site"),
            reference_period_start: Utc.with_ymd_and_hms(2021, 1, 1, 00, 00, 00).unwrap(),
            reference_period_end: Utc.with_ymd_and_hms(2022, 1, 1, 00, 00, 00).unwrap(),
            geographic_scope: Some(GeographicScope::Country { geography_country: ISO3166CC(String::from("DE")) }),
            secondary_emission_factor_sources: Some(EmissionFactorDSSet(vec![EmissionFactorDS {
                name: String::from("Ecoinvent").into(),
                version: String::from("3.1").into(),
            }])),
            exempted_emissions_percent: ExemptedEmissionsPercent(0.8),
            exempted_emissions_description: "Using the most conservative emission factor from a region with higher energy intensive grid for input A resulted in a contribution of 0.8% for this input. This is less than 1% and therefore considered under the cut off rule".to_string(),
            packaging_emissions_included: true,
            packaging_ghg_emissions: Some(dec!(0.12).into()),
            allocation_rules_description: Some("Using mass allocation following the product specific rule as per PACT Framework decision-making tree".to_string()),
            uncertainty_assessment_description: None,
            primary_data_share: Some(Percent::from(16.8)),
            dqi: Some(DataQualityIndicators {
                coverage_percent: Percent::from(87.0),
                technological_d_q_r: 2.3.into(),
                temporal_d_q_r: 1.4.into(),
                geographical_d_q_r: 2.5.into(),
                completeness_d_q_r: 1.1.into(),
                reliability_d_q_r: 1.6.into()
            }),
            assurance: Some(Assurance::default()),
        },
        extensions: None
    };

    // a footprint deprecated by EXAMPLE_4
    static ref EXAMPLE_3: ProductFootprint = ProductFootprint {
        id: PfId(uuid!("fb77319f-2338-4338-868a-98b2206340ad")),
        spec_version: SpecVersionString::from("2.0.0".to_string()),
        preceding_pf_ids: None,
        version: VersionInteger(2),
        created: Utc.with_ymd_and_hms(2022, 3, 15, 11, 47, 32).unwrap(),
        updated: Some(Utc.with_ymd_and_hms(2023, 6, 27, 12, 12, 3).unwrap()),
        status: PfStatus::Deprecated,
        status_comment: Some("Replaced by a new version".to_string()),
        validity_period_start: Some(Utc.with_ymd_and_hms(2022, 3, 15, 11, 47, 32).unwrap()),
        validity_period_end: Some(Utc.with_ymd_and_hms(2023, 6, 27, 12, 12, 3).unwrap()),
        company_name: String::from("My Corp").into(),
        company_ids: CompanyIdSet(vec![Urn::from("urn:uuid:25639HN5-58Q6-1238-S596-9STHZHZJ5623".to_string()), Urn::from("urn:epc:id:sgln:6957976.00000.1".to_string())]),
        product_description: "Cardboard box 50x40x40 cm".to_string(),
        product_ids: ProductIdSet(vec![Urn::from("urn:gtin:5268596541023".to_string())]),
        product_category_cpc: String::from("4365").into(),
        product_name_company: String::from("Cardboard504040").into(),
        comment: "".into(),
        pcf: CarbonFootprint {
            declared_unit: DeclaredUnit::Kilogram,
            unitary_product_amount: dec!(0.8).into(),
            p_cf_excluding_biogenic: dec!(0.28).into(),
            p_cf_including_biogenic: Some(dec!(-0.28).into()),
            fossil_ghg_emissions: dec!(0.19).into(),
            fossil_carbon_content: dec!(0.08).into(),
            biogenic_carbon_content: dec!(0.44).into(),
            d_luc_ghg_emissions: Some(dec!(0.42).into()),
            land_management_ghg_emissions: Some(dec!(0.34).into()),
            other_biogenic_ghg_emissions: Some(dec!(0.2).into()),
            i_luc_ghg_emissions: Some(dec!(0.03).into()),
            biogenic_carbon_withdrawal: Some(dec!(-1.6).into()),
            aircraft_ghg_emissions: Some(dec!(0.08).into()),
            characterization_factors: CharacterizationFactors::Ar5,
            ipcc_characterization_factors_sources: IpccCharacterizationFactorsSources::from(vec![String::from("AR5").into(), String::from("AR6").into()]),
            cross_sectoral_standards_used: CrossSectoralStandardSet(vec![CrossSectoralStandard::Ghgp]),
            product_or_sector_specific_rules: ProductOrSectorSpecificRuleSet(vec![
                ProductOrSectorSpecificRule {
                    operator: ProductOrSectorSpecificRuleOperator::EPDInternational,
                    rule_names: vec![String::from("PCR cardboard").into()].into(),
                    other_operator_name: None
                }
            ]),
            biogenic_accounting_methodology: Some(BiogenicAccountingMethodology::Pef),
            boundary_processes_description: String::from("1) Material acquisition and preprocessing, including growth of trees 2) Production: fuel consumption, electricity consumption, water consumption, process-generated direct emissions 3) Distribution and storage: transportation of the finished product from manufacturing site to storage site"),
            reference_period_start: Utc.with_ymd_and_hms(2021, 1, 1, 00, 00, 00).unwrap(),
            reference_period_end: Utc.with_ymd_and_hms(2022, 1, 1, 00, 00, 00).unwrap(),
            geographic_scope: Some(GeographicScope::Country { geography_country: ISO3166CC("FR".into()) }),
            secondary_emission_factor_sources: Some(EmissionFactorDSSet(vec![EmissionFactorDS {
                name: String::from("Gabi").into(),
                version: String::from("2022").into(),
            }])),
            exempted_emissions_percent: ExemptedEmissionsPercent(0.0),
            exempted_emissions_description: "".to_string(),
            packaging_emissions_included: false,
            packaging_ghg_emissions: None,
            allocation_rules_description: Some("No allocation used, process subdivision was possible".to_string()),
            uncertainty_assessment_description: None,
            primary_data_share: Some(Percent::from(12.6)),
            dqi: Some(DataQualityIndicators {
                coverage_percent: Percent::from(83.0),
                technological_d_q_r: 1.8.into(),
                temporal_d_q_r: 1.2.into(),
                geographical_d_q_r: 1.9.into(),
                completeness_d_q_r: 1.7.into(),
                reliability_d_q_r: 1.4.into()
            }),
            assurance: Some(Assurance {
                assurance: true,
                coverage: Some(AssuranceCoverage::PcfSystem),
                level: Some(AssuranceLevel::Limited),
                boundary: Some(AssuranceBoundary::CradleToGate),
                provider_name: "My Auditor".to_string(),
                completed_at: Some(Utc.with_ymd_and_hms(2022, 12, 15, 00, 00, 00).unwrap()),
                standard_name: Some("ISO 14044".to_string()),
                comments: None
            }),
        },
        extensions: None
    };

    // this is the PCF superseeding EXAMPLE_3
    static ref EXAMPLE_4: ProductFootprint = ProductFootprint {
        id: PfId(uuid!("f369091a-aa5d-4248-9bd5-2812329e1ef1")),
        spec_version: SpecVersionString::from("2.0.0".to_string()),
        preceding_pf_ids: Some(NonEmptyPfIdVec(vec![PfId(uuid!("fb77319f-2338-4338-868a-98b2206340ad"))])),
        version: VersionInteger(1),
        created: Utc.with_ymd_and_hms(2023, 6, 27, 12, 12, 3).unwrap(),
        updated: None,
        status: PfStatus::Active,
        status_comment: None,
        validity_period_start: Some(Utc.with_ymd_and_hms(2023, 2, 1, 00, 00, 00).unwrap()),
        validity_period_end: Some(Utc.with_ymd_and_hms(2025, 8, 31, 00, 00, 00).unwrap()),
        company_name: String::from("My Corp").into(),
        company_ids: CompanyIdSet(vec![Urn::from("urn:uuid:25639HN5-58Q6-1238-S596-9STHZHZJ5623".to_string()), Urn::from("urn:epc:id:sgln:6957976.00000.1".to_string())]),
        product_description: "Cardboard box 50x40x40 cm".to_string(),
        product_ids: ProductIdSet(vec![Urn::from("urn:gtin:5268596541023".to_string())]),
        product_category_cpc: String::from("4365").into(),
        product_name_company: String::from("Cardboard504040").into(),
        comment: "".into(),
        pcf: CarbonFootprint {
            declared_unit: DeclaredUnit::Kilogram,
            unitary_product_amount: dec!(0.8).into(),
            p_cf_excluding_biogenic: dec!(0.32).into(),
            p_cf_including_biogenic: Some(dec!(-0.28).into()),
            fossil_ghg_emissions: dec!(0.23).into(),
            fossil_carbon_content: dec!(0.08).into(),
            biogenic_carbon_content: dec!(0.44).into(),
            d_luc_ghg_emissions: Some(dec!(0.42).into()),
            land_management_ghg_emissions: Some(dec!(0.34).into()),
            other_biogenic_ghg_emissions: Some(dec!(0.2).into()),
            i_luc_ghg_emissions: Some(dec!(0.03).into()),
            biogenic_carbon_withdrawal: Some(dec!(-1.6).into()),
            aircraft_ghg_emissions: Some(dec!(0.08).into()),
            characterization_factors: CharacterizationFactors::Ar5,
            ipcc_characterization_factors_sources: IpccCharacterizationFactorsSources::from(vec![String::from("AR5").into(), String::from("AR6").into()]),
            cross_sectoral_standards_used: CrossSectoralStandardSet(vec![CrossSectoralStandard::Ghgp]),
            product_or_sector_specific_rules: ProductOrSectorSpecificRuleSet(vec![
                ProductOrSectorSpecificRule {
                    operator: ProductOrSectorSpecificRuleOperator::EPDInternational,
                    rule_names: vec![String::from("PCR cardboard").into()].into(),
                    other_operator_name: None
                }
            ]),
            biogenic_accounting_methodology: Some(BiogenicAccountingMethodology::Pef),
            boundary_processes_description: String::from("1) Material acquisition and preprocessing, including growth of trees 2) Production: fuel consumption, electricity consumption, water consumption, process-generated direct emissions 3) Distribution and storage: transportation of the finished product from manufacturing site to storage site"),
            reference_period_start: Utc.with_ymd_and_hms(2021, 1, 1, 00, 00, 00).unwrap(),
            reference_period_end: Utc.with_ymd_and_hms(2022, 1, 1, 00, 00, 00).unwrap(),
            geographic_scope: Some(GeographicScope::Subdivision { geography_country_subdivision: String::from("FR-89").into() }),
            secondary_emission_factor_sources: Some(EmissionFactorDSSet(vec![EmissionFactorDS {
                name: String::from("Gabi").into(),
                version: String::from("2022").into(),
            }])),
            exempted_emissions_percent: ExemptedEmissionsPercent(0.0),
            exempted_emissions_description: "".to_string(),
            packaging_emissions_included: false,
            packaging_ghg_emissions: None,
            allocation_rules_description: Some("No allocation used, process subdivision was possible".to_string()),
            uncertainty_assessment_description: None,
            primary_data_share: Some(Percent::from(12.6)),
            dqi: Some(DataQualityIndicators {
                coverage_percent: Percent::from(83.0),
                technological_d_q_r: 1.8.into(),
                temporal_d_q_r: 1.2.into(),
                geographical_d_q_r: 1.9.into(),
                completeness_d_q_r: 1.7.into(),
                reliability_d_q_r: 1.4.into()
            }),
            assurance: Some(Assurance {
                assurance: true,
                coverage: Some(AssuranceCoverage::PcfSystem),
                level: Some(AssuranceLevel::Limited),
                boundary: Some(AssuranceBoundary::CradleToGate),
                provider_name: "My Auditor".to_string(),
                completed_at: Some(Utc.with_ymd_and_hms(2022, 12, 15, 00, 00, 00).unwrap()),
                standard_name: Some("ISO 14044".to_string()),
                comments: None
            }),
        },
        extensions: None
    };
);

lazy_static! {
    pub(crate) static ref PCF_DEMO_DATA: Vec<ProductFootprint> = vec![
        EXAMPLE_1.clone(),
        EXAMPLE_2.clone(),
        EXAMPLE_3.clone(),
        EXAMPLE_4.clone(),
    ];
}
