use certval::{CrlAuthority, CrlCoverage, CrlReasons, CrlScope, CrlType, name_to_string};
use const_oid::db::rfc5912::{
    ID_CE_AUTHORITY_KEY_IDENTIFIER, ID_CE_DELTA_CRL_INDICATOR, ID_CE_ISSUING_DISTRIBUTION_POINT,
};
use x509_cert::{
    crl::CertificateList,
    der::{Decode, Encode},
    ext::pkix::{
        AuthorityKeyIdentifier, IssuingDistributionPoint,
        name::{DistributionPointName, GeneralName},
    },
};

use crate::x509_check::RustyX509CheckError;

flagset::flags! {
    enum CrlQuestions: u8 {
        EeOnly,
        CaOnly,
        AaOnly,
        Delta,
        Partitioned,
        Indirect,
        SomeReasons
    }
}

type CrlQuestionaire = flagset::FlagSet<CrlQuestions>;

#[derive(PartialEq, Eq, Clone)]
pub(crate) struct CrlInfo {
    pub type_info: CrlType,
    pub this_update: u64,
    pub next_update: Option<u64>,
    pub issuer_name: String,
    pub issuer_name_blob: Vec<u8>,
    pub sig_alg_blob: Vec<u8>,
    pub exts_blob: Option<Vec<u8>>,
    pub idp_name: Option<String>,
    pub idp_blob: Option<Vec<u8>>,
    pub skid: Option<Vec<u8>>,
}

impl TryFrom<&CertificateList> for CrlInfo {
    type Error = RustyX509CheckError;

    fn try_from(crl: &CertificateList) -> Result<Self, Self::Error> {
        let this_update = crl.tbs_cert_list.this_update.to_unix_duration().as_secs();
        let next_update = crl.tbs_cert_list.next_update.map(|nu| nu.to_unix_duration().as_secs());
        let issuer_name_blob = crl
            .tbs_cert_list
            .issuer
            .to_der()
            .map_err(|_| certval::Error::Unrecognized)?;
        let issuer_name = name_to_string(&crl.tbs_cert_list.issuer);
        let sig_alg_blob = crl
            .signature_algorithm
            .to_der()
            .map_err(|_| certval::Error::Unrecognized)?;
        let mut exts_blob = None;
        if let Some(crl_exts) = &crl.tbs_cert_list.crl_extensions {
            exts_blob.replace(crl_exts.to_der().map_err(|_| certval::Error::Unrecognized)?);
        }
        let mut idp_blob: Option<Vec<u8>> = None;
        let mut idp_name: Option<String> = None;
        let mut skid: Option<Vec<u8>> = None;

        let mut questionnaire = CrlQuestionaire::default();

        //SKID, delta, idp
        if let Some(exts) = &crl.tbs_cert_list.crl_extensions {
            for ext in exts.iter() {
                match ext.extn_id {
                    ID_CE_ISSUING_DISTRIBUTION_POINT => {
                        idp_blob = Some(ext.extn_value.as_bytes().to_vec());
                        let idp = IssuingDistributionPoint::from_der(ext.extn_value.as_bytes())
                            .map_err(certval::Error::Asn1Error)?;

                        match &idp.distribution_point {
                            Some(DistributionPointName::FullName(gns)) => {
                                for gn in gns {
                                    if let GeneralName::DirectoryName(dn) = gn {
                                        idp_name.replace(name_to_string(dn));
                                        break;
                                    }
                                    if let GeneralName::UniformResourceIdentifier(uri) = gn {
                                        let uri_str = uri.as_str();
                                        idp_name.replace(uri_str.to_string());
                                        break;
                                    }
                                }
                                if idp_name.is_none() {
                                    // not supporting non-DN DPs
                                    return Err(certval::Error::Unrecognized.into());
                                }
                            }
                            Some(DistributionPointName::NameRelativeToCRLIssuer(_unsupported)) => {
                                // Not supporting name relative to issuer
                                return Err(certval::Error::Unrecognized.into());
                            }
                            _ => {}
                        }

                        if idp.distribution_point.is_some() {
                            questionnaire |= CrlQuestions::Partitioned;
                        }

                        if idp.indirect_crl {
                            questionnaire |= CrlQuestions::Indirect;
                        }
                        if idp.only_some_reasons.is_some() {
                            questionnaire |= CrlQuestions::SomeReasons;
                        }
                        if idp.only_contains_user_certs {
                            questionnaire |= CrlQuestions::EeOnly;
                        }
                        if idp.only_contains_ca_certs {
                            questionnaire |= CrlQuestions::CaOnly;
                        }
                        if idp.only_contains_attribute_certs {
                            questionnaire |= CrlQuestions::AaOnly;
                        }
                    } // end ID_CE_ISSUING_DISTRIBUTION_POINT
                    ID_CE_AUTHORITY_KEY_IDENTIFIER => {
                        if let Ok(akid) = AuthorityKeyIdentifier::from_der(ext.extn_value.as_bytes())
                            && let Some(kid) = akid.key_identifier
                        {
                            skid = Some(kid.as_bytes().to_vec());
                        }
                    }
                    ID_CE_DELTA_CRL_INDICATOR => {
                        questionnaire |= CrlQuestions::Delta;
                    }
                    _ => {}
                }
            } //end iterating over extensions
        }

        if questionnaire.contains(CrlQuestions::AaOnly) {
            //XXX-DEFER Do work here to support ACRL, AARL, etc.
            return Err(certval::Error::CrlIncompatible.into());
        }

        let coverage = if questionnaire.contains(CrlQuestions::EeOnly) {
            CrlCoverage::EeOnly
        } else if questionnaire.contains(CrlQuestions::CaOnly) {
            CrlCoverage::CaOnly
        } else {
            CrlCoverage::All
        };

        let authority = if questionnaire.contains(CrlQuestions::Indirect) {
            CrlAuthority::Indirect
        } else {
            CrlAuthority::Direct
        };

        let scope = if questionnaire.contains(CrlQuestions::Partitioned) {
            if questionnaire.contains(CrlQuestions::Delta) {
                CrlScope::DeltaDp
            } else {
                CrlScope::Dp
            }
        } else if questionnaire.contains(CrlQuestions::Delta) {
            CrlScope::Delta
        } else {
            CrlScope::Complete
        };

        //determine reasons
        let reasons = if questionnaire.contains(CrlQuestions::SomeReasons) {
            CrlReasons::SomeReasons
        } else {
            CrlReasons::AllReasons
        };

        let type_info = CrlType {
            scope,
            coverage,
            authority,
            reasons,
        };

        Ok(CrlInfo {
            type_info,
            skid,
            this_update,
            next_update,
            issuer_name,
            issuer_name_blob,
            sig_alg_blob,
            exts_blob,
            idp_name,
            idp_blob,
        })
    }
}
