use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use certval::{
    CrlInfo, CrlScope, CrlSource, ExtensionProcessing, PDVCertificate, PDVExtension, get_crl_info, name_to_string,
};
use const_oid::db::rfc5912::ID_CE_AUTHORITY_KEY_IDENTIFIER;
use x509_cert::{certificate::Raw, crl::CertificateList, der::Encode};

use super::misc::get_dps_from_cert;

type IssuerMap = BTreeMap<String, Vec<usize>>;
type SkidMap = BTreeMap<Vec<u8>, Vec<usize>>;
type DpMap = BTreeMap<Vec<u8>, Vec<usize>>;

pub(super) struct CrlStore {
    crls: Arc<Mutex<Vec<CertificateList<Raw>>>>,
    crl_info: Arc<Mutex<Vec<CrlInfo>>>,
    issuers: Arc<Mutex<IssuerMap>>,
    sk_ids: Arc<Mutex<SkidMap>>,
    dps: Arc<Mutex<DpMap>>,
}

impl From<&[CertificateList<Raw>]> for CrlStore {
    fn from(value: &[CertificateList<Raw>]) -> Self {
        Self {
            crls: Mutex::new(value.to_vec()).into(),
            crl_info: Default::default(),
            issuers: Default::default(),
            sk_ids: Default::default(),
            dps: Default::default(),
        }
    }
}

impl CrlStore {
    /// Update maps that are used when searching for CRLs matching a given certificate.
    fn populate_maps(&self, index: usize, info: &CrlInfo) {
        if let Some(dp) = info.idp_blob.clone() {
            self.dps
                .lock()
                .expect("not poisoned")
                .entry(dp)
                .or_default()
                .push(index);
        } else {
            if let Some(akid) = info.skid.clone() {
                self.sk_ids
                    .lock()
                    .expect("not poisoned")
                    .entry(akid)
                    .or_default()
                    .push(index);
            }

            if info.type_info.scope == CrlScope::Complete {
                self.issuers
                    .lock()
                    .expect("not poisoned")
                    .entry(info.issuer_name.clone())
                    .or_default()
                    .push(index);
            }
        }
    }
}

impl CrlSource for CrlStore {
    fn get_all_crls(&self) -> certval::Result<Vec<Vec<u8>>> {
        let crls = self.crls.lock().map_err(|_| certval::Error::Unrecognized)?;
        crls.iter().try_fold(Vec::with_capacity(crls.len()), |mut acc, crl| {
            acc.push(crl.to_der()?);
            Ok(acc)
        })
    }

    fn get_crls(&self, cert: &PDVCertificate) -> certval::Result<Vec<Vec<u8>>> {
        let crls = self.crls.lock().map_err(|_| certval::Error::Unrecognized)?;
        // DistributionPoint matching
        if let Some(dps) = get_dps_from_cert(cert) {
            let source_dps = self.dps.lock().map_err(|_| certval::Error::Unrecognized)?;
            for dp in dps {
                if let Some(indices) = source_dps.get(&dp) {
                    let mut retval = vec![];
                    for index in indices {
                        if let Some(crl) = crls.get(*index) {
                            retval.push(crl.to_der()?);
                        }
                    }
                    return Ok(retval);
                }
            }
        }

        // AKI matching
        if let Ok(Some(PDVExtension::AuthorityKeyIdentifier(akid))) =
            cert.get_extension(&ID_CE_AUTHORITY_KEY_IDENTIFIER)
            && let Some(kid) = &akid.key_identifier
        {
            let skids = self.sk_ids.lock().map_err(|_| certval::Error::Unrecognized)?;
            let kid_bytes = kid.as_bytes();
            if let Some(indices) = skids.get(kid_bytes) {
                let mut retval = vec![];
                for index in indices {
                    if let Some(crl) = crls.get(*index) {
                        retval.push(crl.to_der()?);
                    }
                }
                return Ok(retval);
            }
        }

        // Issuer fallback
        let issuer_name = name_to_string(cert.decoded().tbs_certificate().issuer());
        let issuers = self.issuers.lock().map_err(|_| certval::Error::Unrecognized)?;
        if let Some(indices) = issuers.get(&issuer_name) {
            let mut retval = vec![];
            for index in indices {
                if let Some(crl) = crls.get(*index) {
                    retval.push(crl.to_der()?);
                }
            }
            return Ok(retval);
        }

        Err(certval::Error::NotFound)
    }

    fn add_crl(&self, _: &[u8], crl: &CertificateList<Raw>, _: &str) -> certval::Result<()> {
        let info = get_crl_info(crl)?;

        let mut crls = self.crls.lock().expect("not poisoned");
        let mut crl_infos = self.crl_info.lock().expect("not poisoned");

        // see if we already have a matching CRL
        let pos = crl_infos
            .iter()
            .position(|ci| ci.type_info == info.type_info && ci.idp_name == info.idp_name && ci.uri == info.uri);

        match pos {
            Some(idx) => {
                // update the existing CRL and CRL info, but only if the new CRL is actually newer
                if info.this_update < crl_infos[idx].this_update {
                    return Err(certval::Error::Unrecognized);
                }
                crls[idx] = crl.clone();
                crl_infos[idx] = info;
                return Ok(());
            }
            None => {
                crls.push(crl.clone());
                crl_infos.push(info.clone());
                self.populate_maps(crls.len() - 1, &info);
            }
        };

        Ok(())
    }
}
