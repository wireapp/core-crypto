use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, MutexGuard},
};

use certval::{CrlScope, CrlSource, ExtensionProcessing, PDVCertificate, PDVExtension, name_to_string};
use const_oid::db::rfc5912::ID_CE_AUTHORITY_KEY_IDENTIFIER;
use x509_cert::{crl::CertificateList, der::Encode};

use crate::acme::x509_check::{
    RustyX509CheckError, RustyX509CheckResult,
    revocation::{
        crl_info::CrlInfo,
        misc::{check_crl_valid_at_toi, get_dp_from_crl, get_dps_from_cert},
    },
};

type IssuerMap = BTreeMap<String, Vec<usize>>;
type SkidMap = BTreeMap<Vec<u8>, Vec<usize>>;
type DpMap = BTreeMap<Vec<u8>, Vec<usize>>;

pub(crate) struct CrlStore {
    crls: Arc<Mutex<Vec<x509_cert::crl::CertificateList>>>,
    crl_info: Arc<Mutex<Vec<CrlInfo>>>,
    issuers: Arc<Mutex<IssuerMap>>,
    sk_ids: Arc<Mutex<SkidMap>>,
    dps: Arc<Mutex<DpMap>>,
}

impl From<&[CertificateList]> for CrlStore {
    fn from(value: &[CertificateList]) -> Self {
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
    fn add_crl_info_with_guard(
        &self,
        crl: &CertificateList,
        info: CrlInfo,
        crl_info: &mut MutexGuard<Vec<CrlInfo>>,
    ) -> RustyX509CheckResult<()> {
        if crl_info.contains(&info) {
            return Ok(());
        }

        let mut is_dp = false;
        crl_info.push(info);
        let index = crl_info.len() - 1;

        // SAFETY: This unwrap is safe as we just inserted the data above
        let info = crl_info.last().unwrap();
        if let Some(dp) = get_dp_from_crl(crl) {
            self.dps
                .lock()
                .map_err(|_| RustyX509CheckError::LockPoisonError)?
                .entry(dp)
                .or_default()
                .push(index);
            is_dp = true;
        } else if let Some(akid) = info.skid.clone() {
            self.sk_ids
                .lock()
                .map_err(|_| RustyX509CheckError::LockPoisonError)?
                .entry(akid)
                .or_default()
                .push(index);
        }

        if !is_dp && info.type_info.scope == CrlScope::Complete {
            let issuer_name = name_to_string(&crl.tbs_cert_list.issuer);
            self.issuers
                .lock()
                .map_err(|_| RustyX509CheckError::LockPoisonError)?
                .entry(issuer_name)
                .or_default()
                .push(index);
        }

        Ok(())
    }

    #[inline]
    fn add_crl_info(&self, crl: &CertificateList, info: CrlInfo) -> RustyX509CheckResult<()> {
        self.add_crl_info_with_guard(
            crl,
            info,
            &mut self.crl_info.lock().map_err(|_| RustyX509CheckError::LockPoisonError)?,
        )
    }

    pub(crate) fn index_crls(&self, time_of_interest: u64) -> RustyX509CheckResult<()> {
        let crls = self.crls.lock().map_err(|_| RustyX509CheckError::LockPoisonError)?;
        let mut crl_info = self.crl_info.lock().map_err(|_| RustyX509CheckError::LockPoisonError)?;
        for crl in crls.iter() {
            match CrlInfo::try_from(crl) {
                Ok(info) if check_crl_valid_at_toi(time_of_interest, crl) => {
                    self.add_crl_info_with_guard(crl, info, &mut crl_info)?;
                }
                _ => continue,
            }
        }

        Ok(())
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
        let issuer_name = name_to_string(&cert.decoded_cert.tbs_certificate.issuer);
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

    fn add_crl(&self, _: &[u8], crl: &CertificateList, _: &str) -> certval::Result<()> {
        self.crls
            .lock()
            .map_err(|_| certval::Error::Unrecognized)?
            .push(crl.clone());

        if let Ok(info) = CrlInfo::try_from(crl) {
            self.add_crl_info(crl, info).map_err(|_| certval::Error::Unrecognized)?;
        }

        Ok(())
    }
}
