use certval::{ExtensionProcessing, PDVCertificate, PDVExtension};
use const_oid::db::rfc5912::{ID_CE_CRL_DISTRIBUTION_POINTS, ID_CE_ISSUING_DISTRIBUTION_POINT};
use x509_cert::{
    crl::CertificateList,
    der::{Decode, Encode},
    ext::pkix::IssuingDistributionPoint,
};

pub(crate) fn check_crl_valid_at_toi(toi: u64, crl: &CertificateList) -> bool {
    if toi == 0 {
        return false;
    }

    if crl.tbs_cert_list.this_update.to_unix_duration().as_secs() > toi {
        return false;
    }

    if let Some(nu) = crl.tbs_cert_list.next_update
        && nu.to_unix_duration().as_secs() < toi
    {
        return false;
    }

    true
}

pub(crate) fn get_dp_from_crl(crl: &CertificateList) -> Option<Vec<u8>> {
    if let Some(exts) = &crl.tbs_cert_list.crl_extensions {
        for ext in exts {
            if ext.extn_id == ID_CE_ISSUING_DISTRIBUTION_POINT
                && let Some(enc_dp) = IssuingDistributionPoint::from_der(ext.extn_value.as_bytes())
                    .ok()
                    .and_then(|idp| idp.distribution_point)
                    .and_then(|dp| dp.to_der().ok())
            {
                return Some(enc_dp);
            }
        }
    }
    None
}

pub(crate) fn get_dps_from_cert(cert: &PDVCertificate) -> Option<Vec<Vec<u8>>> {
    match cert.get_extension(&ID_CE_CRL_DISTRIBUTION_POINTS) {
        Ok(Some(PDVExtension::CrlDistributionPoints(crl_dps))) => Some(
            crl_dps
                .0
                .iter()
                .filter_map(|crl_dp| crl_dp.distribution_point.as_ref().and_then(|dp| dp.to_der().ok()))
                .collect::<Vec<_>>(),
        ),
        _ => None,
    }
}
