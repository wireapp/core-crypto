use certval::{ExtensionProcessing, PDVCertificate, PDVExtension, TimeOfInterest};
use const_oid::db::rfc5912::{ID_CE_CRL_DISTRIBUTION_POINTS, ID_CE_ISSUING_DISTRIBUTION_POINT};
use x509_cert::{
    certificate::Raw,
    crl::CertificateList,
    der::{Decode, Encode},
    ext::pkix::IssuingDistributionPoint,
};

pub(crate) fn check_crl_valid_at_toi(toi: TimeOfInterest, crl: &CertificateList<Raw>) -> bool {
    let toi = toi.as_unix_secs();
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
