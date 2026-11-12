use certval::{ExtensionProcessing, PDVCertificate, PDVExtension};
use const_oid::db::rfc5912::ID_CE_CRL_DISTRIBUTION_POINTS;
use x509_cert::der::Encode;

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
