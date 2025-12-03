use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use certval::{PDVCertificate, PathValidationStatus, RevocationStatusCache, buffer_to_hex, name_to_string};

#[derive(Clone, Copy, Debug)]
struct StatusAndTime {
    status: PathValidationStatus, // Valid or Revoked
    valid_until: u64,
}

type CacheMap = BTreeMap<(String, String), StatusAndTime>;

#[derive(Default)]
pub(crate) struct RevocationCache {
    cache_map: Arc<Mutex<CacheMap>>,
}

fn get_name_serial_pair(cert: &PDVCertificate) -> (String, String) {
    let name = name_to_string(&cert.decoded_cert.tbs_certificate.issuer);
    let serial = buffer_to_hex(cert.decoded_cert.tbs_certificate.serial_number.as_bytes());
    (name, serial)
}

impl RevocationStatusCache for RevocationCache {
    fn get_status(&self, cert: &PDVCertificate, time_of_interest: u64) -> PathValidationStatus {
        let Ok(cache_map) = self.cache_map.lock() else {
            return PathValidationStatus::RevocationStatusNotDetermined;
        };

        if let Some(status_and_time) = cache_map.get(&get_name_serial_pair(cert))
            && status_and_time.valid_until > time_of_interest
        {
            return status_and_time.status;
        }

        PathValidationStatus::RevocationStatusNotDetermined
    }

    fn add_status(&self, cert: &PDVCertificate, next_update: u64, mut status: PathValidationStatus) {
        let is_status_relevant = matches!(
            status,
            PathValidationStatus::Valid
                | PathValidationStatus::CertificateRevoked
                | PathValidationStatus::CertificateRevokedEndEntity
                | PathValidationStatus::CertificateRevokedIntermediateCa
                | PathValidationStatus::NoPathsFound
        );

        if !is_status_relevant {
            return;
        }

        if status != PathValidationStatus::Valid {
            status = PathValidationStatus::CertificateRevoked;
        }

        let Ok(mut cache_map) = self.cache_map.lock() else {
            return;
        };

        let status_and_time = StatusAndTime {
            status,
            valid_until: next_update,
        };

        cache_map
            .entry(get_name_serial_pair(cert))
            .and_modify(|old_status_and_time| {
                if old_status_and_time.valid_until < next_update {
                    *old_status_and_time = status_and_time;
                }
            })
            .or_insert_with(|| status_and_time);
    }
}
