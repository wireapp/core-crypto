ALTER TABLE mls_keypackages
RENAME TO mls_key_packages;

ALTER TABLE mls_key_packages
RENAME COLUMN keypackage_ref TO key_package_ref;

ALTER TABLE mls_key_packages
RENAME COLUMN keypackage TO key_package;
