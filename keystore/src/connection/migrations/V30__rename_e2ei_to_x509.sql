CREATE TABLE x509_intermediate_certs (
    ski_aki_pair TEXT PRIMARY KEY NOT NULL,
    content BLOB NOT NULL
);

INSERT INTO x509_intermediate_certs (ski_aki_pair, content)
SELECT ski_aki_pair, content
FROM e2ei_intermediate_certs;

DROP TABLE e2ei_intermediate_certs;


CREATE TABLE x509_crls (
    distribution_point TEXT PRIMARY KEY NOT NULL,
    content BLOB NOT NULL
);

INSERT INTO x509_crls (distribution_point, content)
SELECT distribution_point, content
FROM e2ei_crls;

DROP TABLE e2ei_crls;
