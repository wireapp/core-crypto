CREATE TABLE e2ei_acme_ca (
    id INTEGER PRIMARY KEY CHECK ( id = 0 ),
    content BLOB
);

CREATE TABLE e2ei_intermediate_certs (
    ski_aki_pair TEXT UNIQUE,
    content BLOB
);

CREATE TABLE e2ei_crls (
    distribution_point TEXT UNIQUE,
    content BLOB
);
