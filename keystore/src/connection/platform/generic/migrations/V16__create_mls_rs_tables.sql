CREATE TABLE key_package_data (
    id TEXT UNIQUE,
    data BLOB
);

CREATE TABLE psks (
    id BLOB PRIMARY KEY,
    data BLOB NOT NULL
);
