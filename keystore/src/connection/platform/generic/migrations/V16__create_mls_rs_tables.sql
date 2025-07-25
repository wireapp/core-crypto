CREATE TABLE key_package_data (
    id TEXT UNIQUE,
    data BLOB
);

CREATE TABLE psks (
    id BLOB PRIMARY KEY,
    data BLOB NOT NULL
);

CREATE TABLE groups (
    id BLOB PRIMARY KEY,
    snapshot BLOB NOT NULL
);

CREATE TABLE epochs (
    group_id BLOB,
    epoch_id INTEGER,
    epoch_data BLOB NOT NULL,
    FOREIGN KEY (group_id) REFERENCES groups (id) ON DELETE CASCADE
    PRIMARY KEY (group_id, epoch_id)
) WITHOUT ROWID;
