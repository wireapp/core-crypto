-- Add migration script here
CREATE TABLE clients (
    id BIGSERIAL PRIMARY KEY NOT NULL,
    uuid UUID NOT NULL,
    identity BYTEA,
    display_name VARCHAR(64) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT current_timestamp,
    updated_at TIMESTAMP NOT NULL DEFAULT 0,

    CONSTRAINT identity_unique UNIQUE(identity),
    CONSTRAINT uuid_unique UNIQUE(uuid)
);

CREATE TABLE client_keypackages (
    id BIGSERIAL PRIMARY KEY NOT NULL,
    uuid UUID NOT NULL DEFAULT uuid_generate_v4(),
    hash BYTEA NOT NULL,
    kp_tls_payload BYTEA NOT NULL,
    client_id BIGSERIAL NOT NULL,

    CONSTRAINT uuid_unique UNIQUE(uuid),
    CONSTRAINT hash_unique UNIQUE(hash),
    CONSTRAINT fk_client FOREIGN KEY(client_id) REFERENCES clients(id)
);

CREATE TABLE conversations (
    id BIGSERIAL PRIMARY KEY NOT NULL,
    uuid UUID NOT NULL DEFAULT uuid_generate_v4(),

    author_id BIGSERIAL NOT NULL,


)
