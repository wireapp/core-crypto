CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE clients (
    id BIGSERIAL PRIMARY KEY NOT NULL,
    uuid UUID NOT NULL DEFAULT uuid_generate_v4(),
    identity UUID NOT NULL,
    display_name VARCHAR(64) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT current_timestamp,
    updated_at TIMESTAMP NOT NULL,

    CONSTRAINT c_identity_unique UNIQUE(identity),
    CONSTRAINT c_uuid_unique UNIQUE(uuid)
);

CREATE TABLE client_keypackages (
    id BIGSERIAL PRIMARY KEY NOT NULL,
    uuid UUID NOT NULL DEFAULT uuid_generate_v4(),
    hash BYTEA NOT NULL,
    kp_tls_payload BYTEA NOT NULL,
    client_id BIGSERIAL NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT current_timestamp,
    updated_at TIMESTAMP NOT NULL,

    CONSTRAINT ckp_uuid_unique UNIQUE(uuid),
    CONSTRAINT ckp_hash_unique UNIQUE(hash),
    CONSTRAINT ckp_fk_client FOREIGN KEY(client_id) REFERENCES clients(id)
);

CREATE TABLE conversations (
    id BIGSERIAL PRIMARY KEY NOT NULL,
    uuid UUID NOT NULL DEFAULT uuid_generate_v4(),
    title VARCHAR(255),
    description TEXT,
    author_id BIGSERIAL NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT current_timestamp,
    updated_at TIMESTAMP NOT NULL,

    CONSTRAINT cnv_uuid_unique UNIQUE(uuid),
    CONSTRAINT cnv_fk_author FOREIGN KEY(author_id) REFERENCES clients(id)
);

CREATE TABLE conversation_members (
    conversation_id BIGSERIAL NOT NULL,
    client_id BIGSERIAL NOT NULL,
    is_admin BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT current_timestamp,
    updated_at TIMESTAMP NOT NULL,

    CONSTRAINT cnvm_fk_client FOREIGN KEY(client_id) REFERENCES clients(id),
    CONSTRAINT cnvm_fk_conversation FOREIGN KEY(conversation_id) REFERENCES conversations(id),
    CONSTRAINT cnvm_pk PRIMARY KEY(conversation_id, client_id)
);
