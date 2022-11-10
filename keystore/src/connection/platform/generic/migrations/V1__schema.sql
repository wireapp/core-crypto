/*
// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.
*/

CREATE TABLE mls_keys (
    id VARCHAR(255) UNIQUE,
    key BLOB
);

CREATE TABLE mls_identities (
    id VARCHAR(255) UNIQUE,
    signature BLOB,
    credential BLOB
);

CREATE TABLE mls_groups (
    id BLOB,
    state BLOB
);

CREATE TABLE proteus_prekeys (
    id INT UNIQUE,
    key BLOB
);

CREATE TABLE mls_pending_groups (
    id BLOB,
    state BLOB,
    cfg BLOB
);
