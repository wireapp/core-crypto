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

use barrel::{backend::Sqlite, types, Migration};

pub fn migration() -> String {
    let mut m = Migration::new();

    m.create_table("mls_keys", |t| {
        t.add_column("uuid", types::varchar(255).unique(true));
        t.add_column("key", types::binary());
    });

    m.create_table("mls_identities", |t| {
        t.add_column("id", types::varchar(255).unique(true));
        t.add_column("signature", types::binary());
    });

    m.create_table("proteus_prekeys", |t| {
        t.add_column("id", types::integer().unique(true));
        t.add_column("key", types::binary());
    });

    m.make::<Sqlite>()
}
