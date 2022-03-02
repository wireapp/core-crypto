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

#[derive(Debug, thiserror::Error)]
pub enum DsError {
    #[error(transparent)]
    AddrParseError(#[from] std::net::AddrParseError),

    #[error(transparent)]
    DbError(#[from] sea_orm::DbErr),

    #[error(transparent)]
    IoError(#[from] std::io::Error),

    #[error(transparent)]
    ActixError(#[from] actix_web::Error),

    #[error(transparent)]
    HexError(#[from] hex::FromHexError),

    #[error(transparent)]
    RedisError(#[from] redis::RedisError),

    #[error(transparent)]
    UuidError(#[from] uuid::Error),

    #[error(transparent)]
    Other(#[from] color_eyre::Report),
}

impl actix_web::ResponseError for DsError {}

pub type DsResult<T> = Result<T, DsError>;
