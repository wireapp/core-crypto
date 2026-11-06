use rusqlite::{
    ToSql,
    types::{FromSql, FromSqlResult, ToSqlOutput, Value, ValueRef},
};

/// What this item in the inbox is waiting for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum WaitingFor {
    /// This message arrived for a pending group which has not yet been merged
    PendingJoin = 1,
    /// This message arrived before the epoch for which it is intended.
    Epoch = 2,
    /// This message (always a commit) arrived before the proposal it references.
    Proposal = 3,
}

impl ToSql for WaitingFor {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::Owned(Value::Integer(*self as u8 as _)))
    }
}

impl FromSql for WaitingFor {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        let value = i64::column_result(value)?;
        match value {
            1 => Ok(Self::PendingJoin),
            2 => Ok(Self::Epoch),
            3 => Ok(Self::Proposal),
            _ => Err(rusqlite::types::FromSqlError::OutOfRange(value)),
        }
    }
}
