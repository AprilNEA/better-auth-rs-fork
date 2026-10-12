use better_auth_core::{AuthError, DatabaseError, DatabaseErrorCause, FieldMap, FieldValue};
use sea_orm::{DbErr, RuntimeErr, SqlErr, sqlx};

pub(crate) fn map_db_err(error: DbErr) -> AuthError {
    let (category, message): (fn(DatabaseErrorCause) -> DatabaseError, String) =
        match error.sql_err() {
            Some(SqlErr::UniqueConstraintViolation(message)) => {
                (DatabaseError::UniqueConstraint, message)
            }
            Some(SqlErr::ForeignKeyConstraintViolation(message)) => {
                (DatabaseError::Constraint, message)
            }
            Some(_) | None => (
                DatabaseError::Query,
                match &error {
                    DbErr::Custom(message) => message.clone(),
                    _ => error.to_string(),
                },
            ),
        };
    let properties = driver_properties(&error);
    category(DatabaseErrorCause::from_source(message, error, properties)).into()
}

fn driver_properties(error: &DbErr) -> Option<FieldMap> {
    let (DbErr::Conn(RuntimeErr::SqlxError(error))
    | DbErr::Exec(RuntimeErr::SqlxError(error))
    | DbErr::Query(RuntimeErr::SqlxError(error))) = error
    else {
        return None;
    };
    let sqlx::Error::Database(error) = error.as_ref() else {
        return None;
    };
    if let Some(error) = error.try_downcast_ref::<sqlx::postgres::PgDatabaseError>() {
        return Some(postgres_properties(error));
    }
    error
        .try_downcast_ref::<sqlx::mysql::MySqlDatabaseError>()
        .map(mysql_properties)
}

fn postgres_properties(error: &sqlx::postgres::PgDatabaseError) -> FieldMap {
    use sqlx::postgres::{PgErrorPosition, PgSeverity};

    let severity = match error.severity() {
        PgSeverity::Panic => "PANIC",
        PgSeverity::Fatal => "FATAL",
        PgSeverity::Error => "ERROR",
        PgSeverity::Warning => "WARNING",
        PgSeverity::Notice => "NOTICE",
        PgSeverity::Debug => "DEBUG",
        PgSeverity::Info => "INFO",
        PgSeverity::Log => "LOG",
    };
    let (position, internal_position, internal_query) = match error.position() {
        Some(PgErrorPosition::Original(position)) => (
            position.to_string().into(),
            FieldValue::Undefined,
            FieldValue::Undefined,
        ),
        Some(PgErrorPosition::Internal { position, query }) => (
            FieldValue::Undefined,
            position.to_string().into(),
            query.into(),
        ),
        None => (
            FieldValue::Undefined,
            FieldValue::Undefined,
            FieldValue::Undefined,
        ),
    };
    // SQLx does not expose the ErrorResponse length or raw localized severity.
    FieldMap::from([
        ("message".into(), error.message().into()),
        ("name".into(), "error".into()),
        ("severity".into(), severity.into()),
        ("code".into(), error.code().into()),
        ("detail".into(), optional_text(error.detail())),
        ("hint".into(), optional_text(error.hint())),
        ("position".into(), position),
        ("internalPosition".into(), internal_position),
        ("internalQuery".into(), internal_query),
        ("where".into(), optional_text(error.r#where())),
        ("schema".into(), optional_text(error.schema())),
        ("table".into(), optional_text(error.table())),
        ("column".into(), optional_text(error.column())),
        ("dataType".into(), optional_text(error.data_type())),
        ("constraint".into(), optional_text(error.constraint())),
        ("file".into(), optional_text(error.file())),
        (
            "line".into(),
            error
                .line()
                .map(|line| line.to_string().into())
                .unwrap_or_default(),
        ),
        ("routine".into(), optional_text(error.routine())),
    ])
}

fn mysql_properties(error: &sqlx::mysql::MySqlDatabaseError) -> FieldMap {
    // SQLx exposes SQLSTATE and errno, but no mysql2 symbolic code or executed SQL text.
    FieldMap::from([
        ("message".into(), error.message().into()),
        ("errno".into(), f64::from(error.number()).into()),
        ("sqlState".into(), optional_text(error.code())),
        ("sqlMessage".into(), error.message().into()),
    ])
}

fn optional_text(value: Option<&str>) -> FieldValue {
    value.map(FieldValue::from).unwrap_or_default()
}

#[cfg(test)]
mod tests;
