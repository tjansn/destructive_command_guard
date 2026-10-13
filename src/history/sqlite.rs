//! Small compatibility surface around `rusqlite` for history queries.
//!
//! The history schema predates the upstream SQLite backend and intentionally
//! consumes dynamically typed rows. Keeping that narrow shape here avoids
//! spreading statement/row lifetime plumbing through the analytics code while
//! retaining SQLite's native parameter binding.

use rusqlite::types::Value;
use rusqlite::{Error, params_from_iter};
use std::path::Path;

/// Dynamically typed SQLite value used by history queries.
pub type SqliteValue = Value;

/// Owned query row.
#[derive(Debug, Clone)]
pub struct Row {
    values: Vec<SqliteValue>,
}

impl Row {
    /// Return the row's values in column order.
    #[must_use]
    pub fn values(&self) -> &[SqliteValue] {
        &self.values
    }
}

/// History database connection.
///
/// Query rows are materialized into owned values so callers do not need to
/// carry prepared-statement lifetimes through the history analytics API.
pub struct Connection {
    inner: rusqlite::Connection,
}

impl Connection {
    /// Open a file-backed or in-memory SQLite database.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        rusqlite::Connection::open(path).map(|inner| Self { inner })
    }

    /// Whether standalone inserts can commit independently of an earlier
    /// transaction. A failed SQL statement does not necessarily restore this.
    #[must_use]
    pub(crate) fn is_autocommit(&self) -> bool {
        self.inner.is_autocommit()
    }

    /// Execute one or more SQL statements without bind parameters.
    pub fn execute(&self, sql: &str) -> Result<(), Error> {
        self.inner.execute_batch(sql)
    }

    /// Execute one statement with positional bind parameters.
    pub fn execute_with_params(&self, sql: &str, params: &[SqliteValue]) -> Result<usize, Error> {
        self.inner.execute(sql, params_from_iter(params))
    }

    /// Query all rows and materialize their dynamically typed values.
    pub fn query(&self, sql: &str) -> Result<Vec<Row>, Error> {
        self.query_with_params(sql, &[])
    }

    /// Query all rows with positional bind parameters.
    pub fn query_with_params(&self, sql: &str, params: &[SqliteValue]) -> Result<Vec<Row>, Error> {
        let mut statement = self.inner.prepare(sql)?;
        let column_count = statement.column_count();
        let mut rows = statement.query(params_from_iter(params))?;
        let mut output = Vec::new();
        while let Some(row) = rows.next()? {
            output.push(materialize_row(row, column_count)?);
        }
        Ok(output)
    }

    /// Query exactly the first row.
    pub fn query_row(&self, sql: &str) -> Result<Row, Error> {
        let mut statement = self.inner.prepare(sql)?;
        let column_count = statement.column_count();
        statement.query_row([], |row| materialize_row(row, column_count))
    }

    /// Query exactly the first row with positional bind parameters.
    pub fn query_row_with_params(&self, sql: &str, params: &[SqliteValue]) -> Result<Row, Error> {
        let mut statement = self.inner.prepare(sql)?;
        let column_count = statement.column_count();
        statement.query_row(params_from_iter(params), |row| {
            materialize_row(row, column_count)
        })
    }

    /// Return the rowid from the most recent successful insert.
    #[must_use]
    pub fn last_insert_rowid(&self) -> i64 {
        self.inner.last_insert_rowid()
    }
}

fn materialize_row(row: &rusqlite::Row<'_>, column_count: usize) -> Result<Row, Error> {
    let values = (0..column_count)
        .map(|index| row.get::<_, SqliteValue>(index))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Row { values })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autocommit_state_distinguishes_statement_failure_from_rollback() {
        let connection = Connection::open(":memory:").unwrap();
        assert!(connection.is_autocommit());
        connection
            .execute(
                "CREATE TABLE transaction_probe(value TEXT UNIQUE);
                 BEGIN IMMEDIATE;
                 INSERT INTO transaction_probe VALUES ('first');",
            )
            .unwrap();
        assert!(!connection.is_autocommit());
        assert!(
            connection
                .execute("INSERT INTO transaction_probe VALUES ('first');")
                .is_err()
        );
        assert!(
            !connection.is_autocommit(),
            "a constraint error alone does not roll back the transaction"
        );
        connection.execute("ROLLBACK;").unwrap();
        assert!(connection.is_autocommit());
        let row = connection
            .query_row("SELECT COUNT(*) FROM transaction_probe")
            .unwrap();
        assert_eq!(row.values(), &[SqliteValue::Integer(0)]);
    }

    #[test]
    fn query_rows_are_owned_and_parameter_binding_is_native() {
        let connection = Connection::open(":memory:").unwrap();
        connection
            .execute("CREATE TABLE values_table(value TEXT, count INTEGER);")
            .unwrap();
        connection
            .execute_with_params(
                "INSERT INTO values_table(value, count) VALUES (?1, ?2)",
                &[
                    SqliteValue::Text("literal ?2 and ' quote".to_string()),
                    SqliteValue::Integer(7),
                ],
            )
            .unwrap();

        let row = connection
            .query_row_with_params(
                "SELECT value, count FROM values_table WHERE count = ?1",
                &[SqliteValue::Integer(7)],
            )
            .unwrap();
        assert_eq!(
            row.values(),
            &[
                SqliteValue::Text("literal ?2 and ' quote".to_string()),
                SqliteValue::Integer(7),
            ]
        );
    }
}
