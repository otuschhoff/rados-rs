//! Read-only inventory validation for R13 v1 scope.
//!
//! Confirms that:
//! * The frozen native inventory (`reference/go/docs/p00/api-inventory.csv`)
//!   has exactly 623 data rows.
//! * The current parity ledger (`docs/r00/parity-ledger.csv`) has exactly
//!   905 data rows, and every row's status is on the allow-list.
//!
//! No row is repaired or normalised. The check exists to detect drift
//! between what the qualification report claims and what the ledger says.

use std::fs;
use std::path::Path;

use crate::constants::{
    LEDGER_ALLOWED_STATUSES, NATIVE_INVENTORY_PATH, NATIVE_INVENTORY_ROWS, PARITY_LEDGER_PATH,
    PARITY_LEDGER_ROWS,
};

/// Structured inventory summary. Included on qualification reports so the
/// verifier can confirm the count without re-walking the CSVs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventorySummary {
    pub native_rows: usize,
    pub ledger_rows: usize,
}

/// Read-only check.
///
/// # Errors
///
/// Returns an explanation when either CSV cannot be read, has an unexpected
/// row count, or contains a status outside the allow-list.
pub fn check(root: &Path) -> Result<InventorySummary, String> {
    let native = read_csv(&root.join(NATIVE_INVENTORY_PATH))?;
    if native.rows.len() != NATIVE_INVENTORY_ROWS {
        return Err(format!(
            "native inventory has {} rows, expected {}",
            native.rows.len(),
            NATIVE_INVENTORY_ROWS
        ));
    }
    let ledger = read_csv(&root.join(PARITY_LEDGER_PATH))?;
    if ledger.rows.len() != PARITY_LEDGER_ROWS {
        return Err(format!(
            "parity ledger has {} rows, expected {}",
            ledger.rows.len(),
            PARITY_LEDGER_ROWS
        ));
    }
    // Ledger status column is the trailing field; the CSV embeds commas
    // inside quoted cells so we scan the row from the right using an
    // unquoted-comma count.
    let status_column = ledger
        .header
        .split(',')
        .position(|column| column == "status")
        .ok_or_else(|| "parity ledger is missing a `status` column".to_owned())?;
    let header_columns = ledger.header.split(',').count();
    for (index, row) in ledger.rows.iter().enumerate() {
        let status = csv_field(row, status_column, header_columns).ok_or_else(|| {
            format!(
                "parity ledger row {} does not have {} columns",
                index + 2,
                header_columns
            )
        })?;
        if !LEDGER_ALLOWED_STATUSES.contains(&status) {
            return Err(format!(
                "parity ledger row {} has unresolved status {status:?}",
                index + 2
            ));
        }
    }
    Ok(InventorySummary {
        native_rows: native.rows.len(),
        ledger_rows: ledger.rows.len(),
    })
}

struct Csv {
    header: String,
    rows: Vec<String>,
}

fn read_csv(path: &Path) -> Result<Csv, String> {
    let contents =
        fs::read_to_string(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    let mut lines = contents.split('\n');
    let header = lines
        .next()
        .ok_or_else(|| format!("{} is empty", path.display()))?
        .to_owned();
    let mut rows = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        rows.push(line.to_owned());
    }
    Ok(Csv { header, rows })
}

/// Return the CSV field at `column` respecting minimal quoted-field rules.
/// Enough to peek at the frozen ledger; not a full RFC 4180 parser.
fn csv_field(row: &str, column: usize, expected_columns: usize) -> Option<&str> {
    let mut in_quotes = false;
    let mut current = 0_usize;
    let mut field_start = 0_usize;
    let bytes = row.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        match *byte {
            b'"' => in_quotes = !in_quotes,
            b',' if !in_quotes => {
                if current == column {
                    return Some(&row[field_start..index]);
                }
                current += 1;
                field_start = index + 1;
            }
            _ => {}
        }
    }
    if current + 1 != expected_columns {
        return None;
    }
    if current == column {
        Some(&row[field_start..])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::csv_field;

    #[test]
    fn parses_quoted_commas() {
        let row = r#"a,"b,c",d"#;
        assert_eq!(csv_field(row, 0, 3), Some("a"));
        assert_eq!(csv_field(row, 1, 3), Some("\"b,c\""));
        assert_eq!(csv_field(row, 2, 3), Some("d"));
    }
}
