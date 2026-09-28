//! Plain-text rendering of API JSON.

use serde_json::Value;
use std::io::{self, Write};

/// One cell: strings as-is, `null` as `-`, other values as compact JSON.
pub fn cell(value: &Value) -> String {
    let text = match value {
        Value::Null => "-".into(),
        Value::String(s) => s.clone(),
        Value::Object(map) if map.values().all(Value::is_boolean) => map
            .iter()
            .filter(|(_, on)| on.as_bool() == Some(true))
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
            .join(","),
        other => other.to_string(),
    };
    // Keep terminal control characters from API text out of the output.
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

pub fn table(out: &mut dyn Write, columns: &[&str], rows: &[Value]) -> io::Result<()> {
    if rows.is_empty() {
        return writeln!(out, "No results.");
    }
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|row| columns.iter().map(|c| cell(&row[*c])).collect())
        .collect();
    let widths: Vec<usize> = columns
        .iter()
        .enumerate()
        .map(|(i, c)| {
            cells
                .iter()
                .map(|r| r[i].chars().count())
                .max()
                .unwrap_or(0)
                .max(c.len())
        })
        .collect();
    let line = |out: &mut dyn Write, values: &[String]| {
        let text: Vec<String> = values
            .iter()
            .zip(&widths)
            .map(|(v, w)| format!("{v:<w$}"))
            .collect();
        writeln!(out, "{}", text.join("  ").trim_end())
    };
    let header: Vec<String> = columns.iter().map(|c| c.to_uppercase()).collect();
    line(out, &header)?;
    for row in &cells {
        line(out, row)?;
    }
    Ok(())
}

pub fn fields(out: &mut dyn Write, value: &Value, names: &[&str]) -> io::Result<()> {
    let width = names.iter().map(|n| n.len()).max().unwrap_or(0);
    for name in names {
        let line = format!("{name:<width$}  {}", cell(&value[*name]));
        writeln!(out, "{}", line.trim_end())?;
    }
    Ok(())
}

pub fn next_page(out: &mut dyn Write, page: &Value) -> io::Result<()> {
    if let Some(cursor) = page["next_cursor"].as_str() {
        writeln!(out, "More results: --after {}", cell(&Value::from(cursor)))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn renders_tables_and_cells() {
        let mut out = Vec::new();
        table(
            &mut out,
            &["id", "state", "entitlements"],
            &[
                json!({"id": "lic_1", "state": null, "entitlements": {"a": true, "b": false}}),
                json!({"id": "l2", "state": "active\u{1b}[31m", "entitlements": {}}),
            ],
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "ID     STATE        ENTITLEMENTS\nlic_1  -            a\nl2     active [31m\n"
        );
    }
}
