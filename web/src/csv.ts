/** Serialize tabular values for spreadsheet-safe CSV downloads. */
export function serializeCsv(rows: Array<Record<string, unknown>>, columns: string[]): string {
  const field = (value: unknown): string => {
    let text = value == null ? "" : typeof value === "string" ? value : String(value);
    // Keep spreadsheet applications from evaluating attacker-controlled cells.
    if (typeof value === "string" && /^\s*[=+\-@]/.test(value)) text = `'${text}`;
    return `"${text.replace(/"/g, '""')}"`;
  };
  return [columns.map(field).join(","), ...rows.map((row) => columns.map((column) => field(row[column])).join(","))].join("\r\n");
}
