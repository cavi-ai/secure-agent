package store

// activityTimeLayout is used for SQL comparison parameters, not persisted
// timestamps or wire values. Fixed fractional width preserves lexical order.
const activityTimeLayout = "2006-01-02T15:04:05.000000000Z"

// timestampSQLParts splits persisted RFC3339Nano values into whole seconds
// (including the UTC offset) and a nine-digit fractional second.
// Callers supply fixed SQL column identifiers, never user input.
func timestampSQLParts(column string) (seconds, fraction string) {
	suffix := "(CASE WHEN substr(" + column + ",-1)='Z' THEN 1 ELSE 6 END)"
	zone := "substr(" + column + ",-" + suffix + ")"
	fraction = "(CASE WHEN instr(" + column + ",'.')>0 THEN substr(" + column + ",instr(" + column + ",'.')+1,length(" + column + ")-instr(" + column + ",'.')-" + suffix + ") ELSE '' END)"
	return "substr(" + column + ",1,19)||" + zone, "substr(" + fraction + "||'000000000',1,9)"
}

// timestampOrderExpr normalizes to fixed-width UTC without rewriting rows.
// Normalize whole seconds separately so SQLite cannot round fractions; text
// ordering also avoids the representable-range limit of Unix nanoseconds.
func timestampOrderExpr(column string) string {
	seconds, fraction := timestampSQLParts(column)
	return "(strftime('%Y-%m-%dT%H:%M:%S'," + seconds + ")||'.'||" + fraction + "||'Z')"
}

// memoryTimestampExpr preserves the existing nanosecond memory-cursor contract.
func memoryTimestampExpr(column string) string {
	seconds, fraction := timestampSQLParts(column)
	return "(CAST(strftime('%s'," + seconds + ") AS INTEGER)*1000000000 + CAST(" + fraction + " AS INTEGER))"
}
