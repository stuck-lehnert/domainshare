package documents

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

const probeLimit = 512

type cursorPosition struct {
	present              bool
	primary              any
	id                   string
	consumed, rankOffset int64
}

// Python's cursor scope hashes JSON with ensure_ascii and its default comma
// separator. Keep browser pagination valid across migration and rollback.
func cursorScope(query, scope, source, extension, sort string) string {
	values := []string{query, scope, source, extension, sort}
	encoded := make([]string, len(values))
	for i, value := range values {
		encoded[i] = pythonJSONString(value)
	}
	sum := sha256.Sum256([]byte("[" + strings.Join(encoded, ", ") + "]"))
	return hex.EncodeToString(sum[:8])
}

func pythonJSONString(value string) string {
	var out strings.Builder
	out.WriteByte('"')
	writeEscape := func(r rune) {
		const digits = "0123456789abcdef"
		out.WriteString(`\u`)
		for shift := 12; shift >= 0; shift -= 4 {
			out.WriteByte(digits[(r>>shift)&15])
		}
	}
	for _, r := range value {
		switch r {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			switch {
			case r >= 32 && r < 127:
				out.WriteRune(r)
			case r <= 0xffff:
				writeEscape(r)
			default:
				hi, lo := utf16.EncodeRune(r)
				writeEscape(hi)
				writeEscape(lo)
			}
		}
	}
	out.WriteByte('"')
	return out.String()
}

func decodeCursor(encoded, signature, order string) (cursorPosition, error) {
	if encoded == "" {
		return cursorPosition{}, nil
	}
	if len(encoded) > 2048 {
		return cursorPosition{}, invalidCursor
	}

	data, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(encoded, "="))
	if err != nil {
		return cursorPosition{}, invalidCursor
	}
	var outer []json.RawMessage
	if json.Unmarshal(data, &outer) != nil || len(outer) != 3 {
		return cursorPosition{}, invalidCursor
	}

	var scope string
	var position []json.RawMessage
	var result cursorPosition
	if json.Unmarshal(outer[0], &scope) != nil || scope != signature ||
		json.Unmarshal(outer[1], &position) != nil || len(position) < 3 || len(position) > 4 ||
		!cursorInteger(outer[2], &result.consumed) || result.consumed < 0 || result.consumed > 1<<62 {
		return cursorPosition{}, invalidCursor
	}

	var rowID int64
	if !cursorInteger(position[1], &rowID) || !cursorString(position[2], &result.id) {
		return cursorPosition{}, invalidCursor
	}
	if order == "name" {
		var name string
		if !cursorString(position[0], &name) {
			return cursorPosition{}, invalidCursor
		}
		result.primary = name
	} else {
		var number float64
		if bytes.Equal(position[0], []byte("null")) || json.Unmarshal(position[0], &number) != nil {
			return cursorPosition{}, invalidCursor
		}
		result.primary = number
	}

	result.rankOffset = result.consumed
	if len(position) == 4 && (!cursorInteger(position[3], &result.rankOffset) || result.rankOffset < 0) {
		return cursorPosition{}, invalidCursor
	}
	result.present = true
	return result, nil
}

func cursorInteger(raw json.RawMessage, dst *int64) bool {
	return !bytes.Equal(raw, []byte("null")) && json.Unmarshal(raw, dst) == nil
}

func cursorString(raw json.RawMessage, dst *string) bool {
	return !bytes.Equal(raw, []byte("null")) && json.Unmarshal(raw, dst) == nil
}

func pythonFloat(value float64) string {
	// SQLite's ordinary timestamps and BM25 scores use Python's fixed
	// decimal format below 1e16 and down to 1e-4.
	format := byte('f')
	absolute := max(value, -value)
	if absolute >= 1e16 || absolute != 0 && absolute < 1e-4 {
		format = 'e'
	}
	number := strconv.FormatFloat(value, format, -1, 64)
	if format == 'f' && !strings.Contains(number, ".") {
		number += ".0"
	}
	return number
}

func encodeCursor(signature, sort string, row catalogRow, consumed int64) (string, error) {
	primary := pythonFloat(row.Modified)
	if sort == "name" {
		primary = pythonJSONString(row.Name)
	} else if sort == "relevance" {
		primary = pythonFloat(row.rank)
	}
	position := []string{primary, strconv.FormatInt(row.rowID, 10), pythonJSONString(row.ID)}
	if sort == "relevance" {
		position = append(position, strconv.FormatInt(row.streamOffset, 10))
	}
	encoded := `[` + pythonJSONString(signature) + `,[` + strings.Join(position, ",") + `],` + strconv.FormatInt(consumed, 10) + `]`
	if !json.Valid([]byte(encoded)) {
		return "", invalidCursor
	}
	return base64.RawURLEncoding.EncodeToString([]byte(encoded)), nil
}

func asciiLower(value string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, value)
}

func compareRows(order string) func(a, b catalogRow) int {
	return func(a, b catalogRow) int {
		switch order {
		case "relevance":
			if order := cmp.Compare(a.rank, b.rank); order != 0 {
				return order
			}
			return cmp.Compare(a.rowID, b.rowID)
		case "name":
			if order := cmp.Compare(asciiLower(a.Name), asciiLower(b.Name)); order != 0 {
				return order
			}
		case "recent":
			if order := cmp.Compare(b.Modified, a.Modified); order != 0 {
				return order
			}
			return cmp.Compare(b.ID, a.ID)
		default:
			if order := cmp.Compare(a.Modified, b.Modified); order != 0 {
				return order
			}
		}
		return cmp.Compare(a.ID, b.ID)
	}
}

type queryFilter struct {
	where string
	args  []any
}

func addStrings(dst []any, values []string) []any {
	for _, value := range values {
		dst = append(dst, value)
	}
	return dst
}

func placeholderList(n int) string { return strings.Repeat("?,", n-1) + "?" }

func (req searchRequest) baseFilter(sourceIDs []string) queryFilter {
	filter := queryFilter{
		where: `d.source_id IN (` + placeholderList(len(sourceIDs)) + `) AND ` + visibleDocument,
		args:  addStrings(nil, sourceIDs),
	}
	if len(sourceIDs) == 1 {
		filter.where = `d.source_id=? AND ` + visibleDocument
	}
	if req.extension != "" {
		filter.where += ` AND d.extension=?`
		filter.args = append(filter.args, "."+req.extension)
	}
	return filter
}

func (req searchRequest) orderedFilter(sourceIDs []string) queryFilter {
	filter := req.baseFilter(sourceIDs)
	if req.scope == "name" && req.query != "" {
		escape := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
		filter.where += ` AND d.name LIKE ? ESCAPE '\'`
		filter.args = append(filter.args, "%"+escape.Replace(req.query)+"%")
	}
	if req.position.present {
		primary, op := "d.modified", ">"
		if req.sort == "recent" {
			op = "<"
		} else if req.sort == "name" {
			primary = "d.name COLLATE NOCASE"
		}
		filter.where += ` AND (` + primary + `,d.id) ` + op + ` (?,?)`
		filter.args = append(filter.args, req.position.primary, req.position.id)
		if req.sort == "name" {
			filter.where += ` AND d.name COLLATE NOCASE>=?`
			filter.args = append(filter.args, req.position.primary)
		}
	}
	return filter
}

func (req searchRequest) scopedMatch(table, match string, sourceIDs []string, pushSources bool) string {
	match = "(" + match + ")"
	sourceColumn, typeColumn := "", ""
	if table == "document_fts" {
		sourceColumn, typeColumn = "source_key:", "type_key:"
	}
	if pushSources {
		terms := make([]string, len(sourceIDs))
		for i, id := range sourceIDs {
			terms[i] = searchKey(id, "s")
		}
		match += " AND " + sourceColumn + "(" + strings.Join(terms, " OR ") + ")"
	}
	if req.extension != "" {
		match += " AND " + typeColumn + searchKey("."+req.extension, "t")
	}
	return match
}

func (search *searchSnapshot) probe(ctx context.Context, from, where string, args []any) (int, error) {
	var count int
	err := search.tx.QueryRowContext(ctx, `SELECT count(*) FROM (SELECT d.rowid FROM `+from+` WHERE `+where+` LIMIT ?)`,
		append(append([]any(nil), args...), probeLimit+1)...).Scan(&count)
	return count, err
}

func (search *searchSnapshot) loadRows(ctx context.Context, statement string, args ...any) ([]catalogRow, error) {
	rows, err := search.tx.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []catalogRow
	for rows.Next() {
		var row catalogRow
		if err := rows.Scan(append(row.columns(), &row.rank)...); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (search *searchSnapshot) orderedRows(ctx context.Context, sourceIDs []string, table, match string, amount int, global, pushSources bool) ([]catalogRow, bool, error) {
	req := search.req
	filter := req.orderedFilter(sourceIDs)
	order := "d.modified DESC,d.id DESC"
	switch req.sort {
	case "name":
		order = "d.name COLLATE NOCASE,d.id"
	case "oldest":
		order = "d.modified,d.id"
	}
	index := "document_search_" + req.sort
	if global {
		index = "document_global_" + req.sort
	}
	if req.extension != "" {
		index += "_type"
	}
	columns := documentColumns + ",0 _rank"
	ordered := ` ORDER BY ` + order + ` LIMIT ?`
	if table == "" {
		rows, err := search.loadRows(ctx, `SELECT `+columns+` FROM documents d INDEXED BY `+index+
			` WHERE `+filter.where+ordered, append(filter.args, amount)...)
		return rows, false, err
	}

	scoped := req.scopedMatch(table, match, sourceIDs, pushSources)
	joined := table + ` CROSS JOIN documents d ON d.rowid=` + table + `.rowid`
	where := table + ` MATCH ? AND ` + filter.where
	args := append([]any{scoped}, filter.args...)
	count, err := search.probe(ctx, joined, where, args)
	if err != nil || count == 0 {
		return nil, count == 0, err
	}
	complete := count <= probeLimit
	if complete {
		amount = max(amount, probeLimit+1)
	} else {
		// A broad match is fast when ordered metadata supplies the next rows.
		// Retry via the FTS join if that plan scans too far for sparse matches.
		budget := 150 * time.Millisecond
		if global {
			budget = time.Second
		}
		fastCtx, cancel := context.WithTimeout(ctx, budget)
		rows, err := search.loadRows(fastCtx, `SELECT `+columns+` FROM documents d INDEXED BY `+index+
			` WHERE `+filter.where+` AND d.rowid IN (SELECT rowid FROM `+table+` WHERE `+table+` MATCH ?)`+
			ordered, append(append([]any(nil), filter.args...), scoped, amount)...)
		deadline := fastCtx.Err()
		cancel()
		if err == nil || deadline == nil || ctx.Err() != nil {
			return rows, false, err
		}
	}
	rows, err := search.loadRows(ctx, `SELECT `+columns+` FROM `+joined+` WHERE `+where+ordered, append(args, amount)...)
	return rows, complete, err
}

func (search *searchSnapshot) rankedRows(ctx context.Context, sourceIDs []string, match string, amount int, pushSources bool) ([]catalogRow, bool, error) {
	req := search.req
	const table = "document_fts"
	scoped := req.scopedMatch(table, match, sourceIDs, pushSources)
	filter := req.baseFilter(sourceIDs)
	const joined = `document_fts CROSS JOIN documents d ON d.rowid=document_fts.rowid`
	count, err := search.probe(ctx, joined, `document_fts MATCH ? AND `+filter.where, append([]any{scoped}, filter.args...))
	if err != nil {
		return nil, false, err
	}
	if count <= probeLimit {
		amount = max(amount, probeLimit+1)
	}

	// Stream offsets rather than BM25 thresholds survive statistics changes
	// when OCR updates an otherwise unchanged catalog between pages.
	args := append([]any{scoped, amount, req.position.rankOffset}, filter.args...)
	rows, err := search.loadRows(ctx, `SELECT `+documentColumns+`,page.score FROM (
		SELECT rowid,rank score FROM document_fts WHERE document_fts MATCH ? ORDER BY rank LIMIT ? OFFSET ?
	) page JOIN documents d ON d.rowid=page.rowid WHERE `+filter.where+` ORDER BY page.score,page.rowid`, args...)
	for i := range rows {
		rows[i].streamOffset = req.position.rankOffset + int64(i) + 1
	}
	return rows, count <= probeLimit, err
}
