package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	StreamMain    = "main"
	StreamFSLogix = "fslogix"
)

// InvalidQuery distinguishes invalid client parameters from storage errors.
type InvalidQuery struct{ Message string }

func (e *InvalidQuery) Error() string { return e.Message }

type IndexingStatus struct {
	Ready           bool    `json:"ready"`
	ProcessedEvents int64   `json:"processedEvents"`
	TotalEvents     int64   `json:"totalEvents"`
	Percent         float64 `json:"percent"`
}

type Facets struct {
	Users      []string `json:"users"`
	Shares     []string `json:"shares"`
	Operations []string `json:"operations"`
	Actions    []string `json:"actions"`
}

type Activity struct {
	Events       []Event        `json:"events"`
	HasMore      bool           `json:"hasMore"`
	NextCursor   *string        `json:"nextCursor"`
	Matched      *int64         `json:"matched"`
	MatchedExact bool           `json:"matchedExact"`
	Facets       Facets         `json:"facets"`
	Indexing     IndexingStatus `json:"indexing"`
	Stream       string         `json:"stream"`
}

type Summary struct {
	Days     int64          `json:"days"`
	Bytes    int64          `json:"bytes"`
	Oldest   *string        `json:"oldest"`
	Newest   *string        `json:"newest"`
	Indexing IndexingStatus `json:"indexing"`
}

func param(params url.Values, key, fallback string) string {
	if values := params[key]; len(values) != 0 {
		return values[0]
	}
	return fallback
}

func queryFlag(params url.Values, name string) bool {
	switch fold(strings.TrimSpace(param(params, name, "1"))) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

func utcDay(value time.Time) time.Time {
	year, month, day := value.Date()
	return time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
}

// Query resolves HTTP date parameters and the same UTC two-day default and
// AUDIT_QUERY_MAX_DAYS setting as the Python API.
func (s *Store) Query(ctx context.Context, params url.Values, stream string) (Activity, error) {
	today := utcDay(time.Now().UTC())
	start, startErr := time.Parse(dayLayout, param(params, "from", today.AddDate(0, 0, -1).Format(dayLayout)))
	end, endErr := time.Parse(dayLayout, param(params, "to", today.Format(dayLayout)))
	if startErr != nil || endErr != nil || start.Year() < 1 || end.Year() < 1 {
		return Activity{}, &InvalidQuery{"Datumsangaben müssen YYYY-MM-DD verwenden"}
	}
	maxDays, err := strconv.Atoi(strings.TrimSpace(env("AUDIT_QUERY_MAX_DAYS", "31")))
	if err != nil {
		maxDays = 31
	}
	maxDays = min(366, max(1, maxDays))
	if end.Before(start) || !end.Before(start.AddDate(0, 0, maxDays)) {
		return Activity{}, &InvalidQuery{fmt.Sprintf("Der Datumsbereich darf höchstens %d Tage umfassen", maxDays)}
	}
	return s.QueryActivity(ctx, start, end, params, stream)
}

func streamCondition(stream string) (string, error) {
	switch stream {
	case StreamMain:
		return "share <> 'FSLogix' COLLATE NOCASE", nil
	case StreamFSLogix:
		return "share = 'FSLogix' COLLATE NOCASE", nil
	default:
		return "", &InvalidQuery{"Ungültiger Aktivitätsstrom"}
	}
}

type predicate struct {
	clauses []string
	args    []any
}

func (p *predicate) add(clause string, args ...any) {
	p.clauses = append(p.clauses, clause)
	p.args = append(p.args, args...)
}

func (p predicate) sql() string { return strings.Join(p.clauses, " AND ") }

var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

func (p *predicate) excludeSuffixes(suffixes []string) {
	for _, suffix := range suffixes {
		p.add(`account NOT LIKE ? ESCAPE '\'`, "%"+likeEscaper.Replace(suffix))
	}
}

type filters struct{ user, share, path, action, result string }

func readFilters(params url.Values) filters {
	get := func(key string) string { return fold(strings.TrimSpace(params.Get(key))) }
	action := get("action")
	if action == "" {
		action = get("operation")
	}
	return filters{get("user"), get("share"), get("path"), action, get("result")}
}

func (f filters) apply(p *predicate) {
	if f.user != "" {
		if strings.ContainsAny(f.user, `\@`) {
			p.add("user = ? COLLATE NOCASE", f.user)
		} else {
			p.add("account = ?", f.user)
		}
	}
	if f.share != "" {
		p.add("share = ? COLLATE NOCASE", f.share)
	}
	if f.action != "" {
		p.add("action = ?", f.action)
	}
	if f.result == "fail" {
		p.add("success = 0")
	} else if f.result != "" {
		p.add("result = ? COLLATE NOCASE", f.result)
	}
}

func indexingStatus(ctx context.Context, tx *sql.Tx) (IndexingStatus, error) {
	var status IndexingStatus
	var nextID int64
	err := tx.QueryRowContext(ctx, `
		SELECT backfill_next_id, backfill_max_id, ready
		FROM audit_rollup_state WHERE singleton = 1`).Scan(&nextID, &status.TotalEvents, &status.Ready)
	if errors.Is(err, sql.ErrNoRows) {
		return IndexingStatus{}, nil
	}
	if err != nil {
		return IndexingStatus{}, err
	}
	status.TotalEvents = max(0, status.TotalEvents)
	if status.Ready {
		status.ProcessedEvents = status.TotalEvents
	} else if nextID > 1 {
		status.ProcessedEvents = min(status.TotalEvents, nextID-1)
	}
	status.Percent = 100
	if !status.Ready && status.TotalEvents > 0 {
		status.Percent = math.RoundToEven(float64(status.ProcessedEvents)*1000/float64(status.TotalEvents)) / 10
	}
	return status, nil
}

type pageOptions struct {
	limit                  int
	hasCursor              bool
	cursorSecond, cursorID int64
}

func activityPageOptions(params url.Values) (pageOptions, error) {
	limit, err := strconv.Atoi(strings.TrimSpace(param(params, "limit", "100")))
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return pageOptions{}, &InvalidQuery{"Ungültige Seitenlänge"}
	}

	options := pageOptions{limit: min(500, max(1, limit))}
	cursor := strings.TrimSpace(params.Get("cursor"))
	if cursor == "" {
		return options, nil
	}

	second, id, found := strings.Cut(cursor, ":")
	options.cursorSecond, err = strconv.ParseInt(strings.TrimSpace(second), 10, 64)
	var idErr error
	options.cursorID, idErr = strconv.ParseInt(strings.TrimSpace(id), 10, 64)
	if !found || err != nil || idErr != nil {
		return pageOptions{}, &InvalidQuery{"Ungültiger Seitenzeiger"}
	}
	options.hasCursor = true
	return options, nil
}

// QueryActivity returns a keyset page for the inclusive UTC date range. Path
// filtering uses SQLite's escaped literal LIKE fallback rather than relying
// on the FTS index or attempting a full count for a broad path filter.
func (s *Store) QueryActivity(ctx context.Context, start, end time.Time, params url.Values, stream string) (Activity, error) {
	streamSQL, err := streamCondition(stream)
	if err != nil {
		return Activity{}, err
	}
	options, err := activityPageOptions(params)
	if err != nil {
		return Activity{}, err
	}
	start, end = utcDay(start), utcDay(end)
	if end.Before(start) {
		return Activity{}, &InvalidQuery{"Ungültiger Datumsbereich"}
	}
	filters, suffixes := readFilters(params), skippedSuffixes()

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return Activity{}, err
	}
	defer tx.Rollback()
	indexing, err := indexingStatus(ctx, tx)
	if err != nil {
		return Activity{}, err
	}

	var where predicate
	where.add("occurred_second >= ? AND occurred_second < ?", start.Unix(), end.AddDate(0, 0, 1).Unix())
	where.add(streamSQL)
	where.excludeSuffixes(suffixes)
	filters.apply(&where)
	if filters.path != "" {
		where.add(`lower(path) LIKE ? ESCAPE '\'`, "%"+likeEscaper.Replace(filters.path)+"%")
	}
	if options.hasCursor {
		where.add("(occurred_second, id) < (?, ?)", options.cursorSecond, options.cursorID)
	}

	result := Activity{
		Events:   make([]Event, 0, options.limit),
		Facets:   Facets{Users: []string{}, Shares: []string{}, Operations: []string{}, Actions: []string{}},
		Indexing: indexing,
		Stream:   stream,
	}
	if err := readPage(ctx, tx, where, options.limit, &result); err != nil {
		return Activity{}, err
	}

	var rollup predicate
	rollup.add("day >= ? AND day <= ?", dayNumber(start.Unix()), dayNumber(end.Unix()))
	rollup.add(streamSQL)
	rollup.excludeSuffixes(suffixes)
	if indexing.Ready && queryFlag(params, "facets") {
		facets, err := readFacets(ctx, tx, rollup)
		if err != nil {
			return Activity{}, err
		}
		result.Facets = facets
	}
	if queryFlag(params, "count") {
		var matched int64
		switch {
		case indexing.Ready && filters.path == "":
			filters.apply(&rollup)
			query := "SELECT coalesce(sum(event_count), 0) FROM audit_daily_counts WHERE " + rollup.sql()
			if err := tx.QueryRowContext(ctx, query, rollup.args...).Scan(&matched); err != nil {
				return Activity{}, err
			}
			result.Matched = &matched
		case !options.hasCursor && !result.HasMore:
			matched = int64(len(result.Events))
			result.Matched = &matched
		}
	}
	result.MatchedExact = result.Matched != nil
	return result, tx.Commit()
}

func readPage(ctx context.Context, tx *sql.Tx, where predicate, limit int, result *Activity) error {
	query := selectEvents + " WHERE " + where.sql() + " ORDER BY occurred_second DESC, id DESC LIMIT ?"
	rows, err := tx.QueryContext(ctx, query, append(where.args, limit+1)...)
	if err != nil {
		return err
	}
	defer rows.Close()
	var lastSecond int64
	for rows.Next() {
		if len(result.Events) == limit {
			result.HasMore = true
			cursor := fmt.Sprintf("%d:%d", lastSecond, result.Events[limit-1].ID)
			result.NextCursor = &cursor
			break
		}
		event, second, err := scanEvent(rows)
		if err != nil {
			return err
		}
		result.Events = append(result.Events, event)
		lastSecond = second
	}
	return rows.Err()
}

func readFacets(ctx context.Context, tx *sql.Tx, where predicate) (Facets, error) {
	distinct := func(column string) ([]string, error) {
		query := fmt.Sprintf(`SELECT DISTINCT %[1]s FROM audit_daily_counts
			WHERE %[2]s AND %[1]s <> '' ORDER BY %[1]s COLLATE NOCASE`, column, where.sql())
		rows, err := tx.QueryContext(ctx, query, where.args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		values := []string{}
		for rows.Next() {
			var value string
			if err := rows.Scan(&value); err != nil {
				return nil, err
			}
			if column != "user" || !excludedAccount(value) {
				values = append(values, value)
			}
		}
		return values, rows.Err()
	}

	users, err := distinct("user")
	if err != nil {
		return Facets{}, err
	}
	shares, err := distinct("share")
	if err != nil {
		return Facets{}, err
	}
	actions, err := distinct("action")
	if err != nil {
		return Facets{}, err
	}
	return Facets{Users: users, Shares: shares, Operations: actions, Actions: actions}, nil
}

// Summary reports main-stream activity and the database plus WAL size.
func (s *Store) Summary(ctx context.Context, databasePath string) (Summary, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return Summary{}, err
	}
	defer tx.Rollback()
	indexing, err := indexingStatus(ctx, tx)
	if err != nil {
		return Summary{}, err
	}

	result := Summary{Indexing: indexing}
	var oldest, newest sql.NullInt64
	if indexing.Ready {
		query := `SELECT count(DISTINCT day), min(day)*86400, max(day)*86400
			FROM audit_daily_counts WHERE share <> 'FSLogix' COLLATE NOCASE`
		if err := tx.QueryRowContext(ctx, query).Scan(&result.Days, &oldest, &newest); err != nil {
			return Summary{}, err
		}
	} else {
		query := `SELECT
			(SELECT occurred_second FROM audit_events WHERE share <> 'FSLogix' COLLATE NOCASE ORDER BY occurred_second, id LIMIT 1),
			(SELECT occurred_second FROM audit_events WHERE share <> 'FSLogix' COLLATE NOCASE ORDER BY occurred_second DESC, id DESC LIMIT 1)`
		if err := tx.QueryRowContext(ctx, query).Scan(&oldest, &newest); err != nil {
			return Summary{}, err
		}
		if oldest.Valid && newest.Valid {
			result.Days = dayNumber(newest.Int64) - dayNumber(oldest.Int64) + 1
		}
	}
	if err := tx.Commit(); err != nil {
		return Summary{}, err
	}

	result.Oldest = formatDay(oldest)
	result.Newest = formatDay(newest)
	for _, suffix := range []string{"", "-wal"} {
		if info, err := os.Stat(databasePath + suffix); err == nil {
			result.Bytes += info.Size()
		}
	}
	return result, nil
}

func formatDay(second sql.NullInt64) *string {
	if !second.Valid {
		return nil
	}
	day := time.Unix(second.Int64, 0).UTC().Format(dayLayout)
	return &day
}
