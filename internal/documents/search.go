package documents

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/stuck-lehnert/domainshare/internal/directory"
)

const privateFacetLimit = 128

var ErrInvalidSearch = errors.New("invalid document search parameters")

type searchError string

func (err searchError) Error() string { return string(err) }
func (err searchError) Unwrap() error { return ErrInvalidSearch }

const invalidCursor searchError = "Ungültiger Seitenzeiger"

type SearchResult struct {
	Items            []Document `json:"items"`
	Total            int64      `json:"total"`
	TotalExact       bool       `json:"totalExact"`
	HasMore          bool       `json:"hasMore"`
	NextCursor       *string    `json:"nextCursor"`
	Sources          []Source   `json:"sources"`
	Types            []string   `json:"types"`
	Pending          int64      `json:"pending"`
	PendingExact     bool       `json:"pendingExact"`
	SearchIncomplete bool       `json:"searchIncomplete"`
}

type searchRequest struct {
	query, scope, source, extension, sort string
	limit, offset                         int
	signature                             string
	position                              cursorPosition
}

func unicodeSpace(r rune) bool { return unicode.IsSpace(r) || r >= 0x1c && r <= 0x1f }

func limitRunes(value string, count int) string {
	for pos := range value {
		if count == 0 {
			return value[:pos]
		}
		count--
	}
	return value
}

func parseSearch(params url.Values) (searchRequest, error) {
	value := func(key, fallback string) string {
		if entries := params[key]; len(entries) != 0 {
			return entries[0]
		}
		return fallback
	}

	req := searchRequest{
		query: limitRunes(strings.TrimFunc(value("q", ""), unicodeSpace), 256),
		scope: value("scope", "all"), source: value("source", ""),
		extension: strings.TrimLeft(strings.ToLower(value("type", "")), "."),
		sort:      value("sort", "recent"),
	}
	switch req.sort {
	case "name", "oldest", "recent":
	case "relevance":
		if req.query == "" || req.scope == "name" {
			req.sort = "recent"
		}
	default:
		req.sort = "recent"
	}

	limit, limitErr := strconv.Atoi(strings.TrimFunc(value("limit", "40"), unicodeSpace))
	offset, offsetErr := strconv.Atoi(strings.TrimFunc(value("offset", "0"), unicodeSpace))
	encoded := value("cursor", "")
	if limitErr != nil || offsetErr != nil || offset > 1000 && encoded == "" {
		return searchRequest{}, searchError("Für weitere Seiten bitte den Seitenzeiger verwenden")
	}

	req.limit, req.offset = min(100, max(1, limit)), max(0, offset)
	req.signature = cursorScope(req.query, req.scope, req.source, req.extension, req.sort)
	position, err := decodeCursor(encoded, req.signature, req.sort)
	if err != nil {
		return searchRequest{}, err
	}
	if position.present {
		req.offset = 0
	}
	req.position = position
	return req, nil
}

func (req searchRequest) match() (table, match string) {
	if req.query == "" {
		return "", ""
	}
	if req.scope == "name" {
		name := []rune(foldCase.String(req.query))
		n := min(3, len(name))
		terms := make([]string, 0, len(name)-n+1)
		for i := 0; i+n <= len(name); i++ {
			terms = append(terms, searchKey(string(name[i:i+n]), "g"))
		}
		return "document_names_fts", strings.Join(terms, " AND ")
	}

	words := strings.FieldsFunc(req.query, func(r rune) bool {
		return !(unicode.IsLetter(r) || unicode.IsNumber(r) || r == '_')
	})
	if len(words) == 0 {
		return "document_fts", ""
	}
	words = words[:min(24, len(words))]
	for i, word := range words {
		words[i] = `"` + word + `"*`
	}
	columns := "{name path body}"
	if req.scope == "content" {
		columns = "body"
	}
	return "document_fts", columns + " : (" + strings.Join(words, " AND ") + ")"
}

func (service Service) Search(ctx context.Context, identity directory.Identity, params url.Values) (SearchResult, error) {
	req, err := parseSearch(params)
	if err != nil {
		return SearchResult{}, err
	}
	tx, err := service.Catalog.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return SearchResult{}, err
	}
	defer tx.Rollback()

	sources, err := service.allowedSourcesInCatalog(ctx, identity, false, tx)
	if err != nil {
		return SearchResult{}, err
	}
	result := SearchResult{Items: []Document{}, Sources: []Source{}, Types: []string{}, TotalExact: true, PendingExact: true}
	selected := make(map[string]Source)
	for _, id := range sortedKeys(sources) {
		source := sources[id]
		// Source authorization checks policy plus the catalog root. Suppress
		// sources that no longer have an accessible, pinned directory at all.
		root, _, err := openDirectory(source.root, nil, source.owner)
		if err != nil {
			continue
		}
		root.Close()
		result.Sources = append(result.Sources, source)
		if req.source == "" || req.source == id {
			selected[id] = source
		}
	}
	if len(selected) == 0 {
		return result, nil
	}

	search := searchSnapshot{tx: tx, req: req, selected: selected, result: result,
		readable: make(map[string]bool), types: make(map[string]struct{})}
	return search.run(ctx)
}

type searchSnapshot struct {
	tx            *sql.Tx
	req           searchRequest
	selected      map[string]Source
	result        SearchResult
	readable      map[string]bool
	types         map[string]struct{}
	total         int64
	selectedCount int64
}

func (search *searchSnapshot) permitted(id, sourceID, path string) bool {
	source := search.selected[sourceID]
	if source.Kind != "private" {
		return true
	}
	if readable, ok := search.readable[id]; ok {
		return readable
	}

	file, _, err := openFile(source.root, path, source.owner)
	readable := err == nil
	if readable {
		file.Close()
	}
	search.readable[id] = readable
	return readable
}

func (search *searchSnapshot) addFacet(extension, state string, amount int64) {
	if extension != "" {
		search.types[strings.TrimLeft(extension, ".")] = struct{}{}
	}
	if search.req.extension == "" || extension == "."+search.req.extension {
		search.total += amount
	}
	if state == "pending" || state == "ocr" {
		search.result.Pending += amount
	}
}

func (search *searchSnapshot) loadFacets(ctx context.Context, source Source) error {
	rows, err := search.tx.QueryContext(ctx, `SELECT extension,state,amount FROM document_counts WHERE source_id=?`, source.ID)
	if err != nil {
		return err
	}
	defer rows.Close()

	var count int64
	suffixes := make(map[string]struct{})
	for rows.Next() {
		var extension, state string
		var amount int64
		if err := rows.Scan(&extension, &state, &amount); err != nil {
			return err
		}
		count += amount
		if source.Kind == "private" {
			suffixes[extension] = struct{}{}
		} else {
			search.addFacet(extension, state, amount)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	search.selectedCount += count
	if source.Kind != "private" {
		return nil
	}

	small := count <= privateFacetLimit
	search.result.PendingExact = search.result.PendingExact && small
	budget := privateFacetLimit
	for i, suffix := range sortedKeys(suffixes) {
		if !small && budget <= 0 {
			break
		}
		amount := int(count)
		if !small {
			amount = max(1, budget/(len(suffixes)-i))
		}
		sampled, err := search.sampleFacets(ctx, source.ID, suffix, amount)
		if err != nil {
			return err
		}
		budget -= sampled
	}
	return nil
}

func (search *searchSnapshot) sampleFacets(ctx context.Context, sourceID, suffix string, amount int) (int, error) {
	rows, err := search.tx.QueryContext(ctx, `SELECT d.id,d.path,d.state FROM documents d
		INDEXED BY document_search_recent_type WHERE d.source_id=? AND d.extension=? AND `+visibleDocument+`
		ORDER BY d.modified DESC,d.id DESC LIMIT ?`, sourceID, suffix, amount)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var id, path, state string
		if err := rows.Scan(&id, &path, &state); err != nil {
			return 0, err
		}
		count++
		if search.permitted(id, sourceID, path) {
			search.addFacet(suffix, state, 1)
		}
	}
	return count, rows.Err()
}

func (search *searchSnapshot) run(ctx context.Context) (SearchResult, error) {
	ids := sortedKeys(search.selected)
	for _, id := range ids {
		if err := search.loadFacets(ctx, search.selected[id]); err != nil {
			return SearchResult{}, err
		}
	}

	table, match := search.req.match()
	if table != "" && match == "" {
		search.result.Types = sortedKeys(search.types)
		return search.result, nil
	}

	candidates, complete, boundary, err := search.candidates(ctx, ids, table, match)
	if err != nil {
		return SearchResult{}, err
	}
	return search.buildPage(ctx, candidates, complete, boundary)
}

func (search *searchSnapshot) candidates(ctx context.Context, ids []string, table, match string) ([]catalogRow, bool, *catalogRow, error) {
	var all []catalogRow
	var boundary *catalogRow
	complete := true
	combined := search.req.sort == "relevance" || table != "" && len(ids) > 1
	var selections [][]string
	var count int64
	if combined {
		selections = append(selections, ids)
		if err := search.tx.QueryRowContext(ctx, `SELECT coalesce(sum(amount),0) FROM document_counts`).Scan(&count); err != nil {
			return nil, false, nil, err
		}
	} else {
		for _, id := range ids {
			selections = append(selections, []string{id})
		}
	}

	if search.req.sort == "relevance" && max(search.req.position.consumed, search.req.position.rankOffset) > search.selectedCount {
		return nil, false, nil, invalidCursor
	}

	compare := compareRows(search.req.sort)
	for _, selection := range selections {
		amount := search.req.limit + search.req.offset + 1
		for _, id := range selection {
			if search.selected[id].Kind == "private" {
				amount += privateFacetLimit
				break
			}
		}

		var rows []catalogRow
		var exhaustive bool
		var err error
		if search.req.sort == "relevance" {
			rows, exhaustive, err = search.rankedRows(ctx, selection, match, amount, search.selectedCount != count)
		} else {
			pushSources := !combined || float64(search.selectedCount) < float64(count)*0.5
			rows, exhaustive, err = search.orderedRows(ctx, selection, table, match, amount, combined, pushSources)
		}
		if err != nil {
			return nil, false, nil, err
		}

		all = append(all, rows...)
		complete = complete && exhaustive
		if !exhaustive && len(rows) >= amount {
			last := rows[len(rows)-1]
			if boundary == nil || compare(last, *boundary) < 0 {
				boundary = &last
			}
		}
	}
	slices.SortFunc(all, compare)
	return all, complete, boundary, nil
}

func (search *searchSnapshot) buildPage(ctx context.Context, candidates []catalogRow, complete bool, boundary *catalogRow) (SearchResult, error) {
	result := search.result
	req := search.req
	compare := compareRows(req.sort)
	var visible []catalogRow
	var frontier *catalogRow
	exhausted := true
	for i := range candidates {
		if err := ctx.Err(); err != nil {
			return SearchResult{}, err
		}
		row := &candidates[i]
		if boundary != nil && compare(*row, *boundary) > 0 {
			exhausted = false
			break
		}
		frontier = row
		if !search.permitted(row.ID, row.SourceID, row.Path) {
			continue
		}
		file, err := row.openCurrent(search.selected[row.SourceID])
		if err != nil {
			continue
		}
		file.Close()

		visible = append(visible, *row)
		if len(visible) > req.offset+req.limit {
			exhausted = false
			break
		}
	}

	more := len(visible) > req.offset+req.limit
	page := visible[min(len(visible), req.offset):min(len(visible), req.offset+req.limit)]
	incomplete := !more && boundary != nil && (!exhausted || frontier != nil && compare(*frontier, *boundary) >= 0)
	result.HasMore = more || incomplete
	result.SearchIncomplete = incomplete
	advanced := req.position.consumed + int64(req.offset+len(page))
	if result.HasMore && (len(page) != 0 || frontier != nil) {
		last := frontier
		if more {
			last = &page[len(page)-1]
		}
		value, err := encodeCursor(req.signature, req.sort, *last, advanced)
		if err != nil {
			return SearchResult{}, err
		}
		result.NextCursor = &value
	}

	lower := advanced
	if more {
		lower++
	}
	if req.query != "" {
		switch {
		case complete && !req.position.present:
			for _, row := range candidates {
				if search.permitted(row.ID, row.SourceID, row.Path) {
					result.Total++
				}
			}
		case !result.HasMore:
			result.Total = advanced
		default:
			result.Total, result.TotalExact = lower, false
		}
	} else {
		result.Total, result.TotalExact = search.total, result.PendingExact
		if !result.TotalExact {
			result.Total = max(result.Total, lower)
		}
	}

	for _, row := range page {
		result.Items = append(result.Items, row.public(search.selected[row.SourceID]))
		if row.Extension != "" {
			search.types[strings.TrimLeft(row.Extension, ".")] = struct{}{}
		}
	}
	result.Types = sortedKeys(search.types)
	return result, nil
}
