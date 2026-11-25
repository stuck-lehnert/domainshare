# DomainShare architecture

[Back to DomainShare](../README.md)

How Samba integration, document search, and activity storage work.

## Architecture

- Samba runs in ADS mode with `winbind` identity mapping.
- Static shares:
  - `\\server\Private` -> `/data/private`
  - `\\server\Data` -> `/data/groups/data`
  - `\\server\FSLogix` -> `/data/fslogix`
- Data folders and individual user permissions are managed in the admin web UI. AD remains the source of user identities and authentication.
- Data access uses Windows ACLs stored in Samba’s protected `/state/data-xattrs.tdb`, with separate read, modify, and delete permissions.
- Folder and permission records, normalized activity events, collector offsets, and web caches share one SQLite database at `/state/shares.db`.
- Managed folders are name-based while active and moved to archive through the admin UI:
  - active: `/data/groups/data/<folderName>`
  - archived folders: `/data/groups/archive/<folderName>`
- Samba machine trust/key material is persisted in `/var/lib/samba` to survive container recreation.
- Container hostname is fixed (`SAMBA_HOSTNAME`) to keep AD computer identity stable.
- In bridge-mode Docker networking, startup can publish the host LAN IP in AD DNS with `AD_DNS_IP`/`AD_DNS_NAME` instead of the container bridge IP.
- New installations default to `domainshare` for the DNS hostname and `DOMAINSHARE` for the NetBIOS name. The NetBIOS name is clamped to 15 characters (`NETBIOS_NAME` override supported).
- Setup prompts for well-known authorization groups by SID (`DOMAIN_USERS_SID`, `DOMAIN_ADMINS_SID`) to avoid localized group names.
- `FSLOGIX_GROUP_SID` controls who can access the default FSLogix share (defaults to `DOMAIN_USERS_SID`).
- Startup resolves those SIDs to NSS group names via winbind, then uses those resolved groups in Samba `valid users` rules.
- Samba `full_audit` records successful and failed reads, writes, renames, and deletions on all three shares; FSLogix events are retained in a separate indexed activity stream.
- A collector normalizes those four actions and persists them in indexed SQLite tables; activity is never automatically deleted.
- Samba retains deleted files for seven days in per-user recycle repositories on the same data volumes.
- The HTTPS file interface at `/` lets AD users search accessible Data folders and their own Private folder. An independent background worker indexes text and recognizes scanned PDFs without changing original files.
- The administration console at `/admin/...` manages Data folders and individual user access, and provides statistics, logs, trash downloads/restores, manual backups, and share reconciliation. It also includes a fully client-side Typst PDF report.
- Web sign-in validates the submitted username/password with Kerberos and issues an expiring JWT in a Secure, HttpOnly, SameSite=Strict cookie. Human AD users can sign in; `MSOL_*` and `krbtgt` accounts are excluded. Administration pages and APIs require membership in `DOMAIN_ADMINS_SID`. The browser does not use NTLM/SPNEGO or Kerberos negotiation.
- HTTPS certificates are requested from a configured local Smallstep CA and renewed automatically. Pre-issued certificate files are also supported.
- Optional remote backups are configured in the admin UI, including destination, scheduling and full-data encryption.
- Private home creation skips well-known/service accounts by default (including `krbtgt`, `msol_*`, `FileShare_ServiceAcc`).
- Reconciliation is executed:
  - once on startup
  - every 5 minutes via cron
- Backup is executed:
  - manually through the Domain Admin web UI or CLI
  - daily at the configured UTC hour when automatic backups are enabled in the UI

## File Search and PDF Recognition

Users sign in at `/` with their existing AD credentials using `username`, `DOMAIN\username`, or `username@domain`. Domain-qualified names accept the configured AD DNS domain/realm; the short NetBIOS domain is accepted only with the `DOMAIN\username` spelling. The file view provides live search by filename and content, folder and file-type filters, grid/list views, previews, and downloads of the original files. Grid and list entries show file metadata without extracted content snippets. Only Domain Admins see the administration link and can use management pages and APIs under `/admin/...`; old administration URLs redirect there. Administrative APIs are under `/admin/api/...`, while sign-in, session, and document endpoints remain under `/api/...`. This upgrade expires existing web sessions.

The catalog includes active Data folders and each user's own Private folder. Every search, detail, preview, and download request checks current individual folder permissions. Revoking access or archiving a folder takes effect without waiting for reindexing. Domain Admins can see all active Data folders, but the user file view still shows only their own Private folder. Archived folders, recycle repositories, FSLogix profiles, symlinks, nested mounts, and special files are excluded. `Thumbs.db` (case-insensitive) and Office lock files whose names start with `~$` are omitted from results, counts and file-type filters in both Data and Private folders. Upgrades remove their existing catalog entries without deleting original files. Private files additionally require ownership and read/traverse permissions for the signed-in user's mapped Unix identity.

Linux filesystem events update the filename catalog as files change, with periodic scans recovering missed events. Text extraction and OCR run through a persistent background queue; files become searchable by filename before content extraction finishes. Search updates while typing, and open views refresh every two seconds to show completed extraction. Full-text queries match word prefixes and ignore accents; filename-only queries also match substrings.

Search stays in SQLite. FTS5 indexes text together with folder and file-type tokens; a compact character index also covers filename substrings and one- or two-character searches. Composite B-tree indexes cover folder/type filters and the UI's name, newest-first and oldest-first sorting. Pagination uses filter-bound cursors. Name and date sorting seek into their B-tree indexes; relevance uses FTS5's native ordered stream so ongoing OCR updates cannot invalidate a saved score threshold. Counts, file-type options and queue progress use incrementally maintained summaries. Broad text searches show a lower bound rather than delay results for an exact count. Large Private folders use bounded, current permission checks for facets and page candidates; their totals may also be lower bounds. Original files are checked before an item is returned, and current permissions are checked again for previews and downloads.

The first start after this upgrade rebuilds the derived search indexes and summaries once. It preserves document IDs, previews, OCR jobs, pause state, permissions and original files. `python3 scripts/benchmark-document-search --rows 2000000` creates an isolated synthetic catalog and measures 64 combinations of search scope, sorting and folder/type filters plus deep cursor pages for metadata and relevance ordering. It uses a small original-file fixture rather than creating two million physical files. `--database /tmp/adfs-search-benchmark.db` retains that disposable catalog for repeat runs.

Content search indexes only PDFs, Word documents (`docx`, `odt`) and PowerPoint presentations (`pptx`, `odp`). All file types remain searchable by filename, including text, Markdown, spreadsheets and images. Existing extracted content from excluded types is removed from the derived search index on upgrade; original files and filename entries remain intact. PDFs and common images receive a first-page/image thumbnail. PDFs open in a fullscreen dialog with the locally bundled Mozilla PDF.js viewer, including page navigation, zoom, thumbnails and search within native PDF text. PDF loading and byte-range requests check current folder access. Legacy binary Office formats (`doc`, `ppt`) remain searchable by filename. Extracted text is limited to 2 MiB per file; encrypted, damaged, or oversized documents may have no searchable content.

Only PDF pages that themselves contain raster images and little extracted text are queued for local OCR using Poppler and Tesseract, with German and English enabled by default. Search OCR renders those pages at 300 DPI, capped at 3500 pixels on the longest side, instead of inheriting high DPI from embedded logos or rebuilding an OCR PDF. Each render and recognition step has a 30-second timeout. Photos can still require a recognition attempt to establish whether they contain text; text-free pages finish without adding search content. Native text remains searchable while OCR is pending. OCR text is used for search. No file type displays a separate extracted document-text panel in its dialog. The PDF viewer displays the original PDF. Downloads always return the original file. No OCR replacement or separate OCR PDF is published. Failed jobs retry with backoff, and pending work survives restarts.

Parsers run as an unprivileged service account on temporary copies, with filesystem/network restrictions and resource limits. This requires a Linux kernel with Landlock enabled (Linux 5.13 or newer) on x86-64 or ARM64. If isolation is unavailable, extraction fails closed while filename search remains available; the worker logs the reason. OCR needs no external service or additional container capabilities.

The derived index and previews live in `/state/documents` (`DOCUMENT_STATE_ROOT` override), separate from the managed-access database. The directory is accessible only to the service. Backups retain all original files and access records, and omit this rebuildable cache. Restoring a backup rebuilds the catalog automatically. Allow space for extracted text, previews, and temporary OCR work; the first indexing pass runs asynchronously.

Domain Admins monitor the worker at `/admin/documents`: current file and phase, completed/total files, text/OCR queues, retries, heartbeat, last catalog scan, and recent activity. Pause and resume controls stop both catalog updates and extraction. Pausing interrupts an active parser and its child processes, discards its temporary workspace, and keeps the original queue phase for resumption. Existing indexed files remain searchable subject to current access rules. The pause flag survives container restarts. Control events record the administrator in the document activity history; status and control APIs are restricted to administrators. This derived worker history and its pause flag are omitted with the document cache from backups.

| Variable | Default | Purpose |
| --- | --- | --- |
| `DOCUMENT_SCAN_SECONDS` | `30` | Recovery scan interval; filesystem events handle intervening changes |
| `DOCUMENT_OCR_LANGUAGE` | `deu+eng` | Installed Tesseract languages used for OCR |
| `DOCUMENT_OCR_TIMEOUT_SECONDS` | `600` | Maximum runtime for an OCR job |
| `DOCUMENT_OCR_DPI` | `300` | OCR render resolution (150–400 DPI), subject to the pixel cap |
| `DOCUMENT_OCR_MAX_DIMENSION` | `3500` | Maximum OCR image width/height (1500–5000 pixels); originals are unchanged |
| `DOCUMENT_OCR_PAGE_TIMEOUT_SECONDS` | `30` | Maximum runtime per page render or recognition step (5–120 seconds) |
| `DOCUMENT_MAX_FILE_MB` | `512` | Largest file copied for extraction; larger files use filename search |
| `DOCUMENT_MAX_PDF_PAGES` | `500` | Maximum PDF page count for extraction |

These settings are configured under Dokumentindex und OCR at `/admin/settings`. Their internal names below also identify imported legacy settings.

## Shared SQLite State Database

The default database path is `/state/shares.db`; `STATE_DB_PATH` can override it. `SHARE_DB_PATH` remains a backward-compatible fallback.

The database contains:

- `shares`: managed folder lifecycle and ACL reconciliation state;
- `access_users`, `folder_permissions`, `access_settings`, and `access_changes`: managed access rules, cached AD identities, migration state, and administrative change history;
- `audit_events`: normalized read, write, move, and delete events;
- `audit_sources`: Samba log inode/offset checkpoints;
- `audit_event_dedup`: bounded, persistent fingerprints for restart-safe main-read and FSLogix-event deduplication;
- `audit_daily_totals`, `audit_daily_counts`, and `audit_daily_facets`: compact materialized metadata for fast activity counts and filters;
- `audit_paths`, `audit_paths_fts`, and `audit_path_events`: deduplicated trigram path search with an incrementally maintained event mapping;
- `audit_rollup_state`: bounded legacy-event backfill progress;
- `web_cache`: cached storage scan results.

Activity pages use UTC epoch seconds, keyset pagination, and compact indexes for time, scalar filters, and selective substring path searches. Exact scalar-filter counts and facets read the daily rollups instead of scanning raw events. WAL mode allows the collector, reconciler, scanner, and read-only web requests to operate concurrently.

Standard SQLite does not provide transparent general-purpose compression, so this project deliberately does not depend on a non-core compression VFS. Structured columns avoid repeated JSON field names and make indexed queries much cheaper; the state volume still needs capacity for retained activity.

## Activity Database

Samba emits selected high-level `full_audit` operations for Private, Data, and FSLogix, and the collector stores them durably:

- it tails every `/var/log/samba/log.*` source and stores inode/byte offsets transactionally in `audit_sources`, so source progress and inserted events commit together;
- each event records a UTC timestamp, user, client address/name, share, result, path, and one of `read`, `write`, `move`, or `delete`;
- directory listings, sessions, metadata access, file-open/create noise, and all other VFS operations are discarded; users ending in a configured `AUDIT_SKIP_USER_SUFFIXES` value are also discarded;
- FSLogix profile-container events are retained and queried through their own partial indexes, API route, and UI log instead of appearing in the main activity stream;
- identical main-stream reads and identical FSLogix events within the same UTC second are collapsed regardless of intervening events, log source, or collector polling cycle; Data/Private writes remain distinct, and the 48-hour fingerprint window can be tuned with `AUDIT_DEDUP_WINDOW_SECONDS`;
- activity pages read only `limit + 1` indexed rows and use a stable time/id cursor;
- exact counts for date, user, share, action, and result filters and all facet lists come from daily rollups;
- selective substring path searches use the deduplicated trigram index and skip an expensive exact count while more pages exist;
- while a legacy backfill is running, pages return immediately without raw-table count or facet scans and expose indexing progress;
- collector inserts and rollup updates are batched in one transaction;
- no activity retention deletion is performed.

Collection starts even when the web UI is disabled. Existing databases remain queryable while the collector backfills rollups, path IDs, path-event mappings, and recent main-read and FSLogix-event deduplication in bounded chunks after prioritizing each live append. On the first collector start after the legacy archive migration, recognized daily `.jsonl`/`.jsonl.gz` files and the old collector state file under `/state/audit` are deleted without import. Existing raw Samba log content is then processed using the current action, suffix, and deduplication policy.
