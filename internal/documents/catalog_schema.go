package documents

// The catalog keeps the Python v3 on-disk schema, including FTS5, indexes,
// and triggers. The native opener only rebuilds derived state on older versions.
const baseCatalogDDL = `
CREATE TABLE IF NOT EXISTS document_sources (
            id TEXT PRIMARY KEY, kind TEXT NOT NULL, label TEXT NOT NULL,
            root TEXT NOT NULL, owner_sid TEXT NOT NULL DEFAULT ''
        );

CREATE TABLE IF NOT EXISTS documents (
            rowid INTEGER PRIMARY KEY, id TEXT NOT NULL UNIQUE,
            source_id TEXT NOT NULL REFERENCES document_sources(id) ON DELETE CASCADE,
            path TEXT NOT NULL, name TEXT NOT NULL, extension TEXT NOT NULL,
            size INTEGER NOT NULL, modified REAL NOT NULL, fingerprint TEXT NOT NULL,
            body TEXT NOT NULL DEFAULT '', state TEXT NOT NULL DEFAULT 'pending',
            preview TEXT NOT NULL DEFAULT '', pages INTEGER NOT NULL DEFAULT 0,
            attempts INTEGER NOT NULL DEFAULT 0, retry_at REAL NOT NULL DEFAULT 0,
            indexed_at REAL NOT NULL DEFAULT 0, seen INTEGER NOT NULL DEFAULT 0,
            UNIQUE(source_id,path)
        );

CREATE INDEX IF NOT EXISTS document_queue ON documents(state,retry_at);

CREATE INDEX IF NOT EXISTS document_source ON documents(source_id,modified);

CREATE TABLE IF NOT EXISTS document_worker (
            id INTEGER PRIMARY KEY CHECK(id=1), paused INTEGER NOT NULL DEFAULT 0,
            heartbeat REAL NOT NULL DEFAULT 0, state TEXT NOT NULL DEFAULT 'idle',
            current_id TEXT NOT NULL DEFAULT '', processed INTEGER NOT NULL DEFAULT 0,
            scanning INTEGER NOT NULL DEFAULT 0, last_scan REAL NOT NULL DEFAULT 0
        );

CREATE TABLE IF NOT EXISTS document_activity (
            id INTEGER PRIMARY KEY, timestamp REAL NOT NULL, action TEXT NOT NULL,
            path TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT '',
            actor TEXT NOT NULL DEFAULT '', message TEXT NOT NULL DEFAULT ''
        );
`

const searchCatalogDDL = `
CREATE VIEW document_search_content AS
            SELECT rowid,name,path,CASE WHEN extension IN ('.docx','.odp','.odt','.pdf','.pptx') THEN body ELSE '' END body,
                   's'||lower(hex(source_id)) source_key, 't'||lower(hex(extension)) type_key
            FROM documents WHERE lower(name) <> 'thumbs.db' AND name NOT GLOB '~$*';

CREATE VIRTUAL TABLE document_fts USING fts5(
            name,path,body,source_key,type_key,content='document_search_content',content_rowid='rowid',
            tokenize='unicode61 remove_diacritics 2',prefix='2 3 4');

CREATE VIRTUAL TABLE document_names_fts USING fts5(
            terms,source_key,type_key,content='',tokenize='ascii',detail='none',columnsize=0);

CREATE TABLE document_counts (
            source_id TEXT NOT NULL, extension TEXT NOT NULL, state TEXT NOT NULL,
            amount INTEGER NOT NULL, PRIMARY KEY(source_id,extension,state)) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS document_search_recent
                                 ON documents(source_id,modified DESC,id DESC) WHERE lower(name) <> 'thumbs.db' AND name NOT GLOB '~$*';

CREATE INDEX IF NOT EXISTS document_search_recent_type
                                 ON documents(source_id,extension,modified DESC,id DESC) WHERE lower(name) <> 'thumbs.db' AND name NOT GLOB '~$*';

CREATE INDEX IF NOT EXISTS document_search_oldest
                                 ON documents(source_id,modified,id) WHERE lower(name) <> 'thumbs.db' AND name NOT GLOB '~$*';

CREATE INDEX IF NOT EXISTS document_search_oldest_type
                                 ON documents(source_id,extension,modified,id) WHERE lower(name) <> 'thumbs.db' AND name NOT GLOB '~$*';

CREATE INDEX IF NOT EXISTS document_search_name
                                 ON documents(source_id,name COLLATE NOCASE,id) WHERE lower(name) <> 'thumbs.db' AND name NOT GLOB '~$*';

CREATE INDEX IF NOT EXISTS document_search_name_type
                                 ON documents(source_id,extension,name COLLATE NOCASE,id) WHERE lower(name) <> 'thumbs.db' AND name NOT GLOB '~$*';

CREATE INDEX IF NOT EXISTS document_global_recent
                ON documents(modified DESC,id DESC) WHERE lower(name) <> 'thumbs.db' AND name NOT GLOB '~$*';

CREATE INDEX IF NOT EXISTS document_global_recent_type
                ON documents(extension,modified DESC,id DESC) WHERE lower(name) <> 'thumbs.db' AND name NOT GLOB '~$*';

CREATE INDEX IF NOT EXISTS document_global_oldest
                ON documents(modified,id) WHERE lower(name) <> 'thumbs.db' AND name NOT GLOB '~$*';

CREATE INDEX IF NOT EXISTS document_global_oldest_type
                ON documents(extension,modified,id) WHERE lower(name) <> 'thumbs.db' AND name NOT GLOB '~$*';

CREATE INDEX IF NOT EXISTS document_global_name
                ON documents(name COLLATE NOCASE,id) WHERE lower(name) <> 'thumbs.db' AND name NOT GLOB '~$*';

CREATE INDEX IF NOT EXISTS document_global_name_type
                ON documents(extension,name COLLATE NOCASE,id) WHERE lower(name) <> 'thumbs.db' AND name NOT GLOB '~$*';

CREATE TRIGGER document_insert AFTER INSERT ON documents BEGIN
                INSERT INTO document_fts(rowid,name,path,body,source_key,type_key) SELECT new.rowid,new.name,new.path,CASE WHEN new.extension IN ('.docx','.odp','.odt','.pdf','.pptx') THEN new.body ELSE '' END,'s'||lower(hex(new.source_id)),'t'||lower(hex(new.extension)) WHERE lower(new.name) <> 'thumbs.db' AND new.name NOT GLOB '~$*';
             END;

CREATE TRIGGER document_delete AFTER DELETE ON documents BEGIN
                    INSERT INTO document_fts(document_fts,rowid,name,path,body,source_key,type_key)
                        SELECT 'delete',old.rowid,old.name,old.path,CASE WHEN old.extension IN ('.docx','.odp','.odt','.pdf','.pptx') THEN old.body ELSE '' END,'s'||lower(hex(old.source_id)),'t'||lower(hex(old.extension)) WHERE lower(old.name) <> 'thumbs.db' AND old.name NOT GLOB '~$*';
                 END;

CREATE TRIGGER document_update AFTER UPDATE OF name,path,body,source_id,extension ON documents BEGIN
                    INSERT INTO document_fts(document_fts,rowid,name,path,body,source_key,type_key)
                        SELECT 'delete',old.rowid,old.name,old.path,CASE WHEN old.extension IN ('.docx','.odp','.odt','.pdf','.pptx') THEN old.body ELSE '' END,'s'||lower(hex(old.source_id)),'t'||lower(hex(old.extension)) WHERE lower(old.name) <> 'thumbs.db' AND old.name NOT GLOB '~$*';

                INSERT INTO document_fts(rowid,name,path,body,source_key,type_key) SELECT new.rowid,new.name,new.path,CASE WHEN new.extension IN ('.docx','.odp','.odt','.pdf','.pptx') THEN new.body ELSE '' END,'s'||lower(hex(new.source_id)),'t'||lower(hex(new.extension)) WHERE lower(new.name) <> 'thumbs.db' AND new.name NOT GLOB '~$*';
             END;

CREATE TRIGGER document_name_insert AFTER INSERT ON documents BEGIN
                INSERT INTO document_names_fts(rowid,terms,source_key,type_key) SELECT new.rowid,document_name_terms(new.name),'s'||lower(hex(new.source_id)),'t'||lower(hex(new.extension)) WHERE lower(new.name) <> 'thumbs.db' AND new.name NOT GLOB '~$*';
             END;

CREATE TRIGGER document_name_delete AFTER DELETE ON documents BEGIN
                    INSERT INTO document_names_fts(document_names_fts,rowid,terms,source_key,type_key)
                        SELECT 'delete',old.rowid,document_name_terms(old.name),'s'||lower(hex(old.source_id)),'t'||lower(hex(old.extension)) WHERE lower(old.name) <> 'thumbs.db' AND old.name NOT GLOB '~$*';
                 END;

CREATE TRIGGER document_name_update AFTER UPDATE OF name,source_id,extension ON documents BEGIN
                    INSERT INTO document_names_fts(document_names_fts,rowid,terms,source_key,type_key)
                        SELECT 'delete',old.rowid,document_name_terms(old.name),'s'||lower(hex(old.source_id)),'t'||lower(hex(old.extension)) WHERE lower(old.name) <> 'thumbs.db' AND old.name NOT GLOB '~$*';

                INSERT INTO document_names_fts(rowid,terms,source_key,type_key) SELECT new.rowid,document_name_terms(new.name),'s'||lower(hex(new.source_id)),'t'||lower(hex(new.extension)) WHERE lower(new.name) <> 'thumbs.db' AND new.name NOT GLOB '~$*';
             END;

CREATE TRIGGER document_count_insert AFTER INSERT ON documents BEGIN INSERT INTO document_counts(source_id,extension,state,amount)
                    SELECT new.source_id,new.extension,new.state,1 WHERE lower(new.name) <> 'thumbs.db' AND new.name NOT GLOB '~$*'
                    ON CONFLICT(source_id,extension,state) DO UPDATE SET amount=amount+excluded.amount;
                    DELETE FROM document_counts WHERE source_id=new.source_id
                        AND extension=new.extension AND state=new.state AND amount=0; END;

CREATE TRIGGER document_count_delete AFTER DELETE ON documents BEGIN INSERT INTO document_counts(source_id,extension,state,amount)
                    SELECT old.source_id,old.extension,old.state,-1 WHERE lower(old.name) <> 'thumbs.db' AND old.name NOT GLOB '~$*'
                    ON CONFLICT(source_id,extension,state) DO UPDATE SET amount=amount+excluded.amount;
                    DELETE FROM document_counts WHERE source_id=old.source_id
                        AND extension=old.extension AND state=old.state AND amount=0; END;

CREATE TRIGGER document_count_update AFTER UPDATE OF name,source_id,extension,state ON documents BEGIN INSERT INTO document_counts(source_id,extension,state,amount)
                    SELECT old.source_id,old.extension,old.state,-1 WHERE lower(old.name) <> 'thumbs.db' AND old.name NOT GLOB '~$*'
                    ON CONFLICT(source_id,extension,state) DO UPDATE SET amount=amount+excluded.amount;
                    DELETE FROM document_counts WHERE source_id=old.source_id
                        AND extension=old.extension AND state=old.state AND amount=0;INSERT INTO document_counts(source_id,extension,state,amount)
                    SELECT new.source_id,new.extension,new.state,1 WHERE lower(new.name) <> 'thumbs.db' AND new.name NOT GLOB '~$*'
                    ON CONFLICT(source_id,extension,state) DO UPDATE SET amount=amount+excluded.amount;
                    DELETE FROM document_counts WHERE source_id=new.source_id
                        AND extension=new.extension AND state=new.state AND amount=0; END;
`
