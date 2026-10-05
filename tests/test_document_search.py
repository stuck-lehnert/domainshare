import os
from pathlib import Path
import sqlite3
import unittest
from unittest import mock

from app import document_search, documents
from tests.test_documents import DocumentFixture, IDENTITY


class SearchPlanTests(DocumentFixture):
    def legacy_catalog(self):
        for row in self.conn.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='documents'").fetchall():
            self.conn.execute('DROP TRIGGER ' + row['name'])
        for row in self.conn.execute("SELECT name FROM sqlite_master WHERE type='index' AND (name LIKE 'document_search_%' OR name LIKE 'document_global_%')").fetchall():
            self.conn.execute('DROP INDEX ' + row['name'])
        self.conn.execute('DROP TABLE document_fts')
        self.conn.execute('DROP TABLE document_names_fts')
        self.conn.execute('DROP TABLE document_counts')
        self.conn.execute('DROP VIEW document_search_content')
        self.conn.execute("CREATE VIRTUAL TABLE document_fts USING fts5(name,path,body,content='documents',content_rowid='rowid',tokenize='unicode61 remove_diacritics 2',prefix='2 3 4')")
        self.conn.execute("INSERT INTO document_fts(document_fts) VALUES('rebuild')")
        self.conn.execute('PRAGMA user_version=2')
        self.conn.commit()

    def test_genuine_version_two_catalog_migrates_without_changing_documents_or_worker(self):
        documents.control_worker(self.conn, 'pause', 'admin')
        before = [tuple(row) for row in self.conn.execute('SELECT * FROM documents ORDER BY id')]
        originals = [(path, path.read_bytes(), path.stat().st_ino) for path in self.data.rglob('*') if path.is_file()]
        self.legacy_catalog()
        documents.ensure_schema(self.conn)
        self.assertEqual(before, [tuple(row) for row in self.conn.execute('SELECT * FROM documents ORDER BY id')])
        self.assertTrue(documents.worker_paused(self.conn))
        self.assertEqual(self.find({'type': ['docx']})['total'], 1)
        self.assertEqual(self.find({'q': ['ast'], 'scope': ['name']})['total'], 1)
        self.assertEqual(self.find({'q': ['Umsatz'], 'scope': ['content']})['total'], 1)
        for path, content, inode in originals:
            self.assertEqual((path.read_bytes(), path.stat().st_ino), (content, inode))

    def test_failed_derived_index_rebuild_rolls_back_and_can_be_retried(self):
        self.legacy_catalog()
        before = [tuple(row) for row in self.conn.execute('SELECT * FROM documents ORDER BY id')]
        with mock.patch.object(document_search, 'name_terms', side_effect=RuntimeError('simulated interrupted build')):
            with self.assertRaises(sqlite3.OperationalError):
                documents.ensure_schema(self.conn)
        self.assertEqual(self.conn.execute('PRAGMA user_version').fetchone()[0], 2)
        self.assertEqual([row['name'] for row in self.conn.execute('PRAGMA table_info(document_fts)')], ['name', 'path', 'body'])
        self.assertEqual(before, [tuple(row) for row in self.conn.execute('SELECT * FROM documents ORDER BY id')])
        documents.ensure_schema(self.conn)
        self.assertEqual(self.find({'q': ['Umsatz'], 'scope': ['content']})['total'], 1)

    def test_folder_type_and_sort_plans_seek_without_a_temporary_sort(self):
        visible = documents.SEARCHABLE_NAME_SQL.format(name='d.name')
        for sort, order, primary in (('recent', 'modified DESC,id DESC', 'modified'),
                                      ('oldest', 'modified,id', 'modified'),
                                      ('name', 'name COLLATE NOCASE,id', 'name COLLATE NOCASE')):
            for typed in (False, True):
                with self.subTest(sort=sort, typed=typed):
                    index = 'document_search_' + sort + ('_type' if typed else '')
                    where = 'source_id=? AND ' + visible
                    values = ['data:' + self.folder_ids['Finance']]
                    if typed:
                        where += ' AND extension=?'
                        values.append('.docx')
                    op = '<' if sort == 'recent' else '>'
                    where += f' AND ({primary},id) {op} (?,?)'
                    values += ['a' if sort == 'name' else 0, '0' * 32]
                    if sort == 'name':
                        where += ' AND name COLLATE NOCASE>=?'
                        values += ['a']
                    plan = ' '.join(row['detail'] for row in self.conn.execute(
                        f'EXPLAIN QUERY PLAN SELECT id FROM documents d INDEXED BY {index} WHERE {where} ORDER BY {order} LIMIT 40', values))
                    self.assertIn('SEARCH', plan)
                    self.assertIn(index, plan)
                    self.assertNotIn('TEMP B-TREE', plan)
                    bounds = ('name>?',) if sort == 'name' else ('(modified,id)<(?,?)', 'modified<?') if sort == 'recent' else ('(modified,id)>(?,?)', 'modified>?')
                    self.assertTrue(any(bound in plan for bound in bounds), plan)

    def test_counts_and_name_postings_follow_rename_type_state_and_delete(self):
        row = self.document('forecast.docx')
        source = row['source_id']
        self.conn.execute("UPDATE documents SET name='renamed.pdf',extension='.pdf',state='ocr' WHERE id=?", (row['id'],))
        self.conn.commit()
        self.assertEqual(self.find({'q': ['renamed'], 'scope': ['name']})['total'], 1)
        self.assertEqual(self.find({'q': ['forecast'], 'scope': ['name']})['total'], 0)
        self.assertEqual([tuple(value) for value in self.conn.execute('SELECT extension,state,amount FROM document_counts WHERE source_id=?', (source,))], [('.pdf', 'ocr', 1)])
        self.conn.execute('DELETE FROM documents WHERE id=?', (row['id'],))
        self.conn.commit()
        self.assertEqual(self.conn.execute('SELECT count(*) FROM document_counts WHERE source_id=?', (source,)).fetchone()[0], 0)
        self.assertEqual(self.conn.execute("SELECT count(*) FROM document_names_fts WHERE document_names_fts MATCH ?", (document_search.key('ren', 'g'),)).fetchone()[0], 0)

    def test_ocr_updates_do_not_rewrite_filename_postings(self):
        terms = mock.Mock(wraps=document_search.name_terms)
        self.conn.create_function('document_name_terms', 1, terms, deterministic=True)
        self.conn.execute("UPDATE documents SET body='new OCR text',state='ready' WHERE name='forecast.docx'")
        self.conn.commit()
        terms.assert_not_called()

    def test_browsing_has_no_full_count_distinct_scan_or_private_catalog_walk(self):
        statements = []
        self.conn.set_trace_callback(statements.append)
        self.find()
        self.conn.set_trace_callback(None)
        queries = '\n'.join(statements).lower()
        self.assertNotIn('count(*) from documents', queries)
        self.assertNotIn('select distinct extension from documents', queries)
        self.assertNotIn('readable_private', queries)
        self.assertIn('from document_counts', queries)

    def test_cursor_is_bound_to_filters_and_rejects_malformed_input(self):
        signature = document_search.cursor_scope('', 'all', '', '', 'recent')
        cursor = document_search.encode_cursor(signature, [1, 1, '0' * 32], 40)
        for params in ({'cursor': [cursor], 'type': ['pdf']}, {'cursor': ['***']},
                       {'cursor': [document_search.encode_cursor(signature, [{}, 1, 'x'], 1)]}, {'offset': ['2000000']}):
            with self.subTest(params=params), self.assertRaises(ValueError):
                self.find(params)


class SearchPaginationTests(DocumentFixture):
    def setUp(self):
        super().setUp()
        for index in range(620):
            self.write(self.data / 'Finance' / f'report_{index:04}.pdf', 'COMMON742 LATE742' if index >= 600 else 'COMMON742')
        self.scan()
        rows = self.conn.execute("SELECT id,path FROM documents WHERE name LIKE 'report_%'").fetchall()
        for index, row in enumerate(rows):
            self.conn.execute("UPDATE documents SET body=?,state='ready',modified=? WHERE id=?",
                              ('COMMON742 LATE742' if index >= 600 else 'COMMON742', index // 3, row['id']))
        self.conn.commit()

    def test_all_sorts_and_scopes_paginate_without_duplicates_or_missing_matches(self):
        for scope, query in (('all', 'COMMON742'), ('content', 'COMMON742'), ('name', 'report_'), ('name', 'r')):
            for sort in ('recent', 'oldest', 'name', 'relevance'):
                with self.subTest(scope=scope, sort=sort):
                    params = {'scope': [scope], 'q': [query], 'sort': [sort], 'type': ['pdf'], 'limit': ['100']}
                    items = []
                    for page in range(10):
                        result = self.find(params)
                        items.extend(result['items'])
                        if not result['hasMore']:
                            break
                        self.assertTrue(result['nextCursor'])
                        params['cursor'] = [result['nextCursor']]
                    self.assertEqual(len(items), 620)
                    self.assertEqual(len({row['id'] for row in items}), 620)
                    effective = 'recent' if sort == 'relevance' and scope == 'name' else sort
                    if effective == 'name':
                        self.assertEqual([row['name'] for row in items], sorted(row['name'] for row in items))
                    elif effective in ('recent', 'oldest'):
                        self.assertEqual([row['modified'] for row in items], sorted((row['modified'] for row in items), reverse=effective == 'recent'))

    def test_broad_search_uses_a_lower_bound_and_selective_search_is_exact(self):
        broad = self.find({'q': ['COMMON742'], 'scope': ['content'], 'type': ['pdf']})
        self.assertFalse(broad['totalExact'])
        self.assertEqual((len(broad['items']), broad['total'], broad['hasMore']), (40, 41, True))
        narrow = self.find({'q': ['LATE742'], 'scope': ['content'], 'type': ['pdf']})
        self.assertTrue(narrow['totalExact'])
        self.assertEqual(narrow['total'], 20)
        self.assertFalse(narrow['hasMore'])
        browse = self.find({'type': ['pdf']})
        self.assertEqual((browse['totalExact'], browse['total']), (True, 620))

    def test_relevance_pagination_survives_ocr_changes_to_corpus_statistics(self):
        params = {'q': ['report'], 'sort': ['relevance'], 'type': ['pdf']}
        first = self.find(params)
        self.assertEqual(len(first['items']), 40)
        self.conn.execute("UPDATE documents SET body=? WHERE name='own.odt'", ('unrelated OCR text ' * 1000,))
        self.conn.commit()
        params['cursor'] = [first['nextCursor']]
        second = self.find(params)
        self.assertEqual(len(second['items']), 40)

    def test_valid_cursor_can_seek_beyond_the_legacy_offset_limit(self):
        params = {'type': ['pdf'], 'limit': ['40']}
        first = self.find(params)
        params.update(cursor=[first['nextCursor']], offset=['2000000'])
        second = self.find(params)
        self.assertEqual(len(second['items']), 40)
        self.assertFalse({row['id'] for row in first['items']} & {row['id'] for row in second['items']})

    def test_relevance_pagination_advances_past_denied_private_candidates(self):
        for index in range(75):
            self.write(self.private / 'alice' / f'private_rank_{index:04}.pdf', 'original')
        self.scan()
        self.conn.execute("UPDATE documents SET body='PRIVATEPAGING742',state='ready' WHERE name LIKE 'private_rank_%'")
        self.conn.commit()
        params = {'q': ['PRIVATEPAGING742'], 'scope': ['content'], 'sort': ['relevance'], 'limit': ['100']}
        initial = self.find(params)
        self.assertEqual(len(initial['items']), 75)
        for item in initial['items'][:5]:
            (self.private / 'alice' / item['path']).chmod(0)
        params['limit'] = ['40']
        first = self.find(params)
        params['cursor'] = [first['nextCursor']]
        second = self.find(params)
        self.assertEqual((len(first['items']), len(second['items'])), (40, 30))
        self.assertFalse({row['id'] for row in first['items']} & {row['id'] for row in second['items']})

    def test_private_checks_are_bounded_even_for_a_large_catalog_and_hide_denied_files(self):
        source = self.conn.execute("SELECT * FROM document_sources WHERE id='private:alice'").fetchone()
        for index in range(620):
            self.write(self.private / 'alice' / f'private_{index:04}.pdf', 'original')
        documents.walk_source(self.conn, source)
        (self.private / 'alice' / 'private_0619.pdf').chmod(0)
        with mock.patch.object(documents, 'private_readable', wraps=documents.private_readable) as check:
            result = self.find({'source': ['private:alice']})
        self.assertLess(check.call_count, 200)
        self.assertFalse(result['totalExact'])
        self.assertEqual(len(result['items']), 40)
        self.assertNotIn('private_0619.pdf', {row['name'] for row in result['items']})
        (self.private / 'alice' / 'own.odt').chmod(0)
        self.assertNotIn('odt', self.find({'source': ['private:alice']})['types'])


if __name__ == '__main__':
    unittest.main()
