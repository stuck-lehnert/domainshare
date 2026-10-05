import contextlib
import http.client
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from app import access_control as access, document_index, documents, extract_document, reconcile_shares as directory, web_ui

ALICE = 'S-1-5-21-1-2-3-1100'
BOB = 'S-1-5-21-1-2-3-1101'
ADMIN = 'S-1-5-21-1-2-3-1102'
IDENTITY = {'sub': 'EXAMPLE\\alice', 'sid': ALICE, 'uid': os.getuid(), 'role': 'user'}


class DocumentFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.data = root / 'data'
        self.private = root / 'private'
        self.archive = root / 'archive'
        self.state = root / 'documents'
        for path in (self.data, self.private, self.archive):
            path.mkdir()
        for target, field, value in [(directory,'DB_PATH',str(root/'state.db')),
                                     (directory,'GROUP_ROOT',str(self.data)),
                                     (directory,'GROUP_ARCHIVE_ROOT',str(self.archive)),
                                     (directory,'PRIVATE_ROOT',str(self.private)),
                                     (documents,'SEARCH_ROOT',str(self.state)),
                                     (documents,'SEARCH_DB',str(self.state/'search.db'))]:
            patch = mock.patch.object(target,field,value)
            patch.start()
            self.addCleanup(patch.stop)
        self.policy = directory.open_db()
        self.addCleanup(self.policy.close)
        access.ensure_schema(self.policy)
        access.cache_users(self.policy, {ALICE:{'sam':'alice','name':'Alice'},BOB:{'sam':'bob','name':'Bob'},ADMIN:{'sam':'admin','name':'Admin'}})
        self.folder_ids = {}
        for name in ('Finance','Engineering'):
            path = self.data/name
            path.mkdir()
            self.folder_ids[name] = access.create_folder_record(self.policy,name,str(path))
        self.policy.executemany('INSERT INTO folder_permissions VALUES(?,?,?,?)',[
            (self.folder_ids['Finance'],'user',ALICE,1),(self.folder_ids['Engineering'],'user',BOB,3)])
        self.policy.commit()
        for name in ('alice','bob'):
            (self.private/name).mkdir()
        self.write(self.data/'Finance'/'forecast.docx','Forecast apple Umsatz München')
        self.write(self.data/'Engineering'/'secret.hidden','Classified secret ROBOT42')
        self.write(self.private/'alice'/'own.odt','Private personal ALICEONLY')
        self.write(self.private/'bob'/'other.odt','Private personal BOBONLY')
        self.conn = documents.connect()
        self.addCleanup(self.conn.close)
        documents.ensure_schema(self.conn)
        self.scan()
        # Native text extraction is independent of parsers; real parsers are covered by E2E.
        for row in self.conn.execute('SELECT * FROM documents').fetchall():
            source = self.conn.execute('SELECT * FROM document_sources WHERE id=?',(row['source_id'],)).fetchone()
            with documents.open_file(source['root'], row['path']) as (handle,_):
                body = handle.read().decode()
            self.conn.execute("UPDATE documents SET body=?,state='ready' WHERE id=?",(body,row['id']))
        self.conn.commit()

    def write(self,path,text):
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(text)

    def scan(self):
        sources,_ = document_index.update_sources(self.conn)
        for source in sources.values():
            documents.walk_source(self.conn,source)

    def find(self,params=None,identity=IDENTITY):
        return documents.search(self.conn,identity,params or {})

    def document(self,name):
        return dict(self.conn.execute('SELECT * FROM documents WHERE name=?',(name,)).fetchone())


class DocumentTests(DocumentFixture):
    def test_search_facets_counts_and_snippets_never_expose_other_users_or_hidden_folders(self):
        value = self.find()
        self.assertEqual(value['total'],2)
        self.assertEqual({row['name'] for row in value['items']},{'forecast.docx','own.odt'})
        self.assertEqual(value['types'],['docx','odt'])
        self.assertEqual({source['label'] for source in value['sources']},{'Finance','Private'})
        self.assertEqual(self.find({'q':['BOBONLY']})['total'],0)
        self.assertEqual(self.find({'q':['secret']})['total'],0)
        self.assertEqual(self.find({'source':['data:'+self.folder_ids['Engineering']]})['items'],[])

    def test_filename_content_unicode_prefix_and_safe_fts_queries(self):
        self.assertEqual(self.find({'q':['fore'],'scope':['name']})['total'],1)
        result = self.find({'q':['Umsatz Munchen'],'scope':['content']})
        self.assertEqual(result['total'],1)
        self.assertEqual(result['items'][0]['snippet'],'')
        self.assertEqual(self.find({'q':['forecast'],'scope':['content']})['total'],1)
        for query in ('"', '*', ':', '" OR NOT ()', 'x\x00y'):
            self.find({'q':[query]})

    def test_ocr_candidates_match_images_to_their_page_and_ignore_native_text_and_masks(self):
        body='Short cover\f'+'Native text '*30+'\fTiny footer\fNo text\f'
        images='page num type width height\n2 0 image 300 300\n3 1 image 500 500\n4 2 smask 500 500\n'
        self.assertEqual(extract_document.ocr_candidates(body,images,4),[3])
        self.assertEqual(extract_document.ocr_candidates(body,images,2),[])
        self.assertEqual(extract_document.ocr_candidates('Header\fNative text '+('word '*30)+'\f','2 0 image 100 100',2),[])

    def test_search_ocr_limits_render_size_and_time_and_does_not_rebuild_the_pdf(self):
        calls=[]
        def parser(args,timeout=120):
            calls.append((args,timeout))
            return ('Page 3 size: 595 x 842 pts\nPage 7 size: 144 x 288 pts' if args[0]=='pdfinfo' else
                    'Recognized page text' if args[0]=='tesseract' else '')
        config={'language':'deu+eng','ocr_dpi':300,'ocr_max_dimension':3500,'ocr_page_timeout':30}
        with mock.patch.object(extract_document,'command',side_effect=parser):
            body=extract_document.ocr_search_text(Path('input'),[3,7],config)
        self.assertEqual(body,'Recognized page text\nRecognized page text')
        self.assertEqual([args[0] for args,_ in calls],['pdfinfo','pdftoppm','tesseract','pdftoppm','tesseract'])
        for args,timeout in calls[1:]:
            self.assertEqual(timeout,30)
            if args[0]=='pdftoppm':
                self.assertLessEqual(int(args[args.index('-scale-to')+1]),3500)
                self.assertEqual(args[args.index('-r')+1],'300')
                self.assertEqual(args[args.index('-f')+1],args[args.index('-l')+1])
        self.assertEqual(calls[1][0][calls[1][0].index('-f')+1],'3')
        self.assertEqual(calls[3][0][calls[3][0].index('-f')+1],'7')
        self.assertEqual(calls[1][0][calls[1][0].index('-scale-to')+1],'3500')
        self.assertEqual(calls[3][0][calls[3][0].index('-scale-to')+1],'1200')

    def artifact_files(self):
        files=[]
        for root,name in ((self.data/'Finance','Thumbs.db'),(self.data/'Finance'/'Child','THUMBS.DB'),
                          (self.data/'Finance','~$report.docx'),(self.data/'Finance'/'Child','~$Slides.PPTX'),
                          (self.private/'alice','thumbs.Db'),(self.private/'alice','~$notes.odt')):
            path=root/name
            self.write(path,'IGNOREDARTIFACT742')
            files.append((path,path.read_bytes(),path.stat().st_ino))
        return files

    def seed_old_artifact_entries(self):
        files=self.artifact_files()
        with mock.patch.object(documents,'is_excluded_filename',return_value=False):
            self.scan()
        for path,_,_ in files:
            self.conn.execute("UPDATE documents SET body='IGNOREDARTIFACT742',state='pending' WHERE name=?",(path.name,))
        self.conn.commit()
        return files

    def test_cache_and_lock_files_are_never_cataloged_in_data_or_private(self):
        files=self.artifact_files()
        for name in ('Thumbs.db.docx','project-Thumbs.db','~notes.docx'):
            self.write(self.data/'Finance'/name,'ordinary file')
        self.scan()
        for path,original,inode in files:
            self.assertEqual(self.conn.execute('SELECT count(*) FROM documents WHERE name=?',(path.name,)).fetchone()[0],0)
            self.assertEqual(path.read_bytes(),original)
            self.assertEqual(path.stat().st_ino,inode)
        for name in ('Thumbs.db.docx','project-Thumbs.db','~notes.docx'):
            self.assertEqual(self.find({'q':[name],'scope':['name']})['total'],1)

    def test_stale_artifacts_never_affect_search_counts_facets_or_direct_access(self):
        self.seed_old_artifact_entries()
        result=self.find({'limit':['1']})
        self.assertEqual((result['total'],len(result['items']),result['hasMore'],result['types'],result['pending']),
                         (2,1,True,['docx','odt'],0))
        for scope in ('name','all','content'):
            for query in ('Thumbs','report','IGNOREDARTIFACT742'):
                self.assertEqual(self.find({'q':[query],'scope':[scope]})['total'],0)
        for row in self.conn.execute("SELECT id FROM documents WHERE name GLOB '~$*' OR lower(name)='thumbs.db'"):
            with self.assertRaises(FileNotFoundError):
                documents.detail(self.conn,IDENTITY,row['id'])
            for operation in (documents.download,documents.preview):
                with self.assertRaises(FileNotFoundError), operation(self.conn,IDENTITY,row['id']):
                    pass
        with mock.patch.object(document_index,'run_job') as job:
            while document_index.process_next(self.conn):
                pass
            job.assert_not_called()
        self.assertEqual(self.conn.execute('SELECT count(*) FROM documents').fetchone()[0],4)

    def test_upgrade_removes_old_artifacts_and_fts_without_changing_originals_or_pause(self):
        files=self.seed_old_artifact_entries()
        documents.control_worker(self.conn,'pause','admin')
        self.conn.execute('PRAGMA user_version=1')
        self.conn.commit()
        documents.ensure_schema(self.conn)
        self.assertTrue(documents.worker_paused(self.conn))
        self.assertEqual(self.conn.execute('SELECT count(*) FROM documents').fetchone()[0],4)
        self.assertEqual(self.conn.execute("SELECT count(*) FROM document_fts WHERE document_fts MATCH 'IGNOREDARTIFACT742'").fetchone()[0],0)
        self.assertEqual(self.find({'q':['Umsatz'],'scope':['content']})['total'],1)
        for path,original,inode in files:
            self.assertEqual(path.read_bytes(),original)
            self.assertEqual(path.stat().st_ino,inode)
        documents.ensure_schema(self.conn)
        self.assertEqual(self.conn.execute('PRAGMA user_version').fetchone()[0],3)

    def test_only_document_types_are_queued_for_content_and_all_types_keep_filename_search(self):
        for extension in ('.pdf','.docx','.pptx','.odt','.odp','.txt','.md','.csv','.xlsx','.ods','.html','.json','.bin'):
            self.write(self.data/'Finance'/('typed'+extension),'EXCLUDEDBODY742')
        self.scan()
        for extension in ('.pdf','.docx','.pptx','.odt','.odp'):
            self.assertEqual(self.document('typed'+extension)['state'],'pending')
        for extension in ('.txt','.md','.csv','.xlsx','.ods','.html','.json','.bin'):
            row=self.document('typed'+extension)
            self.assertEqual(row['state'],'name-only')
            self.assertEqual(row['body'],'')
            self.assertEqual(self.find({'q':['typed'+extension],'scope':['name']})['total'],1)
            self.assertEqual(self.find({'q':['typed'+extension]})['total'],1)
        self.assertEqual(self.find({'q':['EXCLUDEDBODY742'],'scope':['content']})['total'],0)

    def test_excluded_stale_content_cannot_match_all_or_content_search_or_leak_in_snippets(self):
        self.write(self.data/'Finance'/'legacy.xlsx','original spreadsheet bytes')
        self.scan()
        row=self.document('legacy.xlsx')
        self.conn.execute("UPDATE documents SET body='STALESPREADSHEET742',state='ready' WHERE id=?",(row['id'],))
        self.conn.commit()
        for scope in ('all','content'):
            self.assertEqual(self.find({'q':['STALESPREADSHEET742'],'scope':[scope]})['total'],0)
        result=self.find({'q':['legacy'],'scope':['all']})
        self.assertEqual(result['total'],1)
        self.assertEqual(result['items'][0]['snippet'],'')
        self.assertEqual(documents.detail(self.conn,IDENTITY,row['id'])['text'],'')
        self.assertEqual(next(item for item in self.find()['items'] if item['id']==row['id'])['snippet'],'')

    def test_upgrade_clears_excluded_fts_and_jobs_but_keeps_ids_originals_and_image_previews(self):
        files=[]
        for extension in ('.txt','.md','.csv','.xlsx','.ods','.png'):
            path=self.data/'Finance'/('upgrade'+extension)
            self.write(path,'original bytes '+extension)
            files.append((path,path.read_bytes(),path.stat().st_ino))
        self.scan()
        ids={self.document(path.name)['id'] for path,_,_ in files}
        for path,_,_ in files:
            row=self.document(path.name)
            self.conn.execute("UPDATE documents SET body='OLDINDEX742',state='failed',attempts=4,retry_at=9999999999,preview=?,pages=7 WHERE id=?", ('retained.jpg' if path.suffix=='.png' else '',row['id']))
        self.conn.execute('PRAGMA user_version=0')
        self.conn.commit()
        paused=documents.control_worker(self.conn,'pause','admin')
        self.assertTrue(paused['paused'])
        documents.ensure_schema(self.conn)
        self.assertTrue(documents.worker_paused(self.conn))
        self.assertEqual(ids,{self.document(path.name)['id'] for path,_,_ in files})
        for path,original,inode in files:
            row=self.document(path.name)
            self.assertEqual((row['body'],row['state'],row['attempts'],row['retry_at'],row['pages']),('','name-only',0,0,0))
            self.assertEqual(path.read_bytes(),original)
            self.assertEqual(path.stat().st_ino,inode)
            self.assertEqual(self.find({'q':[path.name],'scope':['name']})['total'],1)
        self.assertEqual(self.document('upgrade.png')['preview'],'retained.jpg')
        self.assertEqual(self.conn.execute("SELECT count(*) FROM document_fts WHERE document_fts MATCH 'body:OLDINDEX742'").fetchone()[0],0)
        self.assertEqual(self.find({'q':['Umsatz'],'scope':['content']})['total'],1)
        self.assertEqual(self.policy.execute('SELECT count(*) FROM folder_permissions').fetchone()[0],2)
        # Reopening a migrated database leaves completed previews untouched.
        documents.ensure_schema(self.conn)
        self.assertEqual(self.document('upgrade.png')['state'],'name-only')

    def test_extractor_rejects_excluded_content_and_preview_jobs_never_index_text(self):
        for extension in ('.txt','.md','.csv','.xlsx','.ods','.html','.json','.bin'):
            with self.assertRaises(ValueError):
                extract_document.extract({'extension':extension})
        self.write(self.data/'Finance'/'photo.png','image fixture')
        self.scan()
        with mock.patch.object(document_index,'run_job',return_value={'body':'UNWANTEDIMAGE742','preview':'photo.jpg','needsOcr':True}) as job:
            while document_index.process_next(self.conn):
                pass
        self.assertEqual(job.call_count,1)
        row=self.document('photo.png')
        self.assertEqual((row['state'],row['body'],row['preview']),('name-only','','photo.jpg'))
        self.assertEqual(self.find({'q':['UNWANTEDIMAGE742']})['total'],0)

    def test_preview_download_and_detail_reject_inaccessible_guessed_ids(self):
        for name in ('secret.hidden','other.odt'):
            row = self.document(name)
            for operation in (documents.detail,):
                with self.assertRaises(FileNotFoundError):
                    operation(self.conn,IDENTITY,row['id'])
            for operation in (documents.download,documents.preview):
                with self.assertRaises(FileNotFoundError), operation(self.conn,IDENTITY,row['id']):
                    pass

    def test_revoke_and_archive_apply_to_all_endpoints_without_reindexing(self):
        row = self.document('forecast.docx')
        with documents.download(self.conn,IDENTITY,row['id']) as (handle,_):
            self.assertIn(b'Umsatz',handle.read())
        self.policy.execute('UPDATE folder_permissions SET level=0 WHERE principalId=?',(ALICE,))
        self.policy.commit()
        self.assertEqual(self.find()['total'],1)
        with self.assertRaises(FileNotFoundError):
            documents.detail(self.conn,IDENTITY,row['id'])
        self.policy.execute('UPDATE folder_permissions SET level=3 WHERE principalId=?',(ALICE,))
        self.policy.execute('UPDATE shares SET isActive=0 WHERE objectGUID=?',(self.folder_ids['Finance'],))
        self.policy.commit()
        self.assertEqual(self.find()['total'],1)
        with self.assertRaises(FileNotFoundError), documents.download(self.conn,IDENTITY,row['id']):
            pass

    def test_admin_sees_all_data_but_only_own_private_and_excluded_accounts_see_nothing(self):
        admin = {**IDENTITY,'sub':'EXAMPLE\\admin','sid':ADMIN,'role':'domain-admin'}
        self.assertEqual({row['name'] for row in self.find(identity=admin)['items']},{'forecast.docx','secret.hidden'})
        for username in ('MSOL_sync','krbtgt'):
            self.assertEqual(self.find(identity={**IDENTITY,'sub':username})['total'],0)
        access.cache_users(self.policy,{ALICE:{'sam':'MSOL_sync','name':'Sync'}})
        self.policy.commit()
        self.assertEqual(self.find()['total'],0)

    def test_private_owner_must_match_current_unix_identity(self):
        identity = {**IDENTITY,'uid':os.getuid()+10000}
        self.assertEqual({row['name'] for row in self.find(identity=identity)['items']},{'forecast.docx'})

    def test_private_read_permissions_filter_counts_types_and_all_file_endpoints(self):
        row = self.document('own.odt')
        (self.private/'alice'/'own.odt').chmod(0)
        self.assertEqual(self.find()['total'],1)
        self.assertEqual(self.find({'q':['ALICEONLY']})['total'],0)
        with self.assertRaises(FileNotFoundError):
            documents.detail(self.conn,IDENTITY,row['id'])
        for operation in (documents.download,documents.preview):
            with self.assertRaises(FileNotFoundError), operation(self.conn,IDENTITY,row['id']):
                pass

    def test_changed_and_deleted_files_cannot_serve_stale_text_preview_or_download(self):
        row = self.document('forecast.docx')
        self.write(self.data/'Finance'/'forecast.docx','Completely new revision')
        self.assertNotIn('forecast.docx',{item['name'] for item in self.find()['items']})
        with self.assertRaises(FileNotFoundError):
            documents.detail(self.conn,IDENTITY,row['id'])
        self.scan()
        current = self.document('forecast.docx')
        self.assertEqual(current['id'],row['id'])
        self.assertEqual(current['body'],'')
        self.assertEqual(current['state'],'pending')
        self.assertEqual(self.find({'q':['Umsatz']})['total'],0)
        (self.data/'Finance'/'forecast.docx').unlink()
        self.scan()
        self.assertEqual(self.find()['total'],1)

    def test_symlinks_trash_fifo_and_path_traversal_are_not_indexed_or_opened(self):
        folder = self.data/'Finance'
        os.symlink(self.private/'bob'/'other.odt',folder/'linked.txt')
        os.symlink(self.private/'bob',folder/'linked-directory')
        os.mkfifo(folder/'fifo')
        self.write(folder/'.trash'/'deleted.txt','deleted contents')
        self.scan()
        self.assertEqual(self.find()['total'],2)
        for path in ('../alice/own.odt','.trash/deleted.txt','linked.txt','linked-directory/other.odt','fifo','/forecast.docx'):
            with self.assertRaises((OSError,FileNotFoundError)), documents.open_file(str(folder),path):
                pass

    def test_queue_phases_retries_and_restart_keep_ocr_work_durable(self):
        row = self.document('forecast.docx')
        self.conn.execute("UPDATE documents SET extension='.pdf',state='pending' WHERE id=?",(row['id'],))
        self.conn.commit()
        with mock.patch.object(document_index,'run_job',return_value={'body':'native footer','pages':1,'needsOcr':True,'preview':''}):
            self.assertTrue(document_index.process_next(self.conn))
        self.assertEqual(self.document('forecast.docx')['state'],'ocr')
        with mock.patch.object(document_index,'run_job',side_effect=RuntimeError('OCR busy')):
            self.assertTrue(document_index.process_next(self.conn))
        queued = self.document('forecast.docx')
        self.assertEqual(queued['state'],'ocr')
        self.assertEqual(queued['body'],'native footer')
        self.assertGreater(queued['retry_at'],time.time())
        self.conn.execute('UPDATE documents SET retry_at=0 WHERE id=?',(row['id'],))
        self.conn.commit()
        with mock.patch.object(document_index,'run_job',return_value={'body':'Recognized invoice OCR742','pages':1,'needsOcr':False,'preview':''}) as job:
            document_index.process_next(self.conn)
        self.assertEqual(job.call_args.args[2],'ocr')
        self.assertEqual(self.find({'q':['OCR742']})['total'],1)

    def test_stale_extraction_result_cannot_overwrite_a_new_version(self):
        row = self.document('forecast.docx')
        self.conn.execute("UPDATE documents SET state='pending' WHERE id=?",(row['id'],))
        self.conn.commit()
        def concurrent_change(*args):
            self.write(self.data/'Finance'/'forecast.docx','New content')
            self.scan()
            return {'body':'obsolete confidential text','pages':0,'needsOcr':False,'preview':''}
        with mock.patch.object(document_index,'run_job',side_effect=concurrent_change):
            document_index.process_next(self.conn)
        self.assertEqual(self.document('forecast.docx')['body'],'')
        self.assertEqual(self.document('forecast.docx')['state'],'pending')

    def test_copy_rejects_growth_before_starting_a_parser(self):
        row = self.document('forecast.docx')
        source = self.conn.execute('SELECT * FROM document_sources WHERE id=?',(row['source_id'],)).fetchone()
        original = self.data/'Finance'/'forecast.docx'
        before = original.read_bytes()
        @contextlib.contextmanager
        def growing_file(*args):
            yield io.BytesIO(before+b'concurrent growth'),original.stat()
        user = SimpleNamespace(pw_uid=os.getuid(),pw_gid=os.getgid())
        with mock.patch.object(document_index.pwd,'getpwnam',return_value=user), \
             mock.patch.object(documents,'open_file',side_effect=growing_file), \
             mock.patch.object(document_index.subprocess,'Popen') as parser:
            self.assertIsNone(document_index.run_job(row,source,'text'))
        parser.assert_not_called()
        self.assertEqual(original.read_bytes(),before)

    def test_pause_survives_restart_and_resume_preserves_queue_and_search(self):
        row = self.document('forecast.docx')
        self.conn.execute("UPDATE documents SET state='ocr' WHERE id=?",(row['id'],))
        self.conn.commit()
        value = documents.control_worker(self.conn,'pause','EXAMPLE\\admin')
        self.assertTrue(value['paused'])
        with contextlib.closing(documents.connect()) as reopened:
            self.assertTrue(documents.worker_paused(reopened))
        with mock.patch.object(document_index,'run_job') as job:
            self.assertFalse(document_index.process_next(self.conn))
            job.assert_not_called()
        self.assertEqual(self.document('forecast.docx')['state'],'ocr')
        self.assertEqual(self.find({'q':['Umsatz']})['total'],1)
        self.conn.commit()
        documents.control_worker(self.conn,'resume','EXAMPLE\\admin')
        with mock.patch.object(document_index,'run_job',return_value={'body':'Resumed OCR742','pages':1,'needsOcr':False,'preview':''}):
            self.assertTrue(document_index.process_next(self.conn))
        self.assertEqual(self.document('forecast.docx')['state'],'ready')
        self.assertEqual(self.find({'q':['OCR742']})['total'],1)
        status = documents.worker_snapshot(self.conn)
        self.assertEqual(status['counts']['complete'],4)
        self.assertEqual(status['processed'],1)
        self.assertEqual({event['action'] for event in status['activity']},{'pause','resume','ocr','complete'})
        with self.assertRaises(ValueError):
            documents.control_worker(self.conn,'delete','admin')

    def test_interrupting_active_job_keeps_ocr_phase_and_attempt_count(self):
        row = self.document('forecast.docx')
        self.conn.execute("UPDATE documents SET state='ocr' WHERE id=?",(row['id'],))
        self.conn.commit()
        def pause(*args):
            documents.control_worker(self.conn,'pause','admin')
            raise document_index.JobPaused()
        with mock.patch.object(document_index,'run_job',side_effect=pause):
            self.assertFalse(document_index.process_next(self.conn))
        queued = self.document('forecast.docx')
        self.assertEqual((queued['state'],queued['attempts'],queued['retry_at']),('ocr',0,0))
        self.assertEqual(documents.worker_snapshot(self.conn)['current'],None)

    def test_interrupted_catalog_scan_never_prunes_existing_records(self):
        source = self.conn.execute('SELECT * FROM document_sources WHERE id=?',('data:'+self.folder_ids['Finance'],)).fetchone()
        before = self.document('forecast.docx')
        self.assertFalse(documents.walk_source(self.conn,source,should_stop=lambda:True))
        self.assertEqual(self.document('forecast.docx'),before)

    def test_linux_file_events_detect_atomic_replacement_and_delete(self):
        watcher = document_index.FileEvents()
        self.addCleanup(watcher.close)
        watcher.add(str(self.data/'Finance'),'finance')
        self.write(self.data/'Finance'/'incoming.txt','incoming document')
        os.rename(self.data/'Finance'/'incoming.txt',self.data/'Finance'/'final.txt')
        (self.data/'Finance'/'final.txt').unlink()
        events = watcher.read(timeout=1)
        self.assertIn(('finance','incoming.txt',False),events)
        self.assertIn(('finance','final.txt',False),events)


class DocumentHttpTests(DocumentFixture):
    def setUp(self):
        super().setUp()
        self.tokens = web_ui.TokenManager('s'*48,600)
        app = mock.Mock(tokens=self.tokens)
        app.overview.return_value = {'administrator':True}
        patches = [mock.patch.object(web_ui,'APP',app),mock.patch.object(web_ui,'STATIC_ROOT',str(Path(__file__).resolve().parents[1]/'app'/'web'))]
        for patch in patches:
            patch.start(); self.addCleanup(patch.stop)
        self.server = web_ui.ReusableHTTPServer(('127.0.0.1',0),web_ui.Handler)
        self.thread = threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.addCleanup(self.close_server)

    def close_server(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join()

    def request(self,path,identity=IDENTITY,method='GET',body=None,extra_headers=None):
        headers = dict(extra_headers or {})
        if identity:
            token,_ = self.tokens.issue(identity['sub'],identity['sid'],identity['role'],identity.get('uid'))
            headers['Authorization'] = 'Bearer '+token
            headers['X-CSRF-Token'] = self.tokens.csrf(self.tokens.verify(token))
        if path == '/api/login':
            headers['X-CSRF-Token'] = 'login'
        if body is not None:
            body=json.dumps(body);headers['Content-Type']='application/json'
        conn=http.client.HTTPConnection(*self.server.server_address)
        try:
            conn.request(method,path,body=body,headers=headers)
            response=conn.getresponse()
            return response.status,dict(response.headers),response.read()
        finally:
            conn.close()

    def test_http_admin_boundary_covers_all_read_and_mutation_endpoints(self):
        for path in ('overview','access','trash','storage','report','reconciliation','activity','system','documents/status'):
            self.assertEqual(self.request('/admin/api/'+path)[0],403)
            self.assertEqual(self.request('/admin/api/'+path,identity=None)[0],401)
        for path in ('access','trash/restore','actions/backup','actions/reconciliation','documents/control'):
            self.assertEqual(self.request('/admin/api/'+path,method='POST',body={})[0],403)
            self.assertEqual(self.request('/api/'+path,method='POST',body={})[0],404)
        self.assertEqual(self.request('/api/storage')[0],404)
        admin = {**IDENTITY,'role':'domain-admin'}
        self.assertEqual(self.request('/admin/api/overview',identity=admin)[0],200)

    def test_http_admin_worker_status_pause_and_resume(self):
        admin = {**IDENTITY,'role':'domain-admin'}
        self.assertEqual(self.request('/admin/api/documents/status',identity=admin)[0],200)
        status,_,body = self.request('/admin/api/documents/control',identity=admin,method='POST',body={'action':'pause'})
        self.assertEqual(status,200)
        self.assertTrue(json.loads(body)['paused'])
        self.assertEqual(self.request('/api/documents/control',identity=admin,method='POST',body={'action':'resume'})[0],404)
        self.assertTrue(documents.worker_paused(self.conn))
        self.assertEqual(self.request('/admin/api/documents/control',identity=admin,method='POST',body={'action':'resume'})[0],200)
        self.assertFalse(documents.worker_paused(self.conn))

    def test_http_serves_user_shell_admin_shell_and_legacy_redirects(self):
        self.assertIn(b'portal.js',self.request('/',identity=None)[2])
        self.assertIn(b'app.js',self.request('/admin/access',identity=None)[2])
        self.assertEqual(self.request('/access')[1]['Location'],'/admin/access')
        self.assertEqual(self.request('/shares')[1]['Location'],'/admin/access')
        self.assertIn(b'"role":"user"',self.request('/api/session')[2])

    def test_http_user_login_succeeds(self):
        with mock.patch.object(web_ui,'authenticate_user',return_value=IDENTITY):
            status,headers,body=self.request('/api/login',identity=None,method='POST',body={'username':'alice','password':'good'})
        self.assertEqual(status,200)
        self.assertEqual(json.loads(body)['role'],'user')
        self.assertIn('HttpOnly',headers['Set-Cookie'])

    def test_http_download_original_detail_and_guessed_private_id(self):
        row=self.document('forecast.docx')
        status,headers,body=self.request('/api/documents/'+row['id']+'/download')
        self.assertEqual(status,200)
        self.assertIn(b'Umsatz',body)
        self.assertIn('attachment;',headers['Content-Disposition'])
        self.assertEqual(headers['Content-Type'],'application/octet-stream')
        for suffix in ('','/download','/preview','/content'):
            self.assertEqual(self.request('/api/documents/'+self.document('other.odt')['id']+suffix)[0],404)
        self.assertEqual(self.request('/api/documents',identity=None)[0],401)

    def test_pdf_content_range_requests_recheck_access_and_keep_original_bytes(self):
        original = self.data/'Finance'/'sample.pdf'
        data = b'%PDF-1.7\n' + b'original PDF bytes\n'*200
        original.write_bytes(data)
        self.scan()
        row = self.document('sample.pdf')
        path = '/api/documents/'+row['id']+'/content'
        status,headers,body = self.request(path)
        self.assertEqual((status,body),(200,data))
        self.assertEqual(headers['Content-Type'],'application/pdf')
        self.assertEqual(headers['Accept-Ranges'],'bytes')
        self.assertIn('inline;',headers['Content-Disposition'])
        for value,expected in [('bytes=0-4',data[:5]),('bytes=-9',data[-9:]),('bytes=10-',data[10:]),('bytes=0-999999',data)]:
            status,headers,body = self.request(path,extra_headers={'Range':value})
            self.assertEqual(status,206)
            self.assertEqual(body,expected)
            self.assertEqual(int(headers['Content-Length']),len(expected))
            self.assertTrue(headers['Content-Range'].endswith('/'+str(len(data))))
        for value in ('bytes=999999-','bytes=4-1','bytes=-0','bytes=-','bytes=0-1,3-4','anything'):
            self.assertEqual(self.request(path,extra_headers={'Range':value})[0],416)
        self.assertEqual(self.request('/api/documents/'+self.document('forecast.docx')['id']+'/content')[0],404)
        self.policy.execute('UPDATE folder_permissions SET level=0 WHERE principalId=?',(ALICE,))
        self.policy.commit()
        self.assertEqual(self.request(path,extra_headers={'Range':'bytes=0-4'})[0],404)
        self.assertEqual(original.read_bytes(),data)

    def test_pdfjs_assets_are_local_and_paths_cannot_escape_the_vendor_directory(self):
        prefix='/assets/vendor/pdfjs/6.3.289-app1/'
        status,headers,body = self.request(prefix+'web/viewer.html',identity=None)
        self.assertEqual(status,200)
        self.assertIn(b'/assets/pdf-viewer.js',body)
        self.assertIn("frame-ancestors 'self'",headers['Content-Security-Policy'])
        self.assertNotIn("'unsafe-eval'",headers['Content-Security-Policy'])
        self.assertIn("frame-ancestors 'none'",self.request('/')[1]['Content-Security-Policy'])
        self.assertEqual(self.request(prefix+'build/pdf.worker.mjs')[1]['Content-Type'],'text/javascript; charset=utf-8')
        for path in ('../LICENSE','%2e%2e/LICENSE','web/%2e%2e/../index.html','web/not-present.js'):
            self.assertEqual(self.request(prefix+path)[0],404)
