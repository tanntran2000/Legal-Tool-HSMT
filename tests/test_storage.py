"""WP01-ST01: independent storage contract, native IO and crash regressions."""
from contextlib import ExitStack, contextmanager
from copy import deepcopy
import ctypes
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import struct
import subprocess
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

# Frozen test-only guard loads R1 types on Linux; native attempts stay fatal.
from tests import test_pdf_read as frozen

FIXTURES = Path(__file__).resolve().parent / "fixtures"
LIMITS = frozen.ImportLimits
SHA = lambda data: hashlib.sha256(data).hexdigest()

def _module():
    try:
        return importlib.import_module("legal_tool.storage")
    except ModuleNotFoundError as exc:
        if exc.name == "legal_tool.storage":
            raise AssertionError("Approved storage API is absent: expected RED") from None
        raise

def _packet(path, failure=False):
    return dict(path=str(path), page_count=0 if failure else 1,
                read_state="LIMIT" if failure else "TEXT_EXTRACTABLE",
                pages=[] if failure else [dict(page_index=0,state="TEXT_EXTRACTABLE",text="OK",locator="page-1",warnings=[])],
                parser_version="pypdf/6.10.0",rule_version="wp01-v1",sha256="a"*64,
                warnings=["TIMEOUT_LIMIT_EXCEEDED: deadline"] if failure else [],
                is_valid=not failure,excerpt="" if failure else "OK")

def _payload(packet):
    return json.dumps({k:v for k,v in packet.items() if k != "path"},ensure_ascii=False)

def _decode(s,path,packet):
    return s._decode_report(path,_payload(packet),LIMITS(),"a"*64)

class _Db(sqlite3.Connection):
    def __exit__(self,*args):
        try:return super().__exit__(*args)
        finally:self.close()

def _disk(root):
    return {p.relative_to(root).as_posix():SHA(p.read_bytes()) for p in root.rglob("*")
            if p.is_file() and not p.is_symlink() and not p.is_junction()}

class TestStoragePortablePolicy(unittest.TestCase):
    def tearDown(self):
        if os.name != "nt":
            self.assertEqual(frozen._NATIVE_CALLS, [], "Native attempt caught or emulated")

    def test_confirmed_id_and_name_contract(self):
        s = _module()
        for value in ("A","A"*64,"PKG_01-2"):
            self.assertEqual(s._validate_package_id(value),value)
        for value in ("","A"*65,False,12,"lower","PHÁP","A/B","A' OR 1=1"):
            with self.subTest(id=value),self.assertRaises(s.StorageError):s._validate_package_id(value)
        self.assertEqual(s._validate_name("法"*200),"法"*200)
        for value in ("N"*201,"\ud800","\udfff",False):
            with self.subTest(name_type=type(value)),self.assertRaises(s.StorageError):s._validate_name(value)

    def test_sqlite_schema_constraints(self):
        s = _module();db=sqlite3.connect(":memory:");s._initialize_schema(db)
        try:
            self.assertEqual(db.execute("PRAGMA foreign_keys").fetchone()[0],1)
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0],1)
            a,b,f = map(str,(uuid4(),uuid4(),uuid4()))
            db.execute("INSERT INTO packages VALUES(?,?,?,?)",(a,"A","A","now"));db.commit()
            columns="file_id,package_uuid,source_name,version,sha256,relative_path,byte_count,report_json,limits_json,imported_utc"
            def insert(values):db.execute("INSERT INTO files ("+columns+") VALUES(?,?,?,?,?,?,?,?,?,?)",values)
            valid=(f,a,"input.pdf",1,"a"*64,"packages/"+a+"/originals/"+f+".pdf",1,"{}","{}","now")
            bads=[(1,b),(3,0),(6,0)]
            for index,value in bads:
                values=list(valid);values[index]=value
                with self.subTest(index=index),self.assertRaises(sqlite3.IntegrityError):insert(values)
                db.rollback()
            insert(valid);db.commit()
            for values in [valid,(str(uuid4()),a,"other.pdf",1,"a"*64,"other",1,"{}","{}","now"),
                           (str(uuid4()),a,"input.pdf",1,"b"*64,"third",1,"{}","{}","now")]:
                with self.assertRaises(sqlite3.IntegrityError):insert(values)
                db.rollback()
        finally:db.close()

    def test_exact_filename_and_relative_identity(self):
        s=_module();root=Path.cwd()/"policy-store";a,b,f,i=map(str,(uuid4(),uuid4(),uuid4(),uuid4()))
        for name in ("A.pdf","a.pdf","é.pdf","e\u0301.pdf","法.pdf"):
            self.assertEqual(s._validate_source_name(name),name)
        part,final,relative=s._managed_paths(root,a,f,i)
        self.assertEqual(relative,"packages/"+a+"/originals/"+f+".pdf")
        self.assertEqual(final,root/relative);self.assertEqual(part,root/"staging"/(i+".part"))
        self.assertNotEqual(s._managed_paths(root,b,f,i)[1],final)
        for value in ("../escape","..",str(uuid4()).upper(),"C:/outside"):
            with self.assertRaises(s.StorageError):s._managed_paths(root,value,f,i)

    def test_limits_revalidated_before_resources(self):
        s=_module();path=Path.cwd()/"never-read.pdf"
        attrs=["max_file_bytes","max_pages","max_stream_bytes","worker_memory_mb","max_excerpt_page_chars","max_excerpt_file_chars","timeout_seconds"]
        for name in attrs:
            for value in (True,0,"1",10**20,float("nan")):
                limits=LIMITS();object.__setattr__(limits,name,value)
                with self.subTest(field=name,type=type(value).__name__),ExitStack() as stack:
                    spies=[stack.enter_context(patch.object(m,n)) for m,n in
                           ((s.pdf,"_read_file_snapshot"),(s,"_directory_guard"),(s.sqlite3,"connect"),(s.worker,"inspect_bounded"))]
                    result=s.import_pdf(path.parent/"no-store","A",path,limits)
                    self.assertEqual(result.outcome,"REJECTED")
                    self.assertTrue(any("CONFIG_ERROR" in x for x in result.diagnostics))
                    self.assertEqual([x.call_count for x in spies],[0]*len(spies))
        for value in ("\ud800.pdf","\udfff.pdf"):
            with ExitStack() as stack:
                spies=[stack.enter_context(patch.object(m,n)) for m,n in
                       ((s.pdf,"_read_file_snapshot"),(s,"_directory_guard"),(s.sqlite3,"connect"),(s.worker,"inspect_bounded"))]
                result=s.import_pdf(path.parent/"no-store","A",Path(value),LIMITS())
                self.assertEqual(result.outcome,"REJECTED")
                self.assertEqual([x.call_count for x in spies],[0]*len(spies))

    def test_persisted_report_shared_predicate(self):
        s=_module();path=Path.cwd()/"policy.pdf";healthy=_packet(path)
        report=_decode(s,path,healthy)
        self.assertEqual(frozen.pdf_read._report_to_wire(report),healthy)
        variants=[]
        for field,value in [("page_count",True),("page_count",2),("is_valid",1),("pages",[42]),
                            ("rule_version","other"),("parser_version","other"),("sha256","b"*64),
                            ("excerpt","invented"),("excerpt","\ud800"),("warnings",[17])]:
            p=deepcopy(healthy);p[field]=value;variants.append(p)
        for field,value in [("page_index",True),("page_index",1),("locator","page-2"),("text","\udfff"),("state","LIMIT")]:
            p=deepcopy(healthy);p["pages"][0][field]=value;variants.append(p)
        for p in variants:
            with self.subTest(packet_field_types=str([(k,type(v).__name__) for k,v in p.items()])),self.assertRaises(s.StorageError):
                _decode(s,path,p)
        for p in ({**healthy,"extra":1},{k:v for k,v in healthy.items() if k!="pages"}):
            with self.assertRaises(s.StorageError):_decode(s,path,p)
        with self.assertRaises(s.StorageError):s._decode_report(path,json.dumps(healthy),LIMITS(),"a"*64)
        # Deliberately matches the fallback in every value except bool-vs-int type.
        trap=_packet(path,True);trap.update(page_count=False,sha256="",warnings=["CHILD_PROCESS_ERROR: report missing or invalid page_count"])
        terminal=deepcopy(trap);terminal["page_count"]=0
        self.assertEqual(trap,terminal,"Demonstrate Python dict equality trap")
        self.assertFalse(s._same_wire_tree(trap,terminal))
        self.assertFalse(s._same_wire_tree({"x":[False]},{"x":[0]}))
        self.assertFalse(s._same_wire_tree({"x":[1]},{"x":[1.0]}))
        with self.assertRaises(s.StorageError) as rejected:_decode(s,path,trap)
        self.assertEqual(rejected.exception.code,"REPORT_CONTRACT_REJECTED")
        accepted=_decode(s,path,terminal)
        self.assertTrue(s._same_wire_tree(frozen.pdf_read._report_to_wire(accepted),terminal))

    def test_terminal_sha_and_counts_preserved(self):
        s=_module();path=Path.cwd()/"policy.pdf"
        for code in frozen.pdf_read.ALLOWED_MISSING_HASH_PREFIXES:
            p=_packet(path,True);p.update(read_state="CORRUPT",sha256="",warnings=[code+": exact originating failure"])
            r=_decode(s,path,p)
            self.assertEqual((r.read_state,r.page_count,r.sha256,r.warnings),("CORRUPT",0,"",p["warnings"]))
        p=_packet(path,True);p.update(read_state="LOCKED",sha256="",warnings=["PATH_NOT_FOUND: source missing"])
        with self.assertRaises(s.StorageError):_decode(s,path,p)
        p.update(sha256="a"*64)
        self.assertEqual(_decode(s,path,p).read_state,"LOCKED")
        for count in (201,10**30):
            p=_packet(path,True);p["page_count"]=count
            self.assertEqual(_decode(s,path,p).page_count,count)

    def test_warning_overflow_and_safe_errors(self):
        s=_module();path=Path.cwd()/"policy.pdf"
        for state in ("CORRUPT","LOCKED","LIMIT","UNSUPPORTED","UNKNOWN"):
            for warning in (17,"\ud800","X"*4097):
                p=_packet(path,True);p.update(read_state=state,warnings=[warning])
                with self.subTest(state=state,warning_type=type(warning)),self.assertRaises(s.StorageError):
                    _decode(s,path,p)
        p=_packet(path,True);p["warnings"]=["X"*4096]
        self.assertEqual(_decode(s,path,p).warnings,p["warnings"])
        error=s.StorageError("IO_FAILED","\ud800"+"X"*10000)
        self.assertLessEqual(len(str(error).encode("utf-8")),4096)

    def test_json_report_envelope_controls(self):
        s=_module();path=Path.cwd()/"policy.pdf";p=_packet(path)
        p["pages"]=[dict(page_index=i,state="TEXT_EXTRACTABLE",text="\x01"*1000,locator="page-"+str(i+1),warnings=[]) for i in range(100)]
        p.update(page_count=100,excerpt=frozen.pdf_read.derive_excerpt([frozen.PageReading(**x) for x in p["pages"]],100000))
        raw=_payload(p);self.assertGreater(len(raw.encode()),1024*1024)
        before=raw.encode();r=s._decode_report(path,raw,LIMITS(),"a"*64)
        self.assertTrue(s._same_wire_tree(frozen.pdf_read._report_to_wire(r),p))
        self.assertEqual(raw.encode(),before)
        with self.assertRaises(s.StorageError) as refused:s._encode_report(path,r,LIMITS(),"a"*64)
        self.assertEqual(refused.exception.code,"REPORT_CONTRACT_REJECTED")
        current=deepcopy(p);current.update(rule_version="wp01-v2-dq",read_state="UNKNOWN",warnings=["D2;P=100;T=0;Q=100;M=0;I=0;U=100"])
        for page in current["pages"]:page.update(state="UNKNOWN",warnings=["TEXT_QUALITY"])
        fresh=_payload(current);self.assertGreater(len(fresh.encode()),1024*1024)
        r=s._decode_report(path,fresh,LIMITS(),"a"*64)
        saved=s._encode_report(path,r,LIMITS(),"a"*64)
        self.assertTrue(s._same_wire_tree(frozen.pdf_read._report_to_wire(s._decode_report(path,saved,LIMITS(),"a"*64)),current))
        self.assertEqual(raw.encode(),before)
        with self.assertRaises(s.StorageError):s._decode_report(path," "*(2*1024*1024+1),LIMITS(),"a"*64)

class _NativeCase(unittest.TestCase):
    def setUp(self):
        root=os.environ.get("WP01_STORAGE_TEST_RUNTIME")
        if not root:raise AssertionError("Set WP01_STORAGE_TEST_RUNTIME to a registered owned root")
        self.case=Path(root)/"stores"/(os.environ.get("WP01_STORAGE_RUN_ID","native")+"-"+self._testMethodName)
        self.case.mkdir(parents=True,exist_ok=False)
        self.store=self.case/"store";self.inputs=self.case/"inputs";self.inputs.mkdir()
        self.processes=[]

    def tearDown(self):
        for process in self.processes:
            if process.poll() is None:process.terminate()
            process.communicate(timeout=3)
            self.assertIsNotNone(process.returncode)
            for pipe in (process.stdin,process.stdout,process.stderr):
                if pipe:self.assertTrue(pipe.closed)
            if os.name=="nt":
                if not process._handle.closed:process._handle.Close()
                self.assertTrue(process._handle.closed)

    def seed(self,s,ids=("A",)):
        for package_id in ids:s.create_package(self.store,package_id,package_id)

    def boot(self):
        s=_module();self.seed(s);return s,self.source()

    def source(self,name="text_unicode.pdf",alias=None):
        p=self.inputs/(alias or name);p.write_bytes((FIXTURES/name).read_bytes());return p

    def imported(self,s,source,package="A",limits=None):
        result=s.import_pdf(self.store,package,source,limits or LIMITS())
        self.assertEqual(result.outcome,"IMPORTED",result.diagnostics)
        self.assertIsNotNone(result.record);return result.record

    def final(self,record):return self.store/record.managed_relative_path

    def db(self):return sqlite3.connect(self.store/"app.sqlite3",factory=_Db)

    def junction(self,link,target):
        self.assertTrue(link.absolute().is_relative_to(self.case.absolute()))
        self.assertTrue(target.absolute().is_relative_to(self.case.absolute()))
        result=subprocess.run(["cmd","/c","mklink","/J",str(link),str(target)],capture_output=True,timeout=3,creationflags=subprocess.CREATE_NO_WINDOW)
        self.assertEqual(result.returncode,0,result.stderr.decode(errors="replace"))

    def paused_child(self,phase,source):
        helpers=self.case/"helpers";helpers.mkdir(exist_ok=True)
        script=helpers/(phase+".py");ready=helpers/(phase+".ready.json")
        script.write_text('''import json,os,sys,time
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from legal_tool import storage as s
phase,root,source,ready=sys.argv[2:]
def checkpoint(value,*args):
 if value==phase:
  Path(ready).write_text(json.dumps(dict(pid=os.getpid(),phase=value)),encoding="utf-8")
  deadline=time.monotonic()+8
  while time.monotonic()<deadline:time.sleep(.02)
  raise RuntimeError("owned checkpoint deadline expired")
s._checkpoint=checkpoint
s.import_pdf(Path(root),"A",Path(source),s.pdf.ImportLimits())
''',encoding="utf-8")
        process=subprocess.Popen([sys.executable,"-B",str(script),str(Path(__file__).resolve().parents[1]),phase,str(self.store),str(source),str(ready)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=subprocess.CREATE_NO_WINDOW)
        self.processes.append(process);deadline=time.monotonic()+5
        while not ready.exists() and process.poll() is None and time.monotonic()<deadline:time.sleep(.02)
        self.assertTrue(ready.exists(),"Owned importer did not acknowledge checkpoint")
        self.assertEqual(json.loads(ready.read_text())["pid"],process.pid);return process

    def stop_child(self,process):
        process.terminate();out,err=process.communicate(timeout=3)
        self.assertIsNotNone(process.returncode)
        self.assertTrue(process.stdout.closed and process.stderr.closed)
        return out,err

@unittest.skipUnless(os.name=="nt","Real Windows managed-file IO required")
class TestStoragePackages(_NativeCase):
    def test_create_unique_stable_id_reopen(self):
        s=_module();a=s.create_package(self.store,"A_1","法"*200);b=s.create_package(self.store,"B-2","B")
        with self.assertRaises(s.StorageError):s.create_package(self.store,"A_1","replacement")
        self.assertEqual(s.open_package(self.store,"A_1").package,a)
        self.assertEqual(s.list_packages(self.store),[a,b])
        self.assertFalse((self.store/"packages").exists())

    def test_list_and_open_metadata_scope(self):
        s=_module();self.seed(s,("A","B"))
        self.assertEqual([x.package_id for x in s.list_packages(self.store)],["A","B"])
        self.assertEqual(s.open_package(self.store,"A").files,())
        with self.assertRaises(s.StorageError):s.open_package(self.store,"UNKNOWN")

    def test_invalid_input_has_no_write(self):
        s=_module();before=_disk(self.case)
        for package_id,name in (("lower","ok"),("../A","ok"),("A","\ud800"),("A","N"*201)):
            with self.assertRaises(s.StorageError):s.create_package(self.store,package_id,name)
        self.assertEqual(_disk(self.case),before)

@unittest.skipUnless(os.name=="nt","Real Windows managed-file IO required")
class TestStorageImports(_NativeCase):
    def test_frozen_fixture_import_and_reopen(self):
        s=_module();self.seed(s);oracle=json.loads((FIXTURES/"expected.json").read_bytes())
        for name,expected in oracle["fixtures"].items():
            with self.subTest(fixture=name):
                source=self.source(name);raw=source.read_bytes();result=s.import_pdf(self.store,"A",source,LIMITS())
                if name=="unsupported.txt":
                    self.assertEqual(result.outcome,"REJECTED");continue
                self.assertEqual(result.outcome,"IMPORTED",result.diagnostics)
                record=result.record;self.assertEqual(self.final(record).read_bytes(),raw)
                self.assertEqual((record.sha256,record.source_name,record.version),(SHA(raw),name,1))
                self.assertEqual((record.report.read_state,record.report.page_count,record.report.is_valid),(expected["read_state"],expected["page_count"],expected["is_valid"]))
                if name=="locked.pdf":self.assertEqual(record.report.sha256,record.sha256)
                saved=next(x for x in s.open_package(self.store,"A").files if x.file_id==record.file_id)
                self.assertEqual(frozen.pdf_read._report_to_wire(saved.report),frozen.pdf_read._report_to_wire(record.report))
        self.assertEqual(len(s.open_package(self.store,"A").files),7)

    def test_duplicate_hash_preserves_first_record(self):
        s,source=self.boot();first=self.imported(s,source)
        alias=self.source(alias="renamed.pdf")
        for p in (source,alias):
            with patch.object(s.worker,"inspect_bounded",side_effect=AssertionError("Duplicate must not inspect")):
                result=s.import_pdf(self.store,"A",p,LIMITS())
            self.assertEqual(result.outcome,"DUPLICATE");self.assertEqual(result.record.file_id,first.file_id)
            self.assertEqual((result.record.source_name,result.record.version),("text_unicode.pdf",1))
        held=self.inputs/"held-original.pdf";self.final(first).rename(held)
        self.assertEqual(s.import_pdf(self.store,"A",source,LIMITS()).outcome,"HOLD")
        self.assertEqual(held.read_bytes(),source.read_bytes())

    def test_same_filename_changed_bytes_versions(self):
        s=_module();self.seed(s);source=self.source(alias="same.pdf");v1=self.imported(s,source);old=self.final(v1).read_bytes()
        source.write_bytes(old+b"\n% changed bytes\n");v2=self.imported(s,source)
        self.assertEqual((v1.version,v2.version),(1,2));self.assertNotEqual(v1.file_id,v2.file_id)
        self.assertEqual(self.final(v1).read_bytes(),old);self.assertEqual(self.final(v2).read_bytes(),source.read_bytes())
        self.assertEqual([x.version for x in s.open_package(self.store,"A").files],[1,2])

    def test_package_isolation_same_name_and_hash(self):
        s=_module();self.seed(s,("A","B"));source=self.source(alias="same.pdf")
        a=self.imported(s,source,"A");b=self.imported(s,source,"B")
        self.assertNotEqual(a.file_id,b.file_id);self.assertNotEqual(a.managed_relative_path,b.managed_relative_path)
        for package,record in (("A",a),("B",b)):
            view=s.open_package(self.store,package);self.assertEqual([x.file_id for x in view.files],[record.file_id])
            self.assertEqual(view.files[0].package_id,package)
        with self.db() as db:db.execute("UPDATE files SET relative_path=? WHERE file_id=?",("packages/"+a.package_uuid+"/originals/"+b.file_id+".pdf",b.file_id))
        self.assertEqual(s.open_package(self.store,"B").files[0].availability,"HOLD")
        self.assertEqual(s.open_package(self.store,"A").files[0].availability,"AVAILABLE")

    def test_quiescent_store_relocation(self):
        s=_module();self.seed(s);original=self.imported(s,self.source());relocated=self.case/"relocated"
        shutil.copytree(self.store,relocated)
        saved=s.open_package(relocated,"A").files[0]
        self.assertEqual((saved.file_id,saved.sha256,saved.version),(original.file_id,original.sha256,1))
        self.assertEqual(saved.report.path,relocated/saved.managed_relative_path)
        with self.db() as db:payload=db.execute("SELECT report_json FROM files").fetchone()[0]
        self.assertNotIn(str(self.store),payload);self.assertNotIn('"path"',payload)

@unittest.skipUnless(os.name=="nt","Real Windows managed-file IO required")
class TestStorageAdmission(_NativeCase):
    def test_native_source_path_refusals(self):
        s=_module();self.seed(s);target=self.inputs/"target";target.mkdir();actual=self.source();link=self.inputs/"linked";self.junction(link,target);(target/"missing.pdf").write_bytes(actual.read_bytes())
        vectors=[self.inputs/"missing.pdf",self.inputs,Path(r"\\server\share\file.pdf"),Path(r"\\.\NUL.pdf"),self.source("unsupported.txt"),link/"missing.pdf"]
        for p in vectors:
            with self.subTest(path=str(p)),patch.object(s.worker,"inspect_bounded",side_effect=AssertionError("Unadmitted worker")):
                self.assertEqual(s.import_pdf(self.store,"A",p,LIMITS()).outcome,"REJECTED")
        with self.db() as db:self.assertEqual(db.execute("SELECT count(*) FROM import_journal").fetchone()[0],0)
        self.assertEqual(s.open_package(self.store,"A").files,());self.assertEqual(actual.read_bytes(),(FIXTURES/"text_unicode.pdf").read_bytes())

    def test_unicode_and_long_path_behavior(self):
        s=_module();self.seed(s);source=self.source(alias="法-luật.pdf");record=self.imported(s,source)
        self.assertEqual(record.source_name,"法-luật.pdf")
        long=self.inputs/("x"*150)/("y"*150)/"long.pdf"
        with patch.object(s.worker,"inspect_bounded",side_effect=AssertionError("Missing long source")):
            result=s.import_pdf(self.store,"A",long,LIMITS())
        self.assertEqual(result.outcome,"REJECTED");self.assertTrue(result.diagnostics)

    def test_stable_capture_source_swap(self):
        s,source=self.boot();captured=source.read_bytes();actual=s.pdf._read_file_snapshot
        def capture(path,cap):
            result=actual(path,cap)
            if path==source:source.write_bytes(captured+b"\n% caller changed after capture\n")
            return result
        with patch.object(s.pdf,"_read_file_snapshot",capture):record=self.imported(s,source)
        self.assertEqual(self.final(record).read_bytes(),captured);self.assertNotEqual(source.read_bytes(),captured)
        other=self.source(alias="swap.pdf");original_admission=s.pdf._check_path_admission
        def before(path):
            if path==other:
                held=self.inputs/"held-swap.pdf";other.rename(held);other.mkdir()
            return original_admission(path)
        with patch.object(s.pdf,"_check_path_admission",before):
            self.assertEqual(s.import_pdf(self.store,"A",other,LIMITS()).outcome,"REJECTED")

    def test_destination_ancestor_swap(self):
        s,source=self.boot();outside=self.case/"outside";outside.mkdir();attempts=[]
        def swap(phase,*args):
            if phase in ("RESERVED","STAGED"):
                directories=(self.store,self.store/"staging",self.store/"packages",*(self.store/"packages").glob("*"),*(self.store/"packages").glob("*/originals"))
                for directory in directories:
                    held=self.case/(directory.name+"-held-"+phase)
                    self.assertTrue(held.absolute().is_relative_to(self.case.absolute()))
                    try:directory.rename(held)
                    except OSError:attempts.append("PREVENTED");continue
                    self.junction(directory,outside);attempts.append("SWAPPED")
        before=_disk(outside)
        with patch.object(s,"_checkpoint",swap):result=s.import_pdf(self.store,"A",source,LIMITS())
        self.assertTrue(attempts);self.assertEqual(_disk(outside),before)
        self.assertIn(result.outcome,("IMPORTED","HOLD","FAILED"))
        if "SWAPPED" in attempts:self.assertNotEqual(result.outcome,"IMPORTED")

    def test_foreign_part_and_final_collision(self):
        s,source=self.boot();foreign=b"foreign bytes preserved";targets=[]
        def collision(phase,root,op):
            if phase=="RESERVED":
                with self.db() as db:relative=db.execute("SELECT part_relative_path FROM import_journal WHERE operation_id=?",(op,)).fetchone()[0]
                p=root/relative;p.write_bytes(foreign);targets.append(p)
        with patch.object(s,"_checkpoint",collision):result=s.import_pdf(self.store,"A",source,LIMITS())
        self.assertEqual(result.outcome,"HOLD");self.assertEqual(targets[0].read_bytes(),foreign)
        s.create_package(self.store,"B","B");targets.clear()
        def final_collision(phase,root,op):
            if phase=="STAGED":
                with self.db() as db:relative=db.execute("SELECT relative_path FROM import_journal WHERE operation_id=?",(op,)).fetchone()[0]
                p=root/relative;p.write_bytes(foreign);targets.append(p)
        with patch.object(s,"_checkpoint",final_collision):result=s.import_pdf(self.store,"B",source,LIMITS())
        self.assertNotEqual(result.outcome,"IMPORTED");self.assertEqual(targets[0].read_bytes(),foreign)

    def test_native_maximum_capture_and_oversize(self):
        s=_module();self.seed(s);source=self.inputs/"boundary.pdf";raw=(FIXTURES/"text_unicode.pdf").read_bytes();size=20*1024*1024
        with source.open("xb") as h:h.write(raw);h.write(b" "*(size-len(raw)))
        record=self.imported(s,source);self.assertEqual(record.byte_count,size)
        self.assertEqual(SHA(self.final(record).read_bytes()),record.sha256)
        with source.open("ab") as h:h.write(b" ")
        with patch.object(s.worker,"inspect_bounded",side_effect=AssertionError("Oversize worker")):
            self.assertEqual(s.import_pdf(self.store,"A",source,LIMITS()).outcome,"REJECTED")
        self.assertEqual(len(s.open_package(self.store,"A").files),1)

    def test_store_budget_and_disk_preflight(self):
        s,source=self.boot();before=_disk(self.store)
        with patch.object(s,"MAX_STORE_BYTES",1):result=s.import_pdf(self.store,"A",source,LIMITS())
        self.assertIn(result.outcome,("REJECTED","HOLD","FAILED"));self.assertEqual(_disk(self.store),before)
        with patch.object(s.shutil,"disk_usage",return_value=SimpleNamespace(free=0)):
            result=s.import_pdf(self.store,"A",source,LIMITS())
        self.assertNotEqual(result.outcome,"IMPORTED");self.assertEqual(_disk(self.store),before)

@unittest.skipUnless(os.name=="nt","Real Windows managed-file IO required")
class TestStorageRecovery(_NativeCase):
    def test_synchronous_io_failure_owned_rollback(self):
        s,source=self.boot()
        for package,obj,name in (("A",s,"_copy_snapshot"),("B",s.os,"fsync"),("C",s.os,"rename")):
            if package!="A":s.create_package(self.store,package,package)
            with patch.object(obj,name,side_effect=OSError("synthetic IO failure")):
                result=s.import_pdf(self.store,package,source,LIMITS())
            self.assertEqual(result.outcome,"FAILED",result.diagnostics)
            self.assertEqual(s.open_package(self.store,package).files,())
            self.assertFalse(list((self.store/"staging").glob("*.part")))
        self.assertTrue(all(x.outcome=="ROLLED_BACK" for x in s.recover_imports(self.store).entries))

    def test_sqlite_busy_failed_commit_and_corruption(self):
        s,source=self.boot();db=self.db();db.execute("BEGIN IMMEDIATE");start=time.monotonic()
        try:result=s.import_pdf(self.store,"A",source,LIMITS())
        finally:db.rollback();db.close()
        self.assertNotEqual(result.outcome,"IMPORTED");self.assertLess(time.monotonic()-start,3)
        with patch.object(s,"_finalize",side_effect=sqlite3.OperationalError("synthetic commit failure")):
            result=s.import_pdf(self.store,"A",source,LIMITS())
        self.assertEqual(result.outcome,"HOLD");self.assertTrue(list((self.store/"packages").rglob("*.pdf")))
        self.assertEqual(s.open_package(self.store,"A").files,())
        with self.db() as db:db.execute("PRAGMA user_version=99")
        with self.assertRaises(s.StorageError):s.open_package(self.store,"A")
        backup=self.inputs/"held-good.sqlite3";shutil.copyfile(self.store/"app.sqlite3",backup)
        (self.store/"app.sqlite3").write_bytes(b"not a sqlite database")
        with self.assertRaises(s.StorageError):s.list_packages(self.store)
        self.assertEqual((self.store/"app.sqlite3").read_bytes(),b"not a sqlite database")

    def test_active_import_serialization(self):
        s=_module();self.seed(s,("A","B"));source=self.source();child=self.paused_child("RESERVED",source)
        result=s.import_pdf(self.store,"A",source,LIMITS());self.assertEqual(result.outcome,"REJECTED")
        self.assertTrue(any("IMPORT_BUSY" in x for x in result.diagnostics));self.imported(s,source,"B")
        self.stop_child(child);report=s.recover_imports(self.store)
        self.assertTrue(any(x.package_id=="A" and x.outcome=="HOLD" for x in report.entries))
        self.assertEqual(s.open_package(self.store,"B").files[0].availability,"AVAILABLE")

    def test_crash_after_staged_checkpoint(self):
        s,source=self.boot();child=self.paused_child("STAGED",source);self.stop_child(child)
        self.assertEqual(list(self.store.rglob(".lt-guard-*.tmp")), [], "Killed importer must release temporary guards")
        parts=list((self.store/"staging").glob("*.part"));self.assertEqual(len(parts),1);before=parts[0].read_bytes()
        first=s.recover_imports(self.store);second=s.recover_imports(self.store)
        self.assertEqual(first,second);self.assertTrue(any(x.outcome=="HOLD" for x in first.entries))
        self.assertEqual(parts[0].read_bytes(),before);self.assertEqual(s.open_package(self.store,"A").files,())

    def test_crash_after_rename_checkpoint(self):
        s,source=self.boot();child=self.paused_child("RENAMED",source);self.stop_child(child)
        originals=list((self.store/"packages").rglob("*.pdf"));self.assertEqual(len(originals),1);before=originals[0].read_bytes()
        self.assertEqual(s.recover_imports(self.store),s.recover_imports(self.store))
        self.assertEqual(s.open_package(self.store,"A").files,());self.assertEqual(originals[0].read_bytes(),before)

    def test_committed_without_response_replay(self):
        s,source=self.boot();child=self.paused_child("COMMITTED",source);self.stop_child(child)
        view=s.open_package(self.store,"A");self.assertEqual(len(view.files),1)
        self.assertEqual(view.files[0].availability,"AVAILABLE")
        result=s.import_pdf(self.store,"A",source,LIMITS());self.assertEqual(result.outcome,"DUPLICATE")
        self.assertEqual(result.record.file_id,view.files[0].file_id);self.assertEqual(result.record.version,1)

    def test_tamper_missing_original_and_hold_isolation(self):
        s=_module();self.seed(s,("A","B"));source=self.source();a=self.imported(s,source,"A");b=self.imported(s,source,"B")
        backup=self.inputs/"held-A-original.pdf";shutil.copyfile(self.final(a),backup);self.final(a).write_bytes(b"synthetic tamper")
        view=s.open_package(self.store,"A");self.assertEqual(view.files[0].availability,"HOLD")
        self.assertEqual(view.files[0].file_id,a.file_id);self.assertEqual(s.import_pdf(self.store,"A",source,LIMITS()).outcome,"HOLD")
        self.assertEqual(s.open_package(self.store,"B").files[0].availability,"AVAILABLE")
        self.assertEqual(self.final(b).read_bytes(),source.read_bytes());self.assertEqual(backup.read_bytes(),source.read_bytes())

@unittest.skipUnless(os.name=="nt","Real Windows managed-file IO required")
class TestStorageContracts(_NativeCase):
    def test_native_import_report_reopen_parity(self):
        s=_module();self.seed(s);source=self.source("page_limit.pdf");record=self.imported(s,source)
        self.assertEqual(record.report.page_count,201)
        reopened=s.open_package(self.store,"A").files[0]
        self.assertEqual(frozen.pdf_read._report_to_wire(record.report),frozen.pdf_read._report_to_wire(reopened.report))
        with self.db() as db:
            payload=json.loads(db.execute("SELECT report_json FROM files").fetchone()[0])
            payload.update(page_count=False,read_state="LIMIT",pages=[],excerpt="",sha256="",is_valid=False,warnings=["CHILD_PROCESS_ERROR: report missing or invalid page_count"])
            db.execute("UPDATE files SET report_json=?",(json.dumps(payload),))
        held=s.open_package(self.store,"A").files[0]
        self.assertEqual(held.availability,"HOLD");self.assertIsNone(held.report)
        self.assertEqual(self.final(record).read_bytes(),source.read_bytes())

@unittest.skipUnless(os.name=="nt","Real Windows metadata admission required")
class TestStorageOrdinarySqlite(_NativeCase):
    def committed(self, s, package, saved=False):
        operation, file_id = str(uuid4()), str(uuid4())
        raw = b"owned synthetic committed bytes"
        relative = "packages/" + package.package_uuid + "/originals/" + file_id + ".pdf"
        values = (operation, package.package_uuid, file_id, "ordinary.pdf", 1, SHA(raw), len(raw),
                  relative, "staging/" + operation + ".part", "null", "COMMITTED", "", "now")
        with self.db() as db:
            db.execute("INSERT INTO import_journal VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", values)
            if saved:
                packet = _packet(self.store / relative); packet["sha256"] = SHA(raw)
                db.execute("INSERT INTO files VALUES(?,?,?,?,?,?,?,?,?,?)", (file_id, package.package_uuid,
                    "ordinary.pdf", 1, SHA(raw), relative, len(raw), _payload(packet), json.dumps(vars(LIMITS())), "now"))
        return values, raw

    def test_committed_missing_row_holds_reopen_and_import(self):
        s = _module(); self.seed(s, ("A", "B"))
        package = s.open_package(self.store, "A").package
        row, _ = self.committed(s, package)
        first = s.recover_imports(self.store)
        self.assertEqual(first.entries[0].outcome, "HOLD")
        with self.db() as db:
            saved = db.execute("SELECT * FROM import_journal WHERE operation_id=?", (row[0],)).fetchone()
            self.assertEqual(saved[10], "HOLD", "Detected missing committed row must durably block the package")
            self.assertEqual(saved[11], first.entries[0].diagnostic)
            self.assertEqual(saved[:10], row[:10])
            self.assertEqual(db.execute("SELECT COUNT(*) FROM files").fetchone()[0], 0)
        self.assertEqual(s.recover_imports(self.store), first)
        reopened = s.open_package(self.store, "A")
        self.assertEqual(reopened.files, ())
        self.assertTrue(any("RECOVERY_HOLD" in message for message in reopened.diagnostics))
        self.assertEqual(s.open_package(self.store, "B").diagnostics, ())
        with patch.object(s.worker, "inspect_bounded", side_effect=AssertionError("Held package launched worker")):
            result = s.import_pdf(self.store, "A", self.source(), LIMITS())
        self.assertEqual(result.outcome, "HOLD")
        self.assertTrue(any("RECOVERY_HOLD" in message for message in result.diagnostics))

    def test_committed_missing_original_keeps_file_history(self):
        s = _module(); self.seed(s)
        row, _ = self.committed(s, s.open_package(self.store, "A").package, saved=True)
        with self.db() as db: before = db.execute("SELECT * FROM files").fetchall()
        first = s.recover_imports(self.store)
        self.assertEqual(first.entries[0].outcome, "HOLD")
        with self.db() as db:
            self.assertEqual(db.execute("SELECT phase,diagnostic FROM import_journal").fetchone(),
                             ("HOLD", first.entries[0].diagnostic))
            self.assertEqual(db.execute("SELECT * FROM files").fetchall(), before)
        self.assertEqual(s.recover_imports(self.store), first)
        view = s.open_package(self.store, "A")
        self.assertEqual((view.files[0].file_id, view.files[0].availability), (row[2], "HOLD"))
        self.assertIsNotNone(view.files[0].report, "Prior parser evidence is retained")
        self.assertTrue(any("RECOVERY_HOLD" in message for message in view.diagnostics))
        self.assertFalse((self.store / row[7]).exists())

    def test_multiple_unproved_commits_keep_one_package_hold(self):
        s = _module(); self.seed(s, ("A", "B"))
        package = s.open_package(self.store, "A").package
        rows = [self.committed(s, package)[0] for _ in range(2)]
        first = s.recover_imports(self.store)
        self.assertEqual([item.outcome for item in first.entries], ["HOLD", "HOLD"])
        with self.db() as db:
            phases = db.execute("SELECT phase,diagnostic FROM import_journal").fetchall()
            self.assertEqual(sum(phase == "HOLD" for phase, _ in phases), 1,
                             "one_active_import permits one durable package blocker")
            self.assertTrue(all("RECOVERY_HOLD" in diagnostic for _, diagnostic in phases))
            self.assertEqual(db.execute("SELECT COUNT(*) FROM files").fetchone()[0], 0)
        self.assertEqual(s.recover_imports(self.store), first)
        self.assertTrue(s.open_package(self.store, "A").diagnostics)
        self.assertEqual(s.open_package(self.store, "B").diagnostics, ())
        with self.db() as db:
            self.assertEqual({r[0] for r in db.execute("SELECT operation_id FROM import_journal")}, {r[0] for r in rows})

    def test_proved_commit_recovery_preserves_terminal_phase(self):
        s = _module(); self.seed(s)
        row, raw = self.committed(s, s.open_package(self.store, "A").package, saved=True)
        final = self.store / row[7]; final.parent.mkdir(parents=True)
        with final.open("xb") as out: out.write(raw)
        first = s.recover_imports(self.store)
        self.assertEqual((first.entries[0].outcome, first.entries[0].diagnostic), ("COMMITTED", ""))
        self.assertEqual(s.recover_imports(self.store), first)
        self.assertEqual(s.open_package(self.store, "A").files[0].availability, "AVAILABLE")
        with self.db() as db:
            s._phase(db, row[0], "HOLD", "ordinary import error")
            self.assertEqual(db.execute("SELECT phase,diagnostic FROM import_journal").fetchone(), ("COMMITTED", ""))
        self.assertEqual(final.read_bytes(), raw)

    def test_metadata_schema_requires_constraints(self):
        s = _module()
        with sqlite3.connect(":memory:", factory=_Db) as reference:
            s._initialize_schema(reference)
            schema = dict(reference.execute("SELECT name,sql FROM sqlite_master WHERE sql IS NOT NULL"))
        fk = " REFERENCES packages(package_uuid) ON DELETE RESTRICT"
        variants = [
            ("files_fk", "files", fk, "", None),
            ("journal_fk", "import_journal", fk, "", None),
            ("fk_delete", "files", "ON DELETE RESTRICT", "ON DELETE CASCADE", None),
            ("hash_unique", "files", "UNIQUE(package_uuid,sha256), ", "", ("package_uuid", "sha256")),
            ("version_unique", "files", ", UNIQUE(package_uuid,source_name,version)", "", ("package_uuid", "source_name", "version")),
            ("path_unique", "files", "relative_path TEXT UNIQUE", "relative_path TEXT", ("relative_path",)),
            ("package_id_unique", "packages", "package_id TEXT UNIQUE", "package_id TEXT", ("package_id",)),
            ("file_id_unique", "files", "file_id TEXT PRIMARY KEY", "file_id TEXT", ("file_id",)),
            ("operation_unique", "import_journal", "operation_id TEXT PRIMARY KEY", "operation_id TEXT", ("operation_id",)),
            ("active_missing", "one_active_import", "", "", None),
            ("active_nonunique", "one_active_import", "CREATE UNIQUE INDEX", "CREATE INDEX", None),
            ("active_phases", "one_active_import", ",'HOLD'", "", None),
            ("active_column", "one_active_import", "(package_uuid)", "(file_id)", None),
        ]
        for label, table, old, new, missing_key in variants:
            with self.subTest(schema=label):
                root = self.case / label; root.mkdir()
                statements = dict(schema)
                if label == "active_missing": del statements[table]
                else:
                    self.assertIn(old, statements[table])
                    statements[table] = statements[table].replace(old, new)
                with sqlite3.connect(root / "app.sqlite3", factory=_Db) as db:
                    for sql in statements.values(): db.execute(sql)
                    db.execute("PRAGMA user_version=1")
                    db.execute("INSERT INTO packages VALUES(?,?,?,?)", (str(uuid4()), "A", "preserve me", "now"))
                    self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 1)
                    self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])
                    if label in {"files_fk", "journal_fk"}:
                        self.assertEqual(db.execute("SELECT * FROM pragma_foreign_key_list(?)", (table,)).fetchall(), [])
                    elif missing_key:
                        keys = {tuple(r[0] for r in db.execute("SELECT name FROM pragma_index_info(?) ORDER BY seqno", (index[1],)))
                                for index in db.execute("SELECT * FROM pragma_index_list(?)", (table,)) if index[2]}
                        self.assertNotIn(missing_key, keys)
                before = _disk(root)
                for name, api in (("list", lambda: s.list_packages(root)), ("open", lambda: s.open_package(root, "A")),
                                  ("recover", lambda: s.recover_imports(root))):
                    with self.subTest(api=name):
                        with self.assertRaises(s.StorageError) as rejected: api()
                        self.assertEqual(rejected.exception.code, "STORE_INVALID")
                        self.assertIn("schema", rejected.exception.diagnostic.lower())
                self.assertEqual(_disk(root), before, "Unsupported databases must not be repaired or migrated")

    def test_equivalent_schema_layout_reopens_without_repair(self):
        s = _module(); self.seed(s)
        with self.db() as db:
            # Recreate only an owned empty index with equivalent phase order and SQL spelling.
            db.execute("DROP INDEX one_active_import")
            db.execute("create unique index one_active_import on import_journal(package_uuid) where phase in ('HOLD','RENAMED','STAGED','RESERVED')")
        before = _disk(self.store)
        self.assertEqual([p.package_id for p in s.list_packages(self.store)], ["A"])
        self.assertEqual(s.open_package(self.store, "A").diagnostics, ())
        self.assertEqual(_disk(self.store), before)

@unittest.skipUnless(os.name=="nt","Real Windows metadata admission required")
class TestStorageRoundTwo(_NativeCase):
    committed = TestStorageOrdinarySqlite.committed

    def original_values(self, row, raw):
        final = self.store / row[7]; final.parent.mkdir(parents=True, exist_ok=True)
        with final.open("xb") as out: out.write(raw)
        packet = _packet(final); packet["sha256"] = SHA(raw)
        return (row[2], row[1], row[3], row[4], row[5], row[7], row[6],
                _payload(packet), json.dumps(vars(LIMITS())), "now")

    def held_with_actor(self, s, package, finish):
        row, _ = self.committed(s, package)
        transaction = s._transaction; actors = []
        @contextmanager
        def after_snapshot(db):
            filename = db.execute("PRAGMA database_list").fetchone()[2]
            if filename and Path(filename) == self.store / "app.sqlite3" and not actors:
                actor, raw = self.committed(s, package)
                with self.db() as writer:
                    writer.execute("UPDATE import_journal SET phase='RESERVED' WHERE operation_id=?", (actor[0],))
                actors.append((actor, raw))
            with transaction(db): yield
        with patch.object(s, "_transaction", after_snapshot): first = s.recover_imports(self.store)
        self.assertEqual(len(first.entries), 1, "Actor starts after the bounded journal snapshot")
        self.assertEqual(first.entries[0].outcome, "HOLD")
        actor, raw = actors[0]
        if finish == "COMMITTED":
            values = self.original_values(actor, raw)
            with self.db() as writer:
                writer.row_factory = sqlite3.Row
                s._phase(writer, actor[0], "RENAMED")
                s._finalize(writer, values, actor[0])
        else:
            with self.db() as writer: s._phase(writer, actor[0], "ROLLED_BACK", "owned actor rollback")
        return row, actor, first.entries[0]

    def test_actor_completion_keeps_hold(self):
        s = _module(); source = self.source()
        for finish in ("ROLLED_BACK", "COMMITTED"):
            with self.subTest(actor=finish):
                self.store = self.case / finish; self.seed(s, ("A", "B"))
                package = s.open_package(self.store, "A").package
                row, actor, first = self.held_with_actor(s, package, finish)
                view = s.open_package(self.store, "A")
                self.assertTrue(any("RECOVERY_HOLD" in d for d in view.diagnostics), "Completed actor must not release detected integrity HOLD")
                self.assertEqual(s.open_package(self.store, "B").diagnostics, ())
                with patch.object(s.worker, "inspect_bounded", side_effect=AssertionError("Held package launched worker")):
                    result = s.import_pdf(self.store, "A", source, LIMITS())
                self.assertEqual(result.outcome, "HOLD")
                repeated = s.recover_imports(self.store)
                self.assertEqual(next(e for e in repeated.entries if e.operation_id == row[0]), first)
                self.assertEqual(s.recover_imports(self.store), repeated)
                with self.db() as db:
                    self.assertEqual(db.execute("SELECT phase FROM import_journal WHERE operation_id=?", (actor[0],)).fetchone()[0], finish)
                    saved = db.execute("SELECT * FROM import_journal WHERE operation_id=?", (row[0],)).fetchone()
                    self.assertEqual(saved[:10], row[:10]); self.assertEqual(saved[11], first.diagnostic)
                    self.assertLessEqual(db.execute("SELECT COUNT(*) FROM import_journal WHERE phase IN('RESERVED','STAGED','RENAMED','HOLD')").fetchone()[0], 1)

    def test_marker_requires_reconciliation(self):
        s = _module(); self.seed(s)
        row, raw = self.committed(s, s.open_package(self.store, "A").package)
        first = s.recover_imports(self.store)
        with self.db() as db: before = db.execute("SELECT * FROM import_journal").fetchone()
        values = self.original_values(row, raw)
        with self.db() as db:
            db.execute("INSERT INTO files VALUES(?,?,?,?,?,?,?,?,?,?)", values)
        with self.db() as db:
            for phase in ("STAGED", "RENAMED", "ROLLED_BACK", "COMMITTED"):
                s._phase(db, row[0], phase, "ordinary actor response")
                self.assertEqual(db.execute("SELECT * FROM import_journal").fetchone(), before, "Ordinary phase calls must retain the recovery marker")
            db.row_factory = sqlite3.Row
            with self.assertRaises(s.StorageError): s._finalize(db, values, row[0])
        self.assertEqual(s.recover_imports(self.store), first)
        self.assertTrue(s.open_package(self.store, "A").diagnostics)
        self.assertEqual((self.store / row[7]).read_bytes(), raw)

    def test_reservation_rechecks_hold(self):
        s = _module(); self.seed(s)
        package = s.open_package(self.store, "A").package; transaction = s._transaction; races = []
        @contextmanager
        def before_reservation(db):
            filename = db.execute("PRAGMA database_list").fetchone()[2]
            if filename and Path(filename) == self.store / "app.sqlite3" and not races:
                races.append(True)
                # Actual recovery creates the marker after admission reads and before BEGIN IMMEDIATE.
                with patch.object(s, "_transaction", transaction): self.held_with_actor(s, package, "ROLLED_BACK")
            with transaction(db): yield
        with patch.object(s, "_transaction", before_reservation), patch.object(s.worker, "inspect_bounded", side_effect=AssertionError("Held reservation launched worker")):
            result = s.import_pdf(self.store, "A", self.source(), LIMITS())
        self.assertEqual(races, [True]); self.assertEqual(result.outcome, "HOLD", result.diagnostics)
        with self.db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM import_journal").fetchone()[0], 2, "No third reservation may be inserted")
        self.assertFalse(any(self.store.rglob("*.part")))

    def test_proof_is_rechecked_in_transaction(self):
        s = _module(); self.seed(s)
        row, raw = self.committed(s, s.open_package(self.store, "A").package)
        transaction = s._transaction; changes = []
        @contextmanager
        def before_write(db):
            filename = db.execute("PRAGMA database_list").fetchone()[2]
            if filename and Path(filename) == self.store / "app.sqlite3" and not changes:
                values = self.original_values(row, raw)
                with self.db() as writer: writer.execute("INSERT INTO files VALUES(?,?,?,?,?,?,?,?,?,?)", values)
                changes.append(True)
            with transaction(db): yield
        with patch.object(s, "_transaction", before_write): report = s.recover_imports(self.store)
        self.assertEqual(changes, [True]); self.assertEqual(report.entries[0].outcome, "COMMITTED", "A newly proved COMMITTED item must be rechecked under the write lock")
        self.assertEqual(s.open_package(self.store, "A").diagnostics, ())
        with self.db() as db:
            self.assertEqual(db.execute("SELECT phase,diagnostic FROM import_journal").fetchone(), ("COMMITTED", ""))

    def test_ordinary_diagnostics_are_not_markers(self):
        s = _module(); self.seed(s)
        row, raw = self.committed(s, s.open_package(self.store, "A").package)
        values = self.original_values(row, raw)
        source = self.inputs / "ordinary.pdf"; source.write_bytes(raw)
        with self.db() as db: db.execute("INSERT INTO files VALUES(?,?,?,?,?,?,?,?,?,?)", values)
        for diagnostic in ("historical response note", "RECOVERY_HOLD: ordinary explanation", "UNPROVED_COMMITTED_V1", "HOLD"):
            with self.subTest(diagnostic=diagnostic):
                with self.db() as db: db.execute("UPDATE import_journal SET diagnostic=?", (diagnostic,))
                self.assertEqual(s.open_package(self.store, "A").diagnostics, ())
                self.assertEqual(s.recover_imports(self.store).entries[0].outcome, "COMMITTED")
                with patch.object(s.worker, "inspect_bounded", side_effect=AssertionError("Duplicate launched worker")):
                    self.assertEqual(s.import_pdf(self.store, "A", source, LIMITS()).outcome, "DUPLICATE")
                with self.db() as db:
                    self.assertEqual(db.execute("SELECT phase,diagnostic FROM import_journal").fetchone(), ("COMMITTED", diagnostic))

    def test_index_comment_is_not_predicate(self):
        s = _module()
        prefix = "CREATE UNIQUE INDEX one_active_import ON import_journal(package_uuid) "
        fake = "WHERE phase IN('RESERVED','STAGED','RENAMED','HOLD')"
        definitions = [prefix + "WHERE phase='RESERVED' -- " + fake,
                       prefix + "WHERE phase='RESERVED' /* " + fake + " */",
                       prefix + "/* " + fake + " */ WHERE phase='RESERVED'",
                       prefix + fake + " -- unsupported trailing comment"]
        for index, sql in enumerate(definitions):
            with self.subTest(index=index):
                self.store = self.case / str(index); self.seed(s)
                with self.db() as db:
                    db.execute("DROP INDEX one_active_import"); db.execute(sql)
                before = _disk(self.store)
                for name, api in (("list", lambda: s.list_packages(self.store)), ("open", lambda: s.open_package(self.store, "A")), ("recover", lambda: s.recover_imports(self.store))):
                    with self.subTest(api=name):
                        with self.assertRaises(s.StorageError) as rejected: api()
                        self.assertEqual(rejected.exception.code, "STORE_INVALID")
                        self.assertIn("schema", rejected.exception.diagnostic.lower())
                self.assertEqual(_disk(self.store), before)

    def test_supported_index_spellings(self):
        s = _module()
        definitions = ["CREATE UNIQUE INDEX one_active_import ON import_journal(package_uuid) WHERE phase IN('RESERVED','STAGED','RENAMED','HOLD')",
                       "create unique index one_active_import on import_journal(package_uuid) where phase in ('HOLD','RENAMED','STAGED','RESERVED')",
                       'create unique index one_active_import on import_journal(package_uuid) where "phase" in (\'HOLD\',\'RENAMED\',\'STAGED\',\'RESERVED\')']
        for index, sql in enumerate(definitions):
            with self.subTest(index=index):
                self.store = self.case / str(index); self.seed(s)
                with self.db() as db: db.execute("DROP INDEX one_active_import"); db.execute(sql)
                before = _disk(self.store)
                self.assertEqual([p.package_id for p in s.list_packages(self.store)], ["A"])
                self.assertEqual(s.open_package(self.store, "A").diagnostics, ())
                self.assertEqual(s.recover_imports(self.store).entries, ())
                self.assertEqual(_disk(self.store), before)

@unittest.skipUnless(os.name=="nt","Real Windows metadata admission required")
class TestStorageIndexOrder(_NativeCase):
    def test_single_key_ordering(self):
        s = _module()
        for index, (key, direction) in enumerate((key, direction)
                for key in ("package_uuid", '"package_uuid"') for direction in ("", "ASC", "DESC")):
            with self.subTest(key=key, direction=direction):
                self.store = self.case / str(index); self.seed(s)
                ordered_key = key + (" " + direction if direction else "")
                definition = ("CREATE UNIQUE INDEX one_active_import ON import_journal(" + ordered_key +
                              ') WHERE "phase" IN(\'HOLD\',\'RENAMED\',\'STAGED\',\'RESERVED\')')
                with self.db() as db:
                    package_uuid = db.execute("SELECT package_uuid FROM packages").fetchone()[0]
                    db.execute("DROP INDEX one_active_import"); db.execute(definition)
                    self.assertEqual(db.execute('SELECT "unique",partial FROM pragma_index_list(\'import_journal\') WHERE name=\'one_active_import\'').fetchone(), (1, 1))
                    self.assertEqual(db.execute('SELECT name,coll,desc FROM pragma_index_xinfo(\'one_active_import\') WHERE "key"=1').fetchall(),
                                     [("package_uuid", "BINARY", int(direction == "DESC"))])
                before = _disk(self.store)
                apis = (("list", lambda: [p.package_id for p in s.list_packages(self.store)], ["A"]),
                        ("open", lambda: s.open_package(self.store, "A").diagnostics, ()),
                        ("recover", lambda: s.recover_imports(self.store).entries, ()))
                for name, api, expected in apis:
                    with self.subTest(api=name):
                        try: actual = api()
                        except s.StorageError as error:
                            self.fail("Valid single-key ordering rejected: " + error.code + ": " + error.diagnostic)
                        self.assertEqual(actual, expected)
                self.assertEqual(_disk(self.store), before, "Opening a supported schema must preserve its bytes")
                # Distinct primary keys prove that package uniqueness still blocks a second active HOLD.
                with self.db() as db:
                    for attempt in range(2):
                        operation, file_id = str(uuid4()), str(uuid4())
                        values = (operation, package_uuid, file_id, "ordinary.pdf", 1, SHA(b"x"), 1,
                                  "packages/" + package_uuid + "/originals/" + file_id + ".pdf",
                                  "staging/" + operation + ".part", "null", "HOLD", "owned control", "now")
                        if attempt == 0:
                            db.execute("INSERT INTO import_journal VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", values)
                        else:
                            with self.assertRaises(sqlite3.IntegrityError):
                                db.execute("INSERT INTO import_journal VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", values)
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM import_journal").fetchone()[0], 1)

@unittest.skipUnless(os.name == "nt", "Real Windows guard operations required")
class TestStorageNativeGuard(_NativeCase):
    def set_reparse(self, s, directory, target):
        native = s.pdf.kernel32
        handle = native.CreateFileW(str(directory), 0x40000000, 3, None, 3, 0x02200000, None)
        self.assertNotIn(handle, (None, 0, s.pdf.INVALID_HANDLE_VALUE))
        try:
            substitute = ("\\??\\" + str(target)).encode("utf-16-le")
            printed = str(target).encode("utf-16-le")
            names = substitute + b"\0\0" + printed + b"\0\0"
            data = struct.pack("<IHHHHHH", 0xA0000003, len(names) + 8, 0,
                               0, len(substitute), len(substitute) + 2, len(printed)) + names
            ioctl = native.DeviceIoControl
            ioctl.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32,
                              ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p]
            ioctl.restype = ctypes.c_int
            returned = ctypes.c_uint32()
            ok = ioctl(handle, 0x900A4, data, len(data), None, 0, ctypes.byref(returned), None)
            return 0 if ok else ctypes.get_last_error()
        finally:
            native.CloseHandle(handle)

    def test_guard_rename_reparse_and_cleanup(self):
        s = _module()
        root, source, dest, empty, target = (self.case / name for name in ("guard", "guard/src", "guard/dst", "empty", "target"))
        for directory in (root, source, dest, empty, target): directory.mkdir()
        self.assertEqual(self.set_reparse(s, empty, target), 0, "Unpinned control must work")
        baseline = frozen._get_process_handle_count()
        for cycle in range(2):
            part, final = source / (str(cycle) + ".part"), dest / (str(cycle) + ".pdf")
            part.write_bytes(b"guarded payload")
            with s._directory_guard(source, anchor=root), s._directory_guard(dest, anchor=root):
                part.rename(final)
                self.assertEqual(final.read_bytes(), b"guarded payload")
                for directory in (root, source, dest):
                    with self.assertRaises(OSError): directory.rename(self.case / "swapped")
                self.assertEqual(self.set_reparse(s, source, target), 145)
                markers = list(root.rglob(".lt-guard-*.tmp"))
                self.assertTrue(markers, "Empty source needs a live nonempty witness")
                replacement = self.case / "replacement"
                replacement.write_bytes(b"foreign")
                for marker in markers:
                    with self.assertRaises(OSError): marker.unlink()
                    with self.assertRaises(OSError): replacement.replace(marker)
                    self.assertTrue(marker.exists())
                self.assertEqual(replacement.read_bytes(), b"foreign")
            self.assertEqual(list(root.rglob(".lt-guard-*.tmp")), [])
            self.assertEqual(frozen._get_process_handle_count(), baseline)
        with self.assertRaises(s.StorageError):
            with s._directory_guard(source, anchor=root):
                raise RuntimeError("owned interruption")
        self.assertEqual(list(root.rglob(".lt-guard-*.tmp")), [])
        self.assertEqual(frozen._get_process_handle_count(), baseline)
        self.assertEqual(self.set_reparse(s, source, target), 0, "Control after release must work")

    def test_guard_foreign_marker_and_preopened_writer(self):
        s = _module(); root = self.case / "guard"; root.mkdir()
        token = uuid4(); foreign = root / (".lt-guard-" + str(token) + ".tmp")
        foreign.write_bytes(b"foreign marker")
        baseline = frozen._get_process_handle_count()
        with patch.object(s, "uuid4", return_value=token), self.assertRaises(s.StorageError):
            with s._directory_guard(root): pass
        self.assertEqual(foreign.read_bytes(), b"foreign marker")
        writer = s.pdf.kernel32.CreateFileW(str(root), 0x40000000, 3, None, 3, 0x02200000, None)
        self.assertNotIn(writer, (None, 0, s.pdf.INVALID_HANDLE_VALUE))
        try:
            with self.assertRaises(s.StorageError):
                with s._directory_guard(root): pass
        finally:
            s.pdf.kernel32.CloseHandle(writer)
        self.assertEqual(_disk(root), {foreign.name: SHA(b"foreign marker")})
        with self.assertRaises(s.StorageError): s.create_package(root, "A", "A")
        self.assertEqual(_disk(root), {foreign.name: SHA(b"foreign marker")})
        self.assertEqual(frozen._get_process_handle_count(), baseline)

    def test_guard_handoff_failure_closes_all_handles(self):
        s = _module(); root = self.case / "guard"; root.mkdir()
        native = s.pdf.kernel32; original = native.CreateFileW; identity = s._identity
        baseline = frozen._get_process_handle_count()
        for fault in ("marker", "operational", "identity"):
            opened = []
            def create(path, access, share, security, disposition, flags, template):
                if fault == "marker" and disposition == 1:
                    return s.pdf.INVALID_HANDLE_VALUE
                if flags == 0x02200000 and share == 3:
                    writer = original(path, 0x40000000, 3, None, 3, 0x02200000, None)
                    if writer not in (None, 0, s.pdf.INVALID_HANDLE_VALUE):
                        native.CloseHandle(writer)
                        raise AssertionError("Bootstrap was released before operational handoff")
                    if fault == "operational": return s.pdf.INVALID_HANDLE_VALUE
                    handle = original(path, access, share, security, disposition, flags, template)
                    opened.append(handle)
                    return handle
                return original(path, access, share, security, disposition, flags, template)
            def checked_identity(handle):
                value = identity(handle)
                return [-1, -1, -1] if fault == "identity" and handle in opened else value
            with self.subTest(fault=fault), patch.object(native, "CreateFileW", side_effect=create), \
                    patch.object(s, "_identity", side_effect=checked_identity):
                with self.assertRaises(s.StorageError) as error:
                    with s._directory_guard(root): pass
                expected = {"marker": "temporary guard", "operational": "operational directory guard", "identity": "changed during guard handoff"}
                self.assertIn(expected[fault], str(error.exception))
            self.assertEqual(list(root.iterdir()), [])
            self.assertEqual(frozen._get_process_handle_count(), baseline)

    def test_database_pin_allows_sql_and_denies_replacement(self):
        s = _module(); self.seed(s)
        path = self.store / "app.sqlite3"; replacement = self.case / "replacement.db"
        shutil.copyfile(path, replacement)
        baseline = frozen._get_process_handle_count()
        connect = s.sqlite3.connect; admissions = []
        def checked_connect(database, *args, **kwargs):
            if database != ":memory:":
                with self.assertRaises(OSError): path.unlink()
                admissions.append(True)
            return connect(database, *args, **kwargs)
        with patch.object(s.sqlite3, "connect", side_effect=checked_connect), s._store(self.store) as (_, db):
            before = path.read_bytes()
            with self.assertRaises(OSError): replacement.replace(path)
            with self.assertRaises(OSError): path.unlink()
            self.assertEqual(path.read_bytes(), before)
            with s._transaction(db): db.execute("UPDATE packages SET name='committed' WHERE package_id='A'")
            with self.assertRaisesRegex(RuntimeError, "rollback"):
                with s._transaction(db):
                    db.execute("UPDATE packages SET name='rolled back' WHERE package_id='A'")
                    raise RuntimeError("rollback")
        self.assertEqual(admissions, [True])
        self.assertEqual(s.open_package(self.store, "A").package.name, "committed")
        self.assertEqual(list(self.store.rglob(".lt-guard-*.tmp")), [])
        self.assertEqual(frozen._get_process_handle_count(), baseline)
        replacement.replace(path)
        self.assertEqual(s.open_package(self.store, "A").package.name, "A")

    def test_budget_closes_inventory_on_early_exit(self):
        s = _module(); root = self.case / "inventory"; root.mkdir()
        for name in ("one", "two"): (root / name).write_bytes(b"xx")
        scans = []; actual = os.scandir
        def scan(path):
            iterator = actual(path); scans.append(iterator); return iterator
        try:
            with patch.object(s.os, "scandir", side_effect=scan), patch.object(s, "MAX_STORE_BYTES", 1):
                with self.assertRaises(s.StorageError) as error: s._budget(root)
            self.assertEqual(error.exception.code, "STORE_BUDGET_EXCEEDED")
            self.assertTrue(scans)
            for iterator in scans: self.assertEqual(list(iterator), [], "Inventory handle remained open after quota failure")
        finally:
            for iterator in scans: iterator.close()



@unittest.skipUnless(os.name == "nt", "Real Windows database admission required")
class TestStorageDbAdmission(_NativeCase):
    def code(self, s, call):
        try: call()
        except s.StorageError as error: return error.code
        return None

    def snapshot(self, path):
        try:
            info = path.stat()
            return dict(exists=True, sha256=SHA(path.read_bytes()), links=info.st_nlink,
                        identity=[info.st_dev, info.st_ino])
        except FileNotFoundError: return dict(exists=False)

    def kernel(self):
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
        k.CreateMutexW.restype = ctypes.c_void_p
        k.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        k.WaitForSingleObject.restype = ctypes.c_uint32
        k.ReleaseMutex.argtypes = [ctypes.c_void_p]; k.ReleaseMutex.restype = ctypes.c_int
        k.CloseHandle.argtypes = [ctypes.c_void_p]; k.CloseHandle.restype = ctypes.c_int
        return k

    def mutex_name(self, s):
        k = s.pdf.kernel32
        handle = k.CreateFileW(str(self.store), 0x81, 3, None, 3, 0x02200000, None)
        self.assertNotIn(handle, (None, 0, s.pdf.INVALID_HANDLE_VALUE))
        try: return "Global\\LegalTool.Database." + ":".join(map(str, s._identity(handle)))
        finally: k.CloseHandle(handle)

    def writer(self, mode="live", name=""):
        tag = self.store.name + "-" + mode
        script = self.case / (tag + ".py"); ready = self.case / (tag + ".ready")
        release = self.case / (tag + ".release")
        script.write_text(r'''import ctypes,json,os,sqlite3,sys,time
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from legal_tool import storage as s
root,mode,name,ready,release=sys.argv[2:]
def pause(db=None):
 ack={"pid":os.getpid()}
 if db is not None:ack.update(in_transaction=db.in_transaction,databases=db.execute("PRAGMA database_list").fetchall())
 Path(ready).write_text(json.dumps(ack))
 deadline=time.monotonic()+10
 while not Path(release).exists() and time.monotonic()<deadline:time.sleep(.02)
 if not Path(release).exists():raise RuntimeError("owned writer deadline")
if mode=="abandon":
 k=ctypes.WinDLL("kernel32",use_last_error=True)
 k.CreateMutexW.argtypes=[ctypes.c_void_p,ctypes.c_int,ctypes.c_wchar_p];k.CreateMutexW.restype=ctypes.c_void_p
 k.WaitForSingleObject.argtypes=[ctypes.c_void_p,ctypes.c_uint32];k.WaitForSingleObject.restype=ctypes.c_uint32
 h=k.CreateMutexW(None,False,name)
 if not h or k.WaitForSingleObject(h,0)!=0:raise RuntimeError("owned mutex admission")
 pause()
elif mode=="hot":
 db=sqlite3.connect(Path(root)/"app.sqlite3",isolation_level=None)
 db.execute("PRAGMA journal_mode=DELETE");db.execute("PRAGMA synchronous=FULL")
 db.execute("PRAGMA cache_size=1");db.execute("PRAGMA cache_spill=ON")
 db.execute("BEGIN IMMEDIATE")
 db.execute("UPDATE packages SET name='uncommitted-' || substr(name,1,175)")
 pause(db)
else:
 with s._store(Path(root)) as (_,db):
  db.execute("PRAGMA cache_size=1");db.execute("PRAGMA cache_spill=ON")
  with s._transaction(db):
   db.execute("UPDATE packages SET name=?",("dirty"*38,))
   pause()
''', encoding="utf8")
        args = [sys.executable, "-B", str(script), str(Path(__file__).resolve().parents[1]),
                str(self.store), mode, name, str(ready), str(release)]
        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   creationflags=subprocess.CREATE_NO_WINDOW)
        self.processes.append(process); deadline = time.monotonic() + 5
        while not ready.exists() and process.poll() is None and time.monotonic() < deadline: time.sleep(.02)
        self.assertTrue(ready.exists(), "Owned writer did not acknowledge admission")
        self.assertEqual(json.loads(ready.read_text())["pid"], process.pid)
        return process, release

    def test_hardlink_rejected_before_connect_and_cleanup(self):
        s = _module(); self.seed(s)
        self.assertEqual([p.package_id for p in s.list_packages(self.store)], ["A"])
        path = self.store / "app.sqlite3"; alias = self.case / "external-alias.db"
        os.link(path, alias); self.assertEqual(path.stat().st_nlink, 2)
        before = self.snapshot(path); self.assertEqual(self.snapshot(alias), before)
        handles = frozen._get_process_handle_count()
        for index, api in enumerate((lambda: s.list_packages(self.store), lambda: s.create_package(self.store, "B", "B"))):
            with patch.object(s.sqlite3, "connect", wraps=s.sqlite3.connect) as connect:
                code = self.code(s, api); calls = connect.call_count
            after, outside = self.snapshot(path), self.snapshot(alias)
            print(json.dumps(dict(witness="hardlink",api=index,code=code,connect_calls=calls,before=before,after=after,alias=outside)))
            with self.subTest(api=index): self.assertEqual((code, calls, after, outside), ("ROOT_UNSAFE", 0, before, before))
            self.assertEqual(list(self.store.rglob(".lt-guard-*.tmp")), [])
            self.assertEqual(frozen._get_process_handle_count(), handles)

    def test_hot_journal_two_reopens_and_open_pager_preserve_bytes(self):
        s = _module()
        for opened in (False, True):
            with self.subTest(open_connection=opened):
                self.store = self.case / ("open" if opened else "closed"); self.seed(s)
                with self.db() as db:
                    db.executemany("INSERT INTO packages VALUES(?,?,?,?)",
                        [(str(uuid4()), "P"+str(i), "original"*25, "now") for i in range(256)])
                with ExitStack() as stack:
                    db = stack.enter_context(s._store(self.store))[1] if opened else None
                    process, _ = self.writer("hot")
                    ack = json.loads((self.case / (self.store.name + "-hot.ready")).read_text())
                    self.assertTrue(ack["in_transaction"])
                    self.assertEqual(len(ack["databases"]), 1)
                    self.assertEqual(ack["databases"][0][1], "main")
                    self.stop_child(process)
                    path = self.store / "app.sqlite3"; journal = self.store / "app.sqlite3-journal"
                    self.assertTrue(journal.exists()); self.assertGreater(journal.stat().st_size, 512)
                    self.assertEqual(journal.read_bytes()[:8], bytes.fromhex("d9d505f920a163d7"))
                    before = (self.snapshot(path), self.snapshot(journal))
                    clone = self.case / ("control-open" if opened else "control-closed"); clone.mkdir()
                    shutil.copyfile(path, clone / path.name); shutil.copyfile(journal, clone / journal.name)
                    with sqlite3.connect(clone / path.name, factory=_Db) as control:
                        self.assertEqual(control.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                        self.assertEqual(control.execute("SELECT name FROM packages WHERE package_id='A'").fetchone()[0], "A")
                    for attempt in range(2):
                        with patch.object(s.sqlite3, "connect", wraps=s.sqlite3.connect) as connect:
                            api = (lambda: db.execute("SELECT name FROM packages").fetchall()) if opened else (lambda: s.list_packages(self.store))
                            code = self.code(s, api); calls = connect.call_count
                        after = (self.snapshot(path), self.snapshot(journal))
                        print(json.dumps(dict(witness="hotjournal",opened=opened,attempt=attempt,code=code,connect_calls=calls,before=before,after=after)))
                        with self.subTest(attempt=attempt): self.assertEqual((code, calls, after), ("RECOVERY_HOLD", 0, before))

    def test_same_thread_other_thread_busy_and_transaction_release(self):
        import threading
        s = _module(); self.seed(s); results = []
        with s._store(self.store) as (_, db):
            with s._transaction(db):
                db.execute("UPDATE packages SET name='committed'")
                with self.subTest(thread="same"):
                    self.assertEqual(self.code(s, lambda: s.list_packages(self.store)), "DATABASE_BUSY")
                t = threading.Thread(target=lambda: results.append(self.code(s, lambda: s.list_packages(self.store))))
                t.start(); t.join(3); self.assertFalse(t.is_alive())
                with self.subTest(thread="other"): self.assertEqual(results, ["DATABASE_BUSY"])
            self.assertEqual(s.open_package(self.store, "A").package.name, "committed")
            with self.assertRaisesRegex(RuntimeError, "owned rollback"):
                with s._transaction(db):
                    db.execute("UPDATE packages SET name='rolled back'")
                    raise RuntimeError("owned rollback")
            self.assertEqual(s.open_package(self.store, "A").package.name, "committed")

    def test_two_process_live_writer_busy_then_release(self):
        s = _module(); self.seed(s); process, release = self.writer()
        with self.subTest(held=True): self.assertEqual(self.code(s, lambda: s.list_packages(self.store)), "DATABASE_BUSY")
        release.write_bytes(b"release"); out, err = process.communicate(timeout=3)
        self.assertEqual(process.returncode, 0, (out, err))
        self.assertEqual(s.open_package(self.store, "A").package.name, "dirty"*38)
        self.assertEqual(s.create_package(self.store, "B", "B").package_id, "B")

    def test_abandoned_mutex_never_proves_clean(self):
        s = _module(); self.seed(s); name = self.mutex_name(s); k = self.kernel()
        observer = k.CreateMutexW(None, False, name); self.assertTrue(observer)
        before = _disk(self.store)
        try:
            process, _ = self.writer("abandon", name); self.stop_child(process)
            for attempt in range(2):
                with self.subTest(attempt=attempt), patch.object(s.sqlite3, "connect", wraps=s.sqlite3.connect) as connect:
                    self.assertEqual(self.code(s, lambda: s.list_packages(self.store)), "RECOVERY_HOLD")
                    self.assertEqual(connect.call_count, 0)
            self.assertEqual(_disk(self.store), before)
        finally: self.assertTrue(k.CloseHandle(observer))

    def test_bootstrap_mutex_precedes_connect(self):
        s = _module(); real = s.sqlite3.connect; observed = []; entered = False
        def connect(database, *args, **kwargs):
            nonlocal entered
            if database != ":memory:" and not entered:
                entered = True
                observed.append(self.code(s, lambda: s.list_packages(self.store)))
            return real(database, *args, **kwargs)
        with patch.object(s.sqlite3, "connect", side_effect=connect):
            self.assertEqual(s.create_package(self.store, "A", "A").package_id, "A")
        self.assertEqual(observed, ["DATABASE_BUSY"])

    def test_cursor_lease_consumption_close_and_exception_cleanup(self):
        s = _module(); self.seed(s, ("A", "B")); baseline = frozen._get_process_handle_count()
        for cycle in range(2):
            with s._store(self.store) as (_, db):
                cursor = db.execute("SELECT * FROM packages ORDER BY package_id")
                with self.subTest(cycle=cycle, held=True):
                    self.assertEqual(self.code(s, lambda: s.list_packages(self.store)), "DATABASE_BUSY")
                self.assertEqual(len(cursor.fetchall()), 2)
                self.assertEqual(len(s.list_packages(self.store)), 2)
                cursor = db.execute("SELECT * FROM packages"); cursor.close()
                self.assertEqual(len(s.list_packages(self.store)), 2)
            with self.assertRaises(s.StorageError) as error:
                with s._store(self.store) as (_, db):
                    cursor = db.execute("SELECT * FROM packages")
                    raise RuntimeError("owned cursor")
            self.assertEqual(error.exception.code, "ROOT_UNSAFE")
            self.assertIsNotNone(cursor)
            self.assertEqual(len(s.list_packages(self.store)), 2)
            self.assertEqual(list(self.store.rglob(".lt-guard-*.tmp")), [])
            self.assertEqual(frozen._get_process_handle_count(), baseline)

    def test_b_progresses_during_a_copy_worker_and_paused_checkpoint(self):
        s = _module(); self.seed(s); source = self.source(); copied = s._copy_snapshot
        checked = []; worker = s.worker.inspect_bounded
        def copy(*args):
            checked.append(s.create_package(self.store, "B", "B").package_id)
            return copied(*args)
        def inspect(*args, **kwargs):
            checked.append(s.create_package(self.store, "C", "C").package_id)
            return worker(*args, **kwargs)
        with patch.object(s, "_copy_snapshot", side_effect=copy), patch.object(s.worker, "inspect_bounded", side_effect=inspect):
            self.imported(s, source)
        self.assertEqual(checked, ["B", "C"])
        process = self.paused_child("STAGED", self.source("mixed.pdf", alias="other.pdf"))
        self.assertEqual(s.create_package(self.store, "D", "D").package_id, "D")
        self.stop_child(process)

    def probe(self):
        script = "from legal_tool.storage import _SqlGate;from pathlib import Path;import sys\ng=_SqlGate(Path(sys.argv[1]));r=g.native.WaitForSingleObject(g.handle,0);print(r)\nif r in (0,128):g.native.ReleaseMutex(g.handle)\ng.close()"
        return int(subprocess.check_output([sys.executable,"-B","-c",script,self.store],
            cwd=FIXTURES.parents[1],timeout=3,creationflags=subprocess.CREATE_NO_WINDOW))

    def test_cancel_gate(self):
        s = _module()
        for phase in ("BEGIN","UPDATE","COMMIT","COMMITTED","ROLLBACK"):
            self.store = self.case / phase; self.seed(s)
            with s._store(self.store) as (_,db), self.subTest(phase=phase):
                real, close = db.execute, db.close; waits = []; error = KeyboardInterrupt()
                def closed():
                    waits.append(self.probe()); close(); waits.append(self.probe())
                def execute(sql,*args):
                    self.assertEqual(self.probe(),258)
                    if sql=="ROLLBACK" and phase=="ROLLBACK": raise RuntimeError()
                    if sql=="COMMIT" and phase=="COMMIT": raise error
                    result = real(sql,*args)
                    if sql.startswith(phase) or (sql=="COMMIT" and phase=="COMMITTED"): raise error
                    return result
                with patch.object(db,"execute",execute),patch.object(db,"close",closed):
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        with s._transaction(db):
                            db.execute("UPDATE packages SET name='dirty'")
                            if phase=="ROLLBACK": raise error
                self.assertIs(caught.exception,error)
                if phase=="ROLLBACK":
                    self.assertEqual(waits,[258,258])
                    self.assertRaises(sqlite3.ProgrammingError,db.connection.execute,"SELECT 1")
                else: self.assertFalse(db.in_transaction)
                self.assertEqual(db.gate.name,self.mutex_name(s))
                self.assertEqual(self.probe(),0)
                self.assertEqual(s.open_package(self.store,"A").package.name,"dirty" if phase=="COMMITTED" else "A")

def load_tests(loader,tests,pattern):
    # Keep the20MiB case last; failures cannot hide behind a zero-test run.
    cases=[]
    def flatten(suite):
        for item in suite:
            if isinstance(item,unittest.TestSuite):flatten(item)
            else:cases.append(item)
    flatten(tests)
    return unittest.TestSuite(sorted(cases,key=lambda x:x._testMethodName=="test_native_maximum_capture_and_oversize"))
