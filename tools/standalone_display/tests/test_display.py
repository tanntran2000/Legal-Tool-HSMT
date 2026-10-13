"""Fictional display contracts. Portable methods never require Tk."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

APP = Path(__file__).resolve().parents[1] / 'display.py'
COUNTS = [8, 6, 8, 9, 6, 4, 3]


def display():
    if not APP.is_file():
        raise AssertionError('standalone display implementation is missing')
    spec = importlib.util.spec_from_file_location('synthetic_display', APP)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DisplayPortableContract(unittest.TestCase):
    def setUp(self):
        self.app = display()
        self.model = self.app.load_model()

    def test_fictional_model_inventory(self):
        m = self.model
        self.assertTrue(m['synthetic'])
        self.assertIn('DEMO', m['title'])
        self.assertIn('fictional', m['scope_notice'])
        self.assertFalse(m['accepted_gold'])
        self.assertFalse(m['read_originals_at_runtime'])
        self.assertEqual([g['id'] for g in m['groups']], ['HSMT', 'CV', 'M3'])
        self.assertEqual(sum(len(g['items']) for g in m['groups']), 21)
        self.assertEqual(len(m['source_blocks']), 8)
        self.assertEqual(len(m['goods']), 7)
        self.assertEqual([len(g['parameter_pairs']) for g in m['goods']], COUNTS)
        self.assertEqual(sum(COUNTS), 44)
        for row in m['goods'] + [i for g in m['groups'] for i in g['items']]:
            self.assertIsNone(row['result'])
            self.assertIs(row['evidence_assessed'], False)
            self.assertIn('Demo', row['status'])

    def test_pin_rejects_changed_short_and_oversized_bytes(self):
        raw = APP.with_name('display_data.json').read_bytes()
        import hashlib
        self.assertEqual(len(raw), self.app.MODEL_BYTES)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), self.app.MODEL_SHA256)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'fictional.json'
            for bad in [raw[:-1], raw + b' ', raw.replace(b'DEMO', b'TEST', 1), b'x' * 32769]:
                path.write_bytes(bad)
                with self.assertRaises(ValueError):
                    self.app.load_model(path)

    def test_contract_rejects_false_assessment_and_wrong_inventory(self):
        for field, value in [('synthetic', False), ('accepted_gold', True),
                             ('read_originals_at_runtime', True), ('row_count', True)]:
            m = deepcopy(self.model); m[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.app._validate(m)
        for mutate in [lambda m: m['goods'][0].update(result='pass'),
                       lambda m: m['goods'][0].update(evidence_assessed=True),
                       lambda m: m['goods'][0]['parameter_pairs'].pop(),
                       lambda m: m['goods'][0]['parameter_pairs'][0].__setitem__(1, 3),
                       lambda m: m['groups'][0]['items'][0].update(source_blocks=['missing']),
                       lambda m: m['source_blocks'].pop(next(iter(m['source_blocks']))),
                       lambda m: m['goods'][0].update(pdf_pages=[True]),
                       lambda m: m['goods'][0].update(quantity='../file')]:
            m = deepcopy(self.model); mutate(m)
            with self.assertRaises(ValueError):
                self.app._validate(m)

    def test_source_composition_preserves_complete_fictional_blocks(self):
        for group in self.model['groups']:
            for row in group['items']:
                text = self.app.source_text(row, self.model)
                for key in row['source_blocks']:
                    block = self.model['source_blocks'][key]
                    self.assertIn(block['text'], text)
                    self.assertIn(block['sha256'], text)
        for good in self.model['goods']:
            text = self.app.goods_source_text(good, self.model)
            self.assertIn(good['technical_text'], text)
            self.assertIn(self.model['source_blocks']['DEMO_CV']['text'], text)
            self.assertIn('fictional', text)

    def test_no_gui_dependency_on_import_and_model_paths(self):
        script = """import importlib.abc, importlib.util, sys
class NoTk(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'tkinter' or fullname.startswith('tkinter.'):
            raise ImportError('Tk unavailable in portable contract')
sys.meta_path.insert(0, NoTk())
spec = importlib.util.spec_from_file_location('demo', sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
m.load_model()
assert not any(x.startswith('tkinter') for x in sys.modules)
"""
        run = subprocess.run([sys.executable, '-X', 'utf8', '-B', '-c', script, str(APP)],
                             capture_output=True, text=True, timeout=15)
        self.assertEqual(run.returncode, 0, run.stderr)

    def test_cli_rejects_arguments_without_opening_ui(self):
        run = subprocess.run([sys.executable, '-X', 'utf8', '-B', str(APP), 'extra'],
                             capture_output=True, text=True, timeout=15)
        self.assertEqual(run.returncode, 2)
        self.assertIn('Usage', run.stderr)


class DisplayNativeUI(unittest.TestCase):
    def setUp(self):
        self.app = display()
        import tkinter as tk
        self.root = tk.Tk()
        self.addCleanup(self.root.destroy)
        self.ui = self.app.DisplayApp(self.root, self.app.load_model())
        self.ui.tabs.select(1)
        self.root.update()

    def test_primary_parameters_all_goods_both_sizes(self):
        for size in ['960x600', '1100x720']:
            self.root.geometry(size)
            for index, count in enumerate(COUNTS):
                self.ui.goods_selector.current(index); self.ui._select_goods()
                self.root.update()
                tree = self.ui.parameter_tree
                self.assertTrue(tree.winfo_ismapped())
                self.assertEqual(len(tree.get_children()), count)
                self.assertEqual(int(tree['height']), count)
                self.assertFalse(self.ui.goods_state['source_open'])
                self.assertFalse(self.ui.goods_state['source_frame'].winfo_ismapped())
                canvas = self.ui.goods_state['pane']['canvas']
                self.assertGreaterEqual(tree.winfo_rooty(), canvas.winfo_rooty())
                self.assertLessEqual(tree.winfo_rooty() + tree.winfo_height(),
                                     canvas.winfo_rooty() + canvas.winfo_height())

    def test_secondary_source_readonly_and_selection_resets(self):
        state = self.ui.goods_state
        self.ui._toggle_source(state); self.root.update()
        self.assertTrue(state['source_frame'].winfo_ismapped())
        self.assertEqual(str(state['source_text']['state']), 'disabled')
        expected = self.app.goods_source_text(state['item'], self.ui.model)
        self.assertEqual(state['source_text'].get('1.0', 'end-1c'), expected)
        self.ui._goods_key(1); self.root.update()
        self.assertFalse(state['source_open'])
        self.assertFalse(state['source_frame'].winfo_ismapped())

    def test_keyboard_goods_copy_and_button_activation(self):
        for move, expected in [('last', 6), (1, 6), ('first', 0), (-1, 0), (1, 1)]:
            self.assertEqual(self.ui._goods_key(move), 'break')
            self.assertEqual(self.ui.goods_selector.current(), expected)
        tree = self.ui.parameter_tree
        row = tree.get_children()[0]; tree.selection_set(row)
        self.assertEqual(self.ui._copy_parameter(None), 'break')
        self.assertEqual(self.root.clipboard_get(), '\t'.join(tree.item(row, 'values')))
        button = self.ui.goods_state['source_button']
        button.focus_force(); self.root.update()
        button.event_generate('<Return>'); self.root.update()
        self.assertTrue(self.ui.goods_state['source_open'])
        button.event_generate('<space>'); self.root.update()
        self.assertFalse(self.ui.goods_state['source_open'])

    def test_checklist_expansion_and_readonly_source(self):
        self.assertEqual(len(self.ui.rows), 21)
        for index in [0, 11, 14]:
            state = self.ui.rows[index]
            self.ui.tabs.select(self.ui.panes.index(state['pane']))
            self.ui._toggle(state); self.ui._toggle_source(state); self.root.update()
            self.assertTrue(state['open'])
            self.assertTrue(state['source_open'])
            self.assertTrue(state['source_frame'].winfo_ismapped())
            self.ui._toggle(state); self.root.update()
            self.assertFalse(state['detail'].winfo_ismapped())


if __name__ == '__main__':
    names = [DisplayPortableContract] + ([DisplayNativeUI] if sys.platform == 'win32' else [])
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(c) for c in names)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() and not result.skipped else 1)
