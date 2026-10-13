"""Read-only fictional demo; contracts load without a GUI dependency."""
import hashlib
import json
import sys
from pathlib import Path

DEFAULT_MODEL = Path(__file__).with_name('display_data.json')
MODEL_SHA256 = '9f69eae322ac4066fa95284a7855c7570fa01976be6dd7940f13ec486f876406'
MODEL_BYTES = 12676
GROUP_IDS = ('HSMT', 'CV', 'M3')
ITEM_IDS = (tuple(f'H{i}' for i in range(1, 12)), ('CV1', 'CV2', 'CV3'),
            tuple(f'P{i}' for i in range(1, 8)))


def _validate(model):
    """Validate the display contract even when supplied directly by a caller."""
    def require(condition):
        if not condition:
            raise ValueError('Invalid fictional display model.')

    try:
        require(isinstance(model, dict))
        require(model['schema'] == 'synthetic_checklist_display_v1')
        require(model['synthetic'] is True)
        require(model['accepted_gold'] is False and model['read_originals_at_runtime'] is False)
        require(type(model['row_count']) is int and model['row_count'] == 21)
        require(type(model['goods_row_count']) is int and model['goods_row_count'] == 7)
        goods = model['goods']
        require(isinstance(goods, list) and tuple(i['id'] for i in goods) ==
                tuple(f'CVG{i}' for i in range(1, 8)))
        source = model['goods_source']
        for field in ('filename', 'section', 'technical_heading', 'equivalence_note'):
            require(isinstance(source[field], str) and 0 < len(source[field]) <= 2000)
        require(isinstance(source['sha256'], str) and len(source['sha256']) == 64)
        require(all(c in '0123456789abcdef' for c in source['sha256']))
        require(source['pdf_pages'] == [11, 12, 13, 14])
        for number, item in enumerate(goods, 1):
            require(item['stt'] == f'{number:02}')
            for field in ('name', 'quantity', 'unit', 'key_requirements',
                          'technical_text', 'status', 'uncertainty'):
                require(isinstance(item[field], str) and 0 < len(item[field]) <= 10000)
            pairs = item['parameter_pairs']
            require(isinstance(pairs, list) and len(pairs) == (8, 6, 8, 9, 6, 4, 3)[number - 1])
            for pair in pairs:
                require(isinstance(pair, list) and len(pair) == 2)
                require(all(isinstance(value, str) and 0 < len(value) <= 2000 for value in pair))
            require(item['quantity'].isascii() and item['quantity'].isdigit())
            require(item['result'] is None and item['evidence_assessed'] is False)
            for field in ('pdf_pages', 'catalogue_pages'):
                pages = item[field]
                require(isinstance(pages, list) and 0 < len(pages) <= 4)
                require(all(type(p) is int and p in source['pdf_pages'] for p in pages))
                require(len(set(pages)) == len(pages))
            require(all(p in item['pdf_pages'] for p in item['catalogue_pages']))
        for key in ('title', 'subtitle', 'scope_notice', 'uncertainty_notice', 'footer', 'authority'):
            require(isinstance(model[key], str) and bool(model[key]))
        groups = model['groups']
        require(isinstance(groups, list) and tuple(g['id'] for g in groups) == GROUP_IDS)
        blocks = model['source_blocks']
        require(isinstance(blocks, dict) and len(blocks) == 8)
        for block in blocks.values():
            for field in ('text', 'filename', 'page_kind'):
                require(isinstance(block[field], str) and bool(block[field]))
            require(len(block['text'].encode('utf-8')) <= 60000)
            require(isinstance(block['sha256'], str) and len(block['sha256']) == 64)
            require(all(c in '0123456789abcdef' for c in block['sha256']))
            require(isinstance(block['pdf_pages'], list) and bool(block['pdf_pages']))
            require(all(type(p) is int and 0 < p <= 1000 for p in block['pdf_pages']))
            require(block['full_not_clipped'] is True)
        for group, ids in zip(groups, ITEM_IDS):
            require(isinstance(group['name'], str) and bool(group['name']))
            require(isinstance(group['items'], list))
            require(tuple(item['id'] for item in group['items']) == ids)
            for item in group['items']:
                for field in ('title', 'condition', 'details', 'source', 'status'):
                    require(isinstance(item[field], str) and 0 < len(item[field]) <= 10000)
                require(isinstance(item['uncertainty'], str))
                require(item['result'] is None and item['evidence_assessed'] is False)
                refs = item['source_blocks']
                require(isinstance(refs, list) and 0 < len(refs) <= 8)
                require(all(isinstance(ref, str) and ref in blocks for ref in refs))
                require(len(set(refs)) == len(refs))
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError('Missing field or invalid type in demo model.') from error


def load_model(path: Path = DEFAULT_MODEL) -> dict:
    """Read at most one bounded model, requiring the exact approved byte hash."""
    with Path(path).open('rb') as stream:
        raw = stream.read(MODEL_BYTES + 1)
    if len(raw) != MODEL_BYTES or hashlib.sha256(raw).hexdigest() != MODEL_SHA256:
        raise ValueError('Demo bytes differ from bundled pinned fixture.')
    model = json.loads(raw)
    _validate(model)
    return model


def source_text(item, model):
    parts = []
    for key in item['source_blocks']:
        block = model['source_blocks'][key]
        parts.extend(("Fictional source: " + block['filename'],
                      block['page_kind'] + ': ' + ', '.join(map(str, block['pdf_pages'])),
                      'Demo text SHA256: ' + block['sha256'], block['text']))
    return '\n\n'.join(parts)


def _details(item):
    return '\n\n'.join((item['status'], item['condition'], item['details'], item['uncertainty'],
                           'Demo evidence: unassessed. No compliance result.'))


def goods_source_text(item, model):
    block = model['source_blocks']['DEMO_CV']
    return '\n\n'.join(('Fictional source: ' + block['filename'],
                           item['name'] + ' - ' + item['quantity'] + ' ' + item['unit'],
                           item['technical_text'], model['goods_source']['equivalence_note'],
                           'Demo text SHA256: ' + block['sha256'], block['text']))


class DisplayApp:
    def __init__(self, root, model: dict):
        global tk, tkfont, ttk
        import tkinter as tk
        import tkinter.font as tkfont
        from tkinter import ttk
        _validate(model)
        self.root = root
        self.model = model
        self.rows = []
        self.panes = []
        self.wrapped = []
        root.title(model['title'] + ' — ' + model['subtitle'])
        root.geometry('1100x720')
        root.minsize(960, 600)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(1, weight=1)
        tkfont.nametofont('TkDefaultFont').configure(size=10)
        tkfont.nametofont('TkTextFont').configure(size=10)
        tkfont.nametofont('TkHeadingFont').configure(size=14, weight='bold')
        style = ttk.Style(root)
        style.configure('Item.TLabel', font=('Segoe UI', 10, 'bold'))
        style.configure('Item.TButton', padding=(8, 6))
        header = ttk.Frame(root, padding=(16, 12, 16, 8))
        header.grid(row=0, column=0, sticky='ew')
        header.columnconfigure(0, weight=1)
        for number, key in enumerate(('title', 'subtitle', 'scope_notice', 'uncertainty_notice')):
            label = ttk.Label(header, text=model[key], wraplength=900,
                              font='TkHeadingFont' if number == 0 else 'TkDefaultFont')
            label.grid(row=number, column=0, sticky='w', pady=(0, 4))
            self.wrapped.append(label)
        self.tabs = ttk.Notebook(root)
        self.tabs.grid(row=1, column=0, sticky='nsew', padx=16)
        self.tabs.bind('<<NotebookTabChanged>>', lambda event: self._after_layout())
        for group in model['groups']:
            pane = self._pane(group)
            tab_text = (f"{group['name']} - 7 demo goods" if group['id'] == 'CV'
                        else f"{group['name']} · {len(group['items'])}")
            self.tabs.add(pane['frame'], text=tab_text)
            if group['id'] == 'CV':
                self._goods(pane)
            for number, item in enumerate(group['items']):
                self._row(pane, number + (2 if group['id'] == 'CV' else 0), item)
        footer = ttk.Frame(root, padding=(16, 8, 16, 12))
        footer.grid(row=2, column=0, sticky='ew')
        footer.columnconfigure(0, weight=1)
        for number, text in enumerate((model['footer'],
                                      '7 fictional goods and 21 demo notes; no real assessment.',
                                      'Tab moves focus; Enter / Space expands; Ctrl+C copies selected text; Esc closes.')):
            label = ttk.Label(footer, text=text, wraplength=900)
            label.grid(row=number, column=0, sticky='w', pady=(0, 3))
            self.wrapped.append(label)
        root.bind('<Configure>', self._resize)
        root.bind('<MouseWheel>', self._wheel)
        root.bind('<Escape>', lambda event: root.destroy())

    def _goods(self, pane):
        container = ttk.Frame(pane['content'], padding=(10, 0, 10, 4))
        container.grid(row=0, column=0, sticky='ew')
        container.columnconfigure(0, weight=1)
        choices = [f"Demo item {g['stt']} — {g['name']} — {g['quantity']} {g['unit']}"
                   for g in self.model['goods']]
        selector = ttk.Combobox(container, values=choices, state='readonly', takefocus=True)
        selector.grid(row=0, column=0, sticky='ew')
        self.goods_selector = selector
        state = {'item': None, 'pane': pane, 'source_open': False}
        self.goods_state = state
        summary = ttk.Label(container, style='Item.TLabel')
        summary.grid(row=1, column=0, sticky='w', pady=(3, 0))
        state['summary'] = summary
        heading = ttk.Label(container, text=self.model['goods_source']['technical_heading'])
        heading.grid(row=2, column=0, sticky='w', pady=(2, 2))
        ttk.Style(self.root).configure('Parameters.Treeview', rowheight=20, font=('Segoe UI', 10))
        tree = ttk.Treeview(container, columns=('parameter', 'required'), show='headings',
                            selectmode='browse', height=8, style='Parameters.Treeview', takefocus=True)
        for key, title, width in (('parameter', 'Parameter', 250), ('required', 'Demo value', 560)):
            tree.heading(key, text=title)
            tree.column(key, width=width, minwidth=220, stretch=True, anchor='w')
        tree.grid(row=3, column=0, sticky='ew')
        self.parameter_tree = tree
        tree.bind('<Control-c>', self._copy_parameter)
        status = ttk.Label(container, wraplength=900)
        status.grid(row=4, column=0, sticky='w', pady=(2, 0))
        state['status'] = status
        pane['labels'].append((status, False))
        detail = ttk.Frame(container)
        detail.grid(row=5, column=0, sticky='ew')
        detail.columnconfigure(0, weight=1)
        source_button = ttk.Button(detail, text='Show complete fictional source',
                                   command=lambda: self._toggle_source(state))
        source_button.grid(row=0, column=0, sticky='w', pady=(2, 0))
        source_frame = ttk.Frame(detail)
        source_frame.columnconfigure(0, weight=1)
        state['source_text'] = self._text(source_frame, '', 0, 12)
        state['source_frame'] = source_frame
        state['source_button'] = source_button
        self._button_keys(source_button, pane)
        selector.bind('<<ComboboxSelected>>', lambda event: self._select_goods())
        for key, move in (('<Up>', -1), ('<Down>', 1), ('<Home>', 'first'), ('<End>', 'last')):
            selector.bind(key, lambda event, m=move: self._goods_key(m))
        ttk.Separator(pane['content']).grid(row=1, column=0, sticky='ew')
        ttk.Label(pane['content'], text='Demo checklist notes',
                  style='Item.TLabel', padding=(10, 8)).grid(row=2, column=0, sticky='w')
        selector.current(0)
        self._select_goods()

    def _copy_parameter(self, event):
        selected = self.parameter_tree.selection()
        if selected:
            value = '\t'.join(self.parameter_tree.item(selected[0], 'values'))
            self.root.clipboard_clear()
            self.root.clipboard_append(value)
        return 'break'

    def _goods_key(self, move):
        current = self.goods_selector.current()
        count = len(self.model['goods'])
        index = (0 if move == 'first' else count - 1 if move == 'last'
                 else max(0, min(count - 1, current + move)))
        self.goods_selector.current(index)
        self._select_goods()
        return 'break'

    def _select_goods(self):
        index = self.goods_selector.current()
        if index < 0:
            return
        state = self.goods_state
        item = self.model['goods'][index]
        state.update(item=item, source_open=False)
        state['source_frame'].grid_remove()
        state['source_button'].configure(text='Show complete fictional source')
        state['summary'].configure(text=self.goods_selector.get())
        tree = self.parameter_tree
        tree.delete(*tree.get_children())
        tree.configure(height=len(item['parameter_pairs']))
        for number, pair in enumerate(item['parameter_pairs']):
            tree.insert('', 'end', iid=f"{item['id']}-{number}", values=pair)
        source = self.model['goods_source']
        state['status'].configure(text=f"{source['filename']} - Fictional page " +
                                  ', '.join(map(str, item['pdf_pages'])) +
                                  f" • {item['status']}\n{item['uncertainty']}")
        text = state['source_text']
        text.configure(state='normal')
        text.delete('1.0', 'end')
        text.insert('1.0', goods_source_text(item, self.model))
        text.configure(state='disabled')
        text.yview_moveto(0)
        self.root.update_idletasks()
        self._region(state['pane'])
        state['pane']['canvas'].yview_moveto(0)

    def _pane(self, group):
        frame = ttk.Frame(self.tabs)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        canvas = tk.Canvas(frame, highlightthickness=0, borderwidth=0,
                           background=ttk.Style(self.root).lookup('TFrame', 'background'))
        scroll = ttk.Scrollbar(frame, orient='vertical', command=canvas.yview)
        canvas.configure(yscrollcommand=scroll.set)
        canvas.grid(row=0, column=0, sticky='nsew')
        scroll.grid(row=0, column=1, sticky='ns')
        content = ttk.Frame(canvas, padding=(0, 6, 8, 0))
        content.columnconfigure(0, weight=1)
        window = canvas.create_window(0, 0, window=content, anchor='nw')
        pane = {'frame': frame, 'canvas': canvas, 'content': content, 'window': window,
                'labels': []}
        content.bind('<Configure>', lambda event, p=pane: self._region(p))
        canvas.bind('<Configure>', lambda event, p=pane: self._width(event, p))
        self.panes.append(pane)
        return pane

    def _row(self, pane, number, item):
        container = ttk.Frame(pane['content'], padding=(10, 8))
        container.grid(row=number * 2, column=0, sticky='ew')
        container.columnconfigure(0, weight=1)
        title = ttk.Label(container, text=item['title'], style='Item.TLabel', wraplength=720)
        title.grid(row=0, column=0, sticky='w', padx=(0, 12))
        pane['labels'].append((title, True))
        state = {'item': item, 'pane': pane, 'open': False, 'source_open': False}
        heading = ttk.Button(container, style='Item.TButton', width=15,
                             command=lambda s=state: self._toggle(s))
        heading.grid(row=0, column=1, sticky='ne')
        state['heading'] = heading
        for row, text in enumerate((item['condition'], item['source'] + ' · ' + item['status']), 1):
            label = ttk.Label(container, text=text, wraplength=900)
            label.grid(row=row, column=0, columnspan=2, sticky='w', pady=(4, 0))
            pane['labels'].append((label, False))
        detail = ttk.Frame(container, padding=(0, 10, 0, 4))
        detail.columnconfigure(0, weight=1)
        state['detail'] = detail
        self._text(detail, _details(item), 0, 8)
        source_button = ttk.Button(detail, text='Show complete fictional source',
                                   command=lambda s=state: self._toggle_source(s))
        source_button.grid(row=1, column=0, sticky='w', pady=(8, 0))
        source_frame = ttk.Frame(detail)
        source_frame.columnconfigure(0, weight=1)
        self._text(source_frame, source_text(item, self.model), 0, 12)
        state['source_frame'] = source_frame
        state['source_button'] = source_button
        self._button_keys(heading, pane)
        self._button_keys(source_button, pane)
        self.rows.append(state)
        self._heading(state)
        ttk.Separator(pane['content']).grid(row=number * 2 + 1, column=0, sticky='ew')

    def _text(self, parent, content, row, height):
        frame = ttk.Frame(parent)
        frame.grid(row=row, column=0, sticky='ew')
        frame.columnconfigure(0, weight=1)
        text = tk.Text(frame, wrap='word', width=1, height=height, font='TkTextFont',
                       padx=10, pady=8, relief='sunken', borderwidth=1, takefocus=True)
        scroll = ttk.Scrollbar(frame, orient='vertical', command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        text.grid(row=0, column=0, sticky='ew')
        scroll.grid(row=0, column=1, sticky='ns')
        text.insert('1.0', content)
        text.configure(state='disabled')
        text.bind('<FocusIn>', lambda event: self._focus(event.widget))
        return text

    def _button_keys(self, button, pane):
        def activate(event):
            button.invoke()
            return 'break'
        button.bind('<Return>', activate)
        button.bind('<space>', activate)
        button.bind('<FocusIn>', lambda event: self._reveal(event.widget, pane))

    def _heading(self, state):
        state['heading'].configure(text=state['item']['id'] + ' · ' +
                                  ('Collapse' if state['open'] else 'Details'))

    def _toggle(self, state):
        state['open'] = not state['open']
        if state['open']:
            state['detail'].grid(row=3, column=0, columnspan=2, sticky='ew')
        else:
            state['detail'].grid_remove()
        self._heading(state)
        self.root.update_idletasks()
        self._region(state['pane'])
        self._reveal(state['heading'], state['pane'])

    def _toggle_source(self, state):
        state['source_open'] = not state['source_open']
        if state['source_open']:
            state['source_frame'].grid(row=2, column=0, sticky='ew', pady=(8, 0))
        else:
            state['source_frame'].grid_remove()
        state['source_button'].configure(text='Collapse source' if state['source_open']
                                         else 'Show complete fictional source')
        self.root.update_idletasks()
        self._region(state['pane'])
        self._reveal(state['source_button'], state['pane'])

    def _region(self, pane):
        pane['canvas'].configure(scrollregion=pane['canvas'].bbox('all'))

    def _width(self, event, pane):
        pane['canvas'].itemconfigure(pane['window'], width=event.width)
        for label, title in pane['labels']:
            label.configure(wraplength=max(100, event.width - (210 if title else 40)))

    def _resize(self, event):
        if event.widget is self.root:
            for label in self.wrapped:
                label.configure(wraplength=max(100, event.width - 40))
            self._after_layout()

    def _after_layout(self):
        self.root.after_idle(lambda: self._focus(self.root.focus_get()))

    def _focus(self, widget):
        pane = self.panes[self.tabs.index('current')]
        if str(widget).startswith(str(pane['frame']) + '.'):
            self._reveal(widget, pane)

    def _reveal(self, widget, pane):
        self.root.update_idletasks()
        content, canvas = pane['content'], pane['canvas']
        total = max(content.winfo_height(), 1)
        top = widget.winfo_rooty() - content.winfo_rooty()
        visible_top = canvas.canvasy(0)
        visible_height = canvas.winfo_height()
        bottom = top + min(widget.winfo_height(), visible_height)
        if top < visible_top:
            canvas.yview_moveto(max(0, top) / total)
        elif bottom > visible_top + visible_height:
            canvas.yview_moveto(max(0, bottom - visible_height) / total)

    def _wheel(self, event):
        if not isinstance(event.widget, tk.Text):
            pane = self.panes[self.tabs.index('current')]
            direction = -1 if event.delta > 0 else 1
            pane['canvas'].yview_scroll(direction * max(1, abs(event.delta) // 120), 'units')
            return 'break'


def main(argv=None):
    if list(sys.argv[1:] if argv is None else argv):
        print('Usage: display.py (bundled fictional fixture only)', file=sys.stderr)
        return 2
    try:
        model = load_model()
    except (OSError, ValueError) as error:
        print('Cannot load demo: ' + str(error), file=sys.stderr)
        return 2
    import tkinter as tk
    root = tk.Tk()
    DisplayApp(root, model)
    root.mainloop()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
