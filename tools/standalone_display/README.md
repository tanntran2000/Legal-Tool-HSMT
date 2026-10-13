# Fictional parameter display demo

All goods, names, quantities, parameters, source texts and hashes in this standalone example are synthetic. HSMT, CV and M3 are demonstration tabs. This is not a real tender, accepted reference, legal opinion or compliance assessment.

Run `python -X utf8 -B tools/standalone_display/display.py` from the checkout with Python and Tk available. The app reads only the bounded, byte-pinned bundled JSON fixture. It does not read PDFs, connect to a backend, or save edits.

The CV tab shows seven imaginary exhibit goods. Their 44 parameter pairs (8/6/8/9/6/4/3) stay visible as the primary table. Complete fictional source text is secondary, expandable and read-only. The three tabs also contain 21 illustrative checklist notes and eight fictional source blocks.

Use Tab to move focus, Up/Down/Home/End to choose a good, Enter or Space to expand a focused button, Ctrl+C to copy a selected parameter row or source text, and Esc to close. Selecting another good collapses its source view. Minimum window: 960x600.

Run `python -X utf8 -B tools/standalone_display/tests/test_display.py` for contracts and, on Windows, native UI tests. CI explicitly includes the portable contracts on Linux without importing Tk; Windows additionally requires the native UI class. No required tests are skipped.
