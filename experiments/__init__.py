"""Experiment scripts for the learned structural baselines reported in the FLINT paper.

These are the scripts behind the learned-baseline, label-aware transfer and
white-box adaptive-mimicry results, released so the reported protocol can be
checked and re-run rather than taken on trust. The protocol constants
(split fraction, epochs, seeds, widths, thresholds) are module-level names in
``learned_baseline`` and ``label_aware_baseline``; the paper's appendix prints
those same values, imported from here, so the documented protocol and the
executed protocol cannot drift apart.

Requires the optional extra:  pip install -e '.[experiments]'
"""
