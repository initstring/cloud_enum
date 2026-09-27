import os
import sys

import cloud_enum


def test_default_wordlists_resolve_when_run_as_console_script(monkeypatch):
    """
    `uv run cloud_enum` launches the console-script shim in .venv/bin, so the
    default wordlists must not be located relative to sys.argv[0].
    """
    shim = os.path.join(os.sep, 'nonexistent', '.venv', 'bin', 'cloud_enum')
    monkeypatch.setattr(sys, 'argv', [shim, '-k', 'test'])

    args = cloud_enum.parse_arguments()

    assert os.access(args.mutations, os.R_OK)
    assert os.access(args.brute, os.R_OK)
