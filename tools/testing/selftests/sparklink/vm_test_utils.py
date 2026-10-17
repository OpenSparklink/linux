#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Shared guest artifact/QMP helpers; no protocol Engine or qualification."""
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import time
HERE = Path(__file__).resolve().parent

def file_record(path):
    path = Path(path).resolve()
    return dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest())


def wait_marker(process, console, marker):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        data = console.read_text(errors='replace') if console.exists() else ''
        if marker in data:
            return
        if 'RUNTIME_FAILURE:' in data or 'NATIVE_FAILURE:' in data:
            # Let init print dmesg and power off before terminating a failed VM.
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            raise RuntimeError(f'guest assertion before {marker}')
        if process.poll() is not None:
            raise RuntimeError(f'guest stopped before {marker}')
        time.sleep(0.05)
    raise TimeoutError(f'guest deadline for {marker}')


def load_qmp():
    spec = importlib.util.spec_from_file_location('runtime_lab_qmp', HERE / 'ws73-lab.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.Qmp


