#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Validate a complete SparkLink QEMU run, independently of its PASS marker."""

import argparse
from pathlib import Path
import re


KSFT_SKIP = 4
KERNEL_FAULT = re.compile(
    r"(?:^|\n)[ \t]*(?:<\d+>)?(?:\[[^\]\n]+\][ \t]*)*"
    r"(?:BUG:|kernel BUG|WARNING:|Kernel panic|Oops:|general protection fault|"
    r"KASAN:|KCSAN:|UBSAN:|Internal error:|Unable to handle kernel|"
    r"possible circular locking dependency|"
    r"INFO: task .+ blocked for more than|"
    r"rcu:.*(?:stall|stalls)|watchdog:.*(?:lockup|LOCKUP))"
    r"|BUG: (?:sleeping function called|scheduling while atomic)"
)


def assess(console, expected, qemu_exit, expected_usb):
    """Return (exit status, reasons); only a complete, clean run returns zero."""
    errors = []
    if qemu_exit:
        errors.append("QEMU timed out" if qemu_exit == 124 else
                      f"QEMU exited with status {qemu_exit}")
    if not expected or len(set(expected)) != len(expected) or any(
            not re.fullmatch(r"test_\w+", name) for name in expected):
        errors.append("invalid or empty expected-case manifest")
    if KERNEL_FAULT.search(console):
        errors.append("kernel exception or diagnostic warning in console")
    begin = re.findall(r"^SPARKLINK_KERNEL_LOG_BEGIN$", console, re.MULTILINE)
    end = re.findall(r"^SPARKLINK_KERNEL_LOG_END$", console, re.MULTILINE)
    if len(begin) != 1 or len(end) != 1:
        errors.append("missing or duplicate complete kernel log")
    else:
        first = console.index("SPARKLINK_KERNEL_LOG_BEGIN")
        last = console.index("SPARKLINK_KERNEL_LOG_END")
        ring = console[first:last]
        if first >= last or not re.search(r"^\[\s*0\.000000\]", ring, re.MULTILINE):
            errors.append("kernel log reversed, empty or missing early records")
    if re.search(r"^\s*FAIL:", console, re.MULTILINE):
        errors.append("test assertion failure in console")

    records = re.findall(r"^SPARKLINK_CASE_(BEGIN|END): (\w+)(?: (\w+))?$",
                         console, re.MULTILINE)
    names = re.findall(r"^SPARKLINK_CASE_(?:BEGIN|END):.*$", console, re.MULTILINE)
    if len(records) != len(names) or len(records) != 2 * len(expected):
        errors.append("missing, duplicate or malformed case records")
    skipped_cases = 0
    for index, name in enumerate(expected):
        offset = 2 * index
        if offset + 1 >= len(records):
            break
        begin, end = records[offset:offset + 2]
        if begin != ("BEGIN", name, "") or end[:2] != ("END", name):
            errors.append(f"case order or identity mismatch at {name}")
            break
        if end[2] not in ("PASS", "FAIL", "SKIP"):
            errors.append(f"invalid case result for {name}")
        elif end[2] == "FAIL":
            errors.append(f"case failed: {name}")
        elif end[2] == "SKIP":
            skipped_cases += 1

    summaries = re.findall(
        r"^SPARKLINK_TEST_SUMMARY: cases=(\d+) failed=(\d+) skipped=(\d+)$",
        console, re.MULTILINE)
    summary_lines = re.findall(r"^SPARKLINK_TEST_SUMMARY:.*$", console, re.MULTILINE)
    skipped_checks = 0
    if len(summaries) != 1 or len(summary_lines) != 1:
        errors.append("missing or ambiguous suite summary")
    else:
        cases, failures, skipped_checks = map(int, summaries[0])
        if cases != len(expected):
            errors.append("suite case count does not match expected manifest")
        if failures:
            errors.append(f"suite reports {failures} failed assertions")
        if bool(skipped_cases) != bool(skipped_checks):
            errors.append("case and suite skip counts disagree")
        if skipped_checks != len(re.findall(r"^\s*SKIP:", console, re.MULTILINE)):
            errors.append("reported and logged skipped checks disagree")
    if console.count("=== All tests completed ===") != 1:
        errors.append("missing or ambiguous suite completion record")

    usb_records = re.findall(
        r"^SPARKLINK_USB_GATE: PASS expected=(\d+) found=(\d+) bound=(\d+)$",
        console, re.MULTILINE)
    usb_lines = re.findall(r"^SPARKLINK_USB_GATE:.*$", console, re.MULTILINE)
    if expected_usb <= 0 or len(usb_lines) != 1 or \
            usb_records != [tuple([str(expected_usb)] * 3)]:
        errors.append("requested USB controller count was not verified")

    results = re.findall(r"^QEMU_TEST_RESULT: (PASS|FAIL|SKIP) \(exit=(\d+)\)$",
                         console, re.MULTILINE)
    result_lines = re.findall(r"^QEMU_TEST_RESULT:.*$", console, re.MULTILINE)
    skipped = skipped_checks > 0 or skipped_cases > 0
    required_result = ("SKIP", str(KSFT_SKIP)) if skipped else ("PASS", "0")
    if len(result_lines) != 1 or results != [required_result]:
        errors.append("guest result/exit status does not match suite outcome")
    if errors:
        return 1, errors
    if skipped:
        return KSFT_SKIP, [f"suite incomplete: {skipped_checks} skipped checks"]
    return 0, [f"all {len(expected)} expected cases completed without failures"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--console", type=Path, required=True)
    parser.add_argument("--expected-cases", type=Path, required=True)
    parser.add_argument("--qemu-exit", type=int, required=True)
    parser.add_argument("--expected-usb", type=int, required=True)
    args = parser.parse_args()
    try:
        status, reasons = assess(args.console.read_text(errors="replace"),
                                 args.expected_cases.read_text().splitlines(),
                                 args.qemu_exit, args.expected_usb)
    except OSError as error:
        status, reasons = 1, [str(error)]
    verdict = "PASS" if status == 0 else "SKIP" if status == KSFT_SKIP else "FAIL"
    for reason in reasons:
        print(f"QEMU_VERDICT: {verdict}: {reason}")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
