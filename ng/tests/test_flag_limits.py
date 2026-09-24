#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2011-2026 Sergey Shekyan and contributors
"""A shared flag must mean the same thing in both tools.

ng and classic parse the same single-letter options with two independent
parsers, so an upper bound added to one of them silently stops matching the
other. That has already happened: -x was capped at 65536 in classic to stop an
unbounded value throwing std::length_error, and ng went on accepting INT_MAX
for the same flag.

This reads the bound out of each parser's source and compares them. It is a
test-time read of a sibling directory, not a build dependency -- if classic's
tree is not present (ng built standalone), the test skips.
"""
import re
import sys

# -c is the one flag allowed to differ, and the difference is real rather than
# drift: classic may be built against select(), which cannot watch a descriptor
# at or above FD_SETSIZE, while every ng reactor backend polls by descriptor.
EXEMPT = {"c"}

# Both parsers default to INT_MAX when a call site passes no bound.
DEFAULT_MAX = 2147483647


def ng_limits(path):
    """{flag: max} from parse_positive(tmp, 'f'[, max]) call sites."""
    src = open(path, encoding="utf-8").read()
    out = {}
    for flag, arg in re.findall(
            r"parse_positive\(\s*\w+\s*,\s*'(\w)'\s*(?:,\s*([0-9]+)L?\s*)?\)", src):
        out[flag] = int(arg) if arg else DEFAULT_MAX
    return out


def classic_limits(path):
    """{flag: max} by pairing each `case 'f':` with the parse_int() under it."""
    src = open(path, encoding="utf-8").read()
    out = {}
    # Split on case labels so a bound is attributed to the flag above it, not
    # to whichever flag happens to be nearest in the file.
    parts = re.split(r"\bcase\s+'(\w)'\s*:", src)
    for i in range(1, len(parts) - 1, 2):
        flag, body = parts[i], parts[i + 1]
        m = re.search(r"parse_int\(\s*\w+\s*(?:,\s*([0-9]+)L?\s*)?\)", body)
        if m:
            out[flag] = int(m.group(1)) if m.group(1) else DEFAULT_MAX
    return out


def main():
    if len(sys.argv) != 3:
        print("usage: test_flag_limits.py <ng cli.cpp> <classic main.cc>")
        return 2
    ng_path, classic_path = sys.argv[1], sys.argv[2]
    try:
        classic = classic_limits(classic_path)
    except OSError:
        print("SKIP: classic sources not present at %s" % classic_path)
        return 0
    ng = ng_limits(ng_path)

    # A parser that yields nothing means the regex stopped matching the source,
    # not that the two agree. Without this the test passes vacuously forever.
    if len(ng) < 10 or len(classic) < 10:
        print("FAIL: parsed %d ng and %d classic bounds; the source shape "
              "changed and this test is no longer reading it" % (len(ng), len(classic)))
        return 1

    shared = sorted((set(ng) & set(classic)) - EXEMPT)
    if not shared:
        print("FAIL: no shared flags found")
        return 1

    bad = [(f, classic[f], ng[f]) for f in shared if classic[f] != ng[f]]
    for flag, c, n in bad:
        print("FAIL: -%s max is %d in classic but %d in ng" % (flag, c, n))
    if bad:
        print("\nPick one bound and set it in both parsers, or add the flag to "
              "EXEMPT here with a comment saying why the tools differ.")
        return 1

    print("ok: %d shared flags agree (%s); -%s exempt"
          % (len(shared), " ".join("-" + f for f in shared), " -".join(sorted(EXEMPT))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
