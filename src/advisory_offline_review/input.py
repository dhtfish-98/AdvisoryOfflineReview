# SPDX-License-Identifier: Apache-2.0
# New AI-assisted implementation, 2026-10-02. See ORIGIN.md and LICENSE.
"""Bounded strict JSON and POSIX non-following ordinary-file reads."""

import json
import math
import os
import stat

from .contracts import Rejected


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Rejected("duplicate_json_key")
        result[key] = value
    return result


def _constant(value):
    raise Rejected("nonfinite_json_number")


def _integer(value):
    if len(value.lstrip("-")) > 20:
        raise Rejected("json_integer_budget")
    return int(value)


def strict_json(data, maximum, limits):
    if type(data) is not bytes or len(data) > maximum:
        raise Rejected("json_bytes_contract_or_budget")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise Rejected("json_utf8_required") from None
    # Check structural depth BEFORE the recursive stdlib JSON decoder.
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > limits.depth:
                raise Rejected("json_depth_budget")
        elif char in "]}":
            depth -= 1
    try:
        obj = json.loads(
            text, object_pairs_hook=_pairs, parse_constant=_constant, parse_int=_integer
        )
    except (ValueError, RecursionError) as error:
        if isinstance(error, Rejected):
            raise
        raise Rejected("invalid_json") from None
    pending, count = [obj], 0
    while pending:
        item = pending.pop()
        count += 1
        if count > limits.nodes:
            raise Rejected("json_node_budget")
        if type(item) is dict:
            pending.extend(item.keys())
            pending.extend(item.values())
        elif type(item) is list:
            pending.extend(item)
        elif type(item) is str:
            if any(0xD800 <= ord(c) <= 0xDFFF for c in item):
                raise Rejected("json_surrogate_unsupported")
        elif type(item) is float and not math.isfinite(item):
            raise Rejected("nonfinite_json_number")
    return obj


def read_regular_file(path, maximum):
    if type(maximum) is not int or not 1 <= maximum <= 4194304:
        raise Rejected("read_budget_contract")
    flags = ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK", "O_CLOEXEC")
    if (
        os.name != "posix"
        or os.open not in os.supports_dir_fd
        or not all(hasattr(os, f) for f in flags)
    ):
        raise Rejected("safe_read_unavailable")
    path = os.fspath(path)
    if (
        type(path) is not str
        or not path
        or len(path) > 4096
        or "\0" in path
        or ".." in path.split("/")
    ):
        raise Rejected("local_path_contract")
    parts = [x for x in os.path.abspath(path).split("/") if x]
    if not parts:
        raise Rejected("regular_file_required")
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    leaf = None
    try:
        for part in parts[:-1]:
            child = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory
            )
            os.close(directory)
            directory = child
        leaf = os.open(
            parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory
        )
        before = os.fstat(leaf)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise Rejected("regular_file_budget")
        chunks, size = [], 0
        while size <= maximum:
            chunk = os.read(leaf, min(65536, maximum + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        after = os.fstat(leaf)

        def identity(info):
            return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

        if size > maximum or size != after.st_size or identity(before) != identity(after):
            raise Rejected("input_changed_or_budget")
        return b"".join(chunks)
    finally:
        if leaf is not None:
            os.close(leaf)
        os.close(directory)
