"""Bound untrusted historical data before copying, normalizing or rendering it."""

import math
from dataclasses import fields, is_dataclass

MAX_PAYLOAD_BYTES = 16 * 1024 * 1024
MAX_DATA_NODES = 200_000
MAX_DATA_DEPTH = 40
MAX_FINDINGS = 512


class DataValidationError(ValueError):
    """Unsupported/corrupt data; callers must preserve the original source."""


def check_payload_size(payload: str) -> int:
    if not isinstance(payload, str) or len(payload) > MAX_PAYLOAD_BYTES:
        raise DataValidationError("Historical payload exceeds the supported size or type")
    try:
        size = len(payload.encode("utf-8"))
        if size > MAX_PAYLOAD_BYTES:
            raise DataValidationError("Historical payload exceeds the supported byte limit")
        return size
    except UnicodeEncodeError as exc:
        raise DataValidationError("Historical data contains invalid Unicode") from exc


def _children(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise DataValidationError("Historical object keys must be strings")
            yield key
            yield item
    elif is_dataclass(value) and not isinstance(value, type):
        for entry in fields(value):
            yield entry.name
            yield getattr(value, entry.name)
    else:
        yield from value


def validate_data_size(value: object) -> None:
    """Walk iterators with bounded depth/size, without recursive copies or dumps."""
    stack = [(iter((value,)), 0)]
    nodes = size = 0
    while stack:
        iterator, depth = stack[-1]
        try:
            item = next(iterator)
        except StopIteration:
            stack.pop()
            continue
        nodes += 1
        if nodes > MAX_DATA_NODES:
            raise DataValidationError("Historical data exceeds the supported item limit")
        if isinstance(item, str):
            size += check_payload_size(item)
        elif item is None or type(item) in (bool, int, float):
            if (type(item) is float and not math.isfinite(item)) or (
                type(item) is int and item.bit_length() > 64
            ):
                raise DataValidationError("Historical data contains an unsupported number")
            size += 16
        elif isinstance(item, (dict, list, tuple)) or (is_dataclass(item) and not isinstance(item, type)):
            if depth >= MAX_DATA_DEPTH:
                raise DataValidationError("Historical data exceeds the supported nesting limit")
            stack.append((iter(_children(item)), depth + 1))
        else:
            raise DataValidationError("Historical data contains an unsupported value")
        if size > MAX_PAYLOAD_BYTES:
            raise DataValidationError("Historical data exceeds the supported content limit")
