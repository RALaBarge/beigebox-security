"""Minimal YAML subset for beigebox (Python 3.11+, zero deps).

Supports the block-style YAML used in config.yaml and runtime_config.yaml:
  - Block mappings and sequences (nested)
  - Sequences of mappings (- key: val / key2: val2)
  - Scalars: str, int, float, bool, null
  - Quoted strings (single + double)
  - Inline comments
  - safe_load accepts str, bytes, or file-like objects
  - dump with default_flow_style=False, allow_unicode=True, sort_keys=False

Does NOT support: anchors, aliases, tags, multi-document streams, flow
style blocks, block scalars (| >), complex keys.
"""
from __future__ import annotations

import re
from typing import Any, IO


class YAMLError(ValueError):
    pass


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def safe_load(stream: str | bytes | IO) -> Any:
    if hasattr(stream, "read"):
        stream = stream.read()
    if isinstance(stream, bytes):
        stream = stream.decode("utf-8")
    lines = stream.splitlines()
    value, _ = _parse_value(lines, 0, 0)
    return value


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _is_blank(line: str) -> bool:
    s = line.strip()
    return not s or s.startswith("#")


def _skip_blank(lines: list[str], pos: int) -> int:
    while pos < len(lines) and _is_blank(lines[pos]):
        pos += 1
    return pos


def _parse_value(lines: list[str], min_indent: int, pos: int) -> tuple[Any, int]:
    """Parse a YAML value starting at pos, requiring indent >= min_indent."""
    pos = _skip_blank(lines, pos)
    if pos >= len(lines):
        return None, pos

    ind = _indent(lines[pos])
    if ind < min_indent:
        return None, pos

    stripped = lines[pos].strip()

    # Detect block type from first content line
    if re.match(r"^- ", stripped) or stripped == "-":
        return _parse_sequence(lines, ind, pos)
    elif ":" in stripped:
        return _parse_mapping(lines, ind, pos)
    else:
        return _parse_scalar(stripped), pos + 1


def _parse_sequence(lines: list[str], block_indent: int, pos: int) -> tuple[list, int]:
    result: list[Any] = []
    while pos < len(lines):
        pos = _skip_blank(lines, pos)
        if pos >= len(lines):
            break
        ind = _indent(lines[pos])
        if ind < block_indent:
            break
        stripped = lines[pos].strip()
        if ind == block_indent and (stripped.startswith("- ") or stripped == "-"):
            after_dash = stripped[1:].strip() if len(stripped) > 1 else ""
            if not after_dash:
                # Nested value on following lines
                val, pos = _parse_value(lines, block_indent + 2, pos + 1)
                result.append(val)
            elif ":" in after_dash and not _looks_like_scalar(after_dash):
                # Sequence of mappings: "- key: value"
                # Build a mini-mapping block from this line + subsequent same-indent continuation lines
                mapping_lines = [" " * (block_indent + 2) + after_dash]
                pos += 1
                while pos < len(lines):
                    if _is_blank(lines[pos]):
                        pos += 1
                        continue
                    item_ind = _indent(lines[pos])
                    if item_ind <= block_indent:
                        break
                    mapping_lines.append(lines[pos])
                    pos += 1
                val, _ = _parse_mapping(mapping_lines, block_indent + 2, 0)
                result.append(val)
            else:
                result.append(_parse_scalar(after_dash))
                pos += 1
        else:
            break
    return result, pos


def _parse_mapping(lines: list[str], block_indent: int, pos: int) -> tuple[dict, int]:
    result: dict[str, Any] = {}
    while pos < len(lines):
        pos = _skip_blank(lines, pos)
        if pos >= len(lines):
            break
        ind = _indent(lines[pos])
        if ind < block_indent:
            break
        line = lines[pos]
        stripped = line.strip()
        # Skip sequence items that sneak in (shouldn't happen in a mapping context)
        if stripped.startswith("- "):
            break

        colon_idx = _find_key_colon(stripped)
        if colon_idx == -1:
            pos += 1
            continue

        key = stripped[:colon_idx].strip()
        raw_value = stripped[colon_idx + 1:].strip()
        # Strip inline comment from raw_value
        raw_value = _strip_inline_comment(raw_value)
        pos += 1

        if raw_value:
            # Check for | or > block scalars (minimal support: collect as empty string)
            if raw_value in ("|", ">", "|-", ">-"):
                # Consume indented continuation lines
                val_lines = []
                while pos < len(lines):
                    if _is_blank(lines[pos]):
                        pos += 1
                        continue
                    child_ind = _indent(lines[pos])
                    if child_ind <= block_indent:
                        break
                    val_lines.append(lines[pos].strip())
                    pos += 1
                result[key] = "\n".join(val_lines)
            else:
                result[key] = _parse_scalar(raw_value)
        else:
            # Value is on the following lines; None means no child block → null
            val, pos = _parse_value(lines, block_indent + 2, pos)
            result[key] = val

    return result, pos


def _find_key_colon(stripped: str) -> int:
    """Find the first ':' that acts as a key-value separator.

    Colons inside quotes are ignored.  A colon followed by nothing, a space,
    or a tab is the separator.
    """
    in_single = False
    in_double = False
    for i, ch in enumerate(stripped):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == ":" and not in_single and not in_double:
            # Must be followed by space/tab/end to be a separator
            rest = stripped[i + 1:]
            if not rest or rest[0] in (" ", "\t", "#"):
                return i
    return -1


def _looks_like_scalar(s: str) -> bool:
    """Return True if s is likely a plain scalar (not a key: value pair)."""
    return _find_key_colon(s) == -1


def _strip_inline_comment(s: str) -> str:
    """Remove trailing inline comment (space + #...)."""
    in_single = False
    in_double = False
    for i, ch in enumerate(s):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            if i == 0 or s[i - 1] == " ":
                return s[:i].rstrip()
    return s


def _unescape_dq(s: str) -> str:
    """Single-pass unescape for double-quoted YAML strings."""
    out: list[str] = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            c = s[i + 1]
            if c == "\\":
                out.append("\\")
            elif c == '"':
                out.append('"')
            elif c == "n":
                out.append("\n")
            elif c == "t":
                out.append("\t")
            else:
                out.append("\\")
                out.append(c)
            i += 2
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def _parse_scalar(val: str) -> Any:
    val = val.strip()
    if not val or val.lower() in ("null", "~"):
        return None
    if val.lower() in ("true", "yes", "on"):
        return True
    if val.lower() in ("false", "no", "off"):
        return False
    # Flow-style empty containers / malformed flow containers
    if val == "{}":
        return {}
    if val == "[]":
        return []
    if val.startswith("[") and not val.endswith("]"):
        raise YAMLError(f"Unclosed flow sequence: {val!r}")
    if val.startswith("{") and not val.endswith("}"):
        raise YAMLError(f"Unclosed flow mapping: {val!r}")
    # Quoted strings — single-pass unescape to avoid \\t inside \\\\t ambiguity
    if (val.startswith('"') and val.endswith('"') and len(val) >= 2):
        return _unescape_dq(val[1:-1])
    if (val.startswith("'") and val.endswith("'") and len(val) >= 2):
        return val[1:-1].replace("''", "'")
    # Numbers
    try:
        if "." in val or ("e" in val.lower() and not val.startswith("0x")):
            return float(val)
        return int(val, 0)  # base 0 handles 0x hex, 0o octal
    except (ValueError, OverflowError):
        pass
    return val


# ---------------------------------------------------------------------------
# Dumper
# ---------------------------------------------------------------------------

def dump(
    data: Any,
    stream=None,
    *,
    default_flow_style: bool = False,
    allow_unicode: bool = True,
    sort_keys: bool = False,
) -> str:
    lines = _dump_node(data, 0, sort_keys=sort_keys)
    result = "\n".join(lines) + "\n"
    if stream is not None:
        stream.write(result)
    return result


def _dump_node(val: Any, indent: int, sort_keys: bool = False) -> list[str]:
    prefix = "  " * indent
    if val is None:
        return [f"{prefix}null"]
    if isinstance(val, bool):
        return [f"{prefix}{'true' if val else 'false'}"]
    if isinstance(val, int):
        return [f"{prefix}{val}"]
    if isinstance(val, float):
        return [f"{prefix}{val!r}"]
    if isinstance(val, str):
        return [f"{prefix}{_dump_str(val)}"]
    if isinstance(val, dict):
        if not val:
            return [f"{prefix}{{}}"]
        out = []
        items = sorted(val.items()) if sort_keys else val.items()
        for k, v in items:
            k_str = _dump_str(str(k))
            if isinstance(v, (dict, list)):
                out.append(f"{prefix}{k_str}:")
                out.extend(_dump_node(v, indent + 1, sort_keys))
            else:
                v_str = _dump_node(v, 0, sort_keys)[0].strip()
                out.append(f"{prefix}{k_str}: {v_str}")
        return out
    if isinstance(val, list):
        if not val:
            return [f"{prefix}[]"]
        out = []
        for item in val:
            if isinstance(item, (dict, list)):
                child_lines = _dump_node(item, indent + 1, sort_keys)
                # First child line gets the "- " prefix at current indent
                first = child_lines[0].lstrip()
                out.append(f"{prefix}- {first}")
                out.extend(child_lines[1:])
            else:
                v_str = _dump_node(item, 0, sort_keys)[0].strip()
                out.append(f"{prefix}- {v_str}")
        return out
    # Fallback
    return [f"{prefix}{_dump_str(str(val))}"]


_SAFE_STR = re.compile(r'^[a-zA-Z0-9 _./:@\-]+$')
_KEYWORDS = frozenset(("true", "false", "null", "yes", "no", "on", "off", "~"))


def _would_reparse_as_non_str(s: str) -> bool:
    """Return True if an unquoted s would be parsed back as a non-string type."""
    sl = s.lower()
    if sl in _KEYWORDS:
        return True
    # Would it parse as a number?
    try:
        if "." in s or ("e" in sl and not s.startswith("0x")):
            float(s)
        else:
            int(s, 0)
        return True
    except (ValueError, OverflowError):
        return False


def _dump_str(s: str) -> str:
    if not s:
        return "''"
    if _SAFE_STR.match(s) and not _would_reparse_as_non_str(s):
        return s
    escaped = s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\t", "\\t")
    return f'"{escaped}"'
