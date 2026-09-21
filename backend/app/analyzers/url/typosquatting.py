"""Typosquatting detection against a configurable brand list."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

try:
    from Levenshtein import distance as _levenshtein_distance
except Exception:  # pragma: no cover - fallback if package missing
    def _levenshtein_distance(a: str, b: str) -> int:
        if a == b:
            return 0
        if not a:
            return len(b)
        if not b:
            return len(a)
        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a, start=1):
            cur = [i] + [0] * len(b)
            for j, cb in enumerate(b, start=1):
                cost = 0 if ca == cb else 1
                cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            prev = cur
        return prev[-1]


# Real brand characters and the lookalike spellings phishers use for them.
HOMOGLYPH_SPELLINGS: dict[str, tuple[str, ...]] = {
    "o": ("0",),
    "i": ("1",),
    "l": ("1",),
    "e": ("3",),
    "a": ("4", "@"),
    "s": ("5",),
    "t": ("7",),
    "b": ("8",),
    "g": ("9",),
}


@dataclass
class TyposquatMatch:
    brand: str
    distance: int
    similarity: float
    # "lookalike" = homoglyph substitution (g00gle -> google), "swap" = adjacent
    # letter transposition, "typo" = plain edit-distance close.
    kind: str = "typo"
    chars: list[str] = field(default_factory=list)


def _homoglyph_variants(word: str) -> list[str]:
    """Every spelling of a brand reachable by homoglyph substitution."""
    combos = [""]
    for ch in word.lower():
        alts = HOMOGLYPH_SPELLINGS.get(ch, ())
        nxt: set[str] = set()
        for c in combos:
            nxt.add(c + ch)
            for a in alts:
                nxt.add(c + a)
        combos = sorted(nxt)
    return combos


def _diff_chars(brand: str, spelling: str) -> list[str]:
    return [
        f"{brand[i]}→{spelling[i]}"
        for i in range(min(len(brand), len(spelling)))
        if brand[i] != spelling[i]
    ]


def _is_adjacent_swap(a: str, b: str) -> bool:
    if len(a) != len(b):
        return False
    for i in range(len(a) - 1):
        if a[:i] + a[i + 1] + a[i] + a[i + 2:] == b:
            return True
    return False


def _strip_label(label: str) -> str:
    return re.sub(r"[^a-z0-9]", "", label)


def detect_typosquatting(hostname: str, brands: list[str], max_distance: int = 2) -> TyposquatMatch | None:
    """Return the closest brand match if the hostname looks like a typosquat.

    Two mechanisms are combined:
      1. Homoglyph lookalikes: a label contains a brand spelling reachable by
         visually-similar character substitution (g00gle -> google,
         paypa1 -> paypal). Substring matches require brands of >= 5 chars so
         short homoglyph fragments (e.g. "5bi" inside "5billion") do not
         false-positive.
      2. Plain edit-distance typos over every hostname label (not just the
         first), promoting adjacent transpositions to distance-1 severity.
    """
    if not hostname:
        return None
    labels = [label for label in hostname.lower().split(".") if label]

    # 1) Homoglyph lookalike.
    for label in labels:
        stripped = _strip_label(label)
        if not stripped:
            continue
        for brand in brands:
            brand = brand.lower()
            for spelling in _homoglyph_variants(brand):
                if spelling == brand:
                    continue
                if stripped == spelling or (len(brand) >= 5 and spelling in stripped):
                    dist = _levenshtein_distance(stripped, brand)
                    max_len = max(len(stripped), len(brand)) or 1
                    return TyposquatMatch(
                        brand=brand,
                        distance=dist,
                        similarity=round(1 - (dist / max_len), 3),
                        kind="lookalike",
                        chars=_diff_chars(brand, spelling),
                    )

    # 2) Edit-distance typos.
    best: TyposquatMatch | None = None
    for label in labels:
        stripped = _strip_label(label)
        if not stripped:
            continue
        for brand in brands:
            brand = brand.lower()
            if stripped == brand:
                continue  # exact brand label (e.g. paypal.com) is not a squat
            dist = _levenshtein_distance(stripped, brand)
            if dist == 0 or dist > max_distance:
                continue
            max_len = max(len(stripped), len(brand)) or 1
            similarity = 1 - (dist / max_len)
            if similarity < 0.6:
                continue
            if best is None or dist < best.distance:
                best = TyposquatMatch(
                    brand=brand,
                    distance=dist,
                    similarity=round(similarity, 3),
                    kind="swap" if dist == 2 and _is_adjacent_swap(stripped, brand) else "typo",
                )
    return best