#!/usr/bin/env python3
"""
GCC Map File Analyzer
Parses a GCC linker .map file and prints a memory usage summary
for each configured memory region plus a per-section breakdown.

Usage:
    python map_analyze.py <file.map> [options]

Options:
    --all-sections    Show every section including zero-size ones
    --no-detail       Skip per-region section breakdown
    --min-size N      Hide sections smaller than N bytes (default: 0)
"""

import sys
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class MemoryRegion:
    name: str
    origin: int
    length: int
    attributes: str

    @property
    def end(self) -> int:
        return self.origin + self.length


@dataclass
class Section:
    name: str
    address: int
    size: int
    region: Optional[str] = None


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_memory_config(lines: list[str]) -> dict[str, MemoryRegion]:
    """Extract memory regions from the 'Memory Configuration' block."""
    regions: dict[str, MemoryRegion] = {}
    in_block = False

    for line in lines:
        stripped = line.strip()

        if "Memory Configuration" in line:
            in_block = True
            continue

        if in_block:
            # Stop at the next major section heading
            if stripped.startswith("Linker script"):
                break

            # Skip blank lines and the column-header line
            if not stripped or stripped.startswith("Name"):
                continue

            # e.g. "FLASH            0x0000000008000000 0x0000000000100000 xr"
            m = re.match(
                r'^(\S+)\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s*(\S*)',
                stripped,
            )
            if m:
                name = m.group(1)
                if name == "*default*":
                    continue
                regions[name] = MemoryRegion(
                    name=name,
                    origin=int(m.group(2), 16),
                    length=int(m.group(3), 16),
                    attributes=m.group(4),
                )

    return regions


def parse_sections(lines: list[str]) -> list[Section]:
    """
    Extract top-level output sections from the 'Linker script and memory map'
    block.  Only sections that start at column 0 (or after a single leading
    space that GCC sometimes uses) are counted to avoid double-counting
    sub-sections from individual object files.

    Handles the 'wrapped' case where the address/size appear on the next line
    because the section name is very long.
    """
    sections: list[Section] = []
    in_block = False
    i = 0

    while i < len(lines):
        line = lines[i]

        if "Linker script and memory map" in line:
            in_block = True
            i += 1
            continue

        if not in_block:
            i += 1
            continue

        # Top-level section: starts with '.' at column 0 (no leading whitespace)
        m_full = re.match(
            r'^(\.[A-Za-z_][A-Za-z0-9_.]*)\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)',
            line,
        )
        if m_full:
            size = int(m_full.group(3), 16)
            if size > 0:
                sections.append(Section(
                    name=m_full.group(1),
                    address=int(m_full.group(2), 16),
                    size=size,
                ))
            i += 1
            continue

        # Wrapped case: long section name alone on a line, addr/size on next
        m_name = re.match(r'^(\.[A-Za-z_][A-Za-z0-9_.]*)\s*$', line)
        if m_name and i + 1 < len(lines):
            next_line = lines[i + 1]
            m_addr = re.match(r'^\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)', next_line)
            if m_addr:
                size = int(m_addr.group(2), 16)
                if size > 0:
                    sections.append(Section(
                        name=m_name.group(1),
                        address=int(m_addr.group(1), 16),
                        size=size,
                    ))
                i += 2
                continue

        i += 1

    return sections


# Sections that carry debug/metadata and have a fake address of 0x0 —
# they must not be counted against any runtime memory region.
_DEBUG_PREFIXES = (
    ".debug_", ".zdebug_", ".comment", ".ARM.attributes", ".gnu.attributes",
)

def is_debug_section(name: str) -> bool:
    return any(name.startswith(p) for p in _DEBUG_PREFIXES)


def assign_regions(sections: list[Section], regions: dict[str, MemoryRegion]) -> None:
    """Tag each section with the memory region whose address range contains it.
    Debug/metadata sections are excluded from region accounting."""
    for section in sections:
        if is_debug_section(section.name):
            continue
        for region in regions.values():
            if region.origin <= section.address < region.end:
                section.region = region.name
                break


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def fmt_size(size: int) -> str:
    """Human-readable byte count."""
    if size >= 1024 * 1024:
        return f"{size / (1024 * 1024):.2f} MB"
    if size >= 1024:
        return f"{size / 1024:.2f} KB"
    return f"{size} B"


def fmt_bar(used: int, total: int, width: int = 24) -> str:
    """ASCII progress bar."""
    if total == 0:
        return "[" + " " * width + "]"
    filled = round(used / total * width)
    return "[" + "#" * filled + "." * (width - filled) + "]"


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

SEPARATOR = "=" * 80
THIN_SEP  = "-" * 80


def print_summary(regions: dict[str, MemoryRegion],
                  region_usage: dict[str, int],
                  region_sections: dict[str, list[Section]],
                  unassigned: list[Section],
                  show_detail: bool,
                  min_size: int,
                  map_name: str) -> None:

    print(f"\n{SEPARATOR}")
    print(f"  GCC Map File Analyzer  -  {map_name}")
    print(SEPARATOR)

    # ---- Region summary table ----
    print(f"\n{'MEMORY REGION SUMMARY':^74}")
    print(THIN_SEP)
    print(f"  {'Region':<14} {'Used':>10} {'Total':>10} {'Free':>10}  {'Usage':>6}  Bar")
    print(THIN_SEP)

    for name, region in regions.items():
        used  = region_usage.get(name, 0)
        total = region.length
        free  = total - used
        pct   = (used / total * 100) if total > 0 else 0.0
        bar   = fmt_bar(used, total)
        print(f"  {name:<14} {fmt_size(used):>10} {fmt_size(total):>10} "
              f"{fmt_size(free):>10}  {pct:5.1f}%  {bar}")

    print(THIN_SEP)

    total_used  = sum(region_usage.values())
    total_alloc = sum(r.length for r in regions.values())
    print(f"  {'TOTAL':<14} {fmt_size(total_used):>10} {fmt_size(total_alloc):>10}")

    # ---- Per-region section detail ----
    if show_detail:
        print(f"\n{'SECTION DETAIL BY REGION':^80}")

        for name, region in sorted(regions.items(), key=lambda x: x[1].origin):
            secs = [s for s in region_sections.get(name, []) if s.size >= min_size]
            if not secs:
                continue

            used  = region_usage.get(name, 0)
            total = region.length
            pct_region = (used / total * 100) if total > 0 else 0.0
            bar = fmt_bar(used, total)
            print(f"\n  +- {name}  "
                  f"Origin: 0x{region.origin:08X}  "
                  f"Length: {fmt_size(total)}  "
                  f"Used: {fmt_size(used)} ({pct_region:.1f}%)  {bar}")
            print(f"  |  {'Section':<32} {'Address':>12}  {'Size':>10}  {'% of region':>12}  {'% of used':>10}")
            print(f"  |  {'-'*32}  {'-'*12}  {'-'*10}  {'-'*12}  {'-'*10}")

            for s in sorted(secs, key=lambda x: x.address):
                pct_of_total = (s.size / total * 100) if total else 0.0
                pct_of_used  = (s.size / used  * 100) if used  else 0.0
                print(f"  |  {s.name:<32}  0x{s.address:010X}  {fmt_size(s.size):>10}  {pct_of_total:>11.1f}%  {pct_of_used:>9.1f}%")

        if unassigned:
            filtered = [s for s in unassigned if s.size >= min_size]
            if filtered:
                print(f"\n  +- (unassigned - not within any declared memory region)")
                print(f"  |  {'Section':<30} {'Address':>12}  {'Size':>10}")
                print(f"  |  {'-'*30}  {'-'*12}  {'-'*10}")
                for s in sorted(filtered, key=lambda x: -x.size):
                    print(f"  |  {s.name:<30}  0x{s.address:010X}  {fmt_size(s.size):>10}")

    print(f"\n{SEPARATOR}\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    # --- Argument parsing (no external deps) ---
    args = sys.argv[1:]

    if args and args[0] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    DEFAULT_MAP = "disco_nc_test.map"

    map_file   = None
    show_all   = False
    show_detail = True
    min_size   = 0

    for arg in args:
        if arg == "--all-sections":
            show_all = True
        elif arg == "--no-detail":
            show_detail = False
        elif arg.startswith("--min-size="):
            min_size = int(arg.split("=", 1)[1])
        elif arg.startswith("--min-size"):
            pass
        elif not arg.startswith("--"):
            map_file = arg

    if map_file is None:
        map_file = DEFAULT_MAP

    path = Path(map_file)
    if not path.exists():
        print(f"Error: file not found: {map_file}")
        sys.exit(1)

    # --- Read ---
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        print(f"Error reading file: {e}")
        sys.exit(1)

    lines = content.splitlines()

    # --- Parse ---
    regions  = parse_memory_config(lines)
    sections = parse_sections(lines)

    if not regions:
        print("Warning: No 'Memory Configuration' block found in this map file.")
        print("         Region summary will be skipped; showing raw section list.\n")

    assign_regions(sections, regions)

    # --- Aggregate ---
    region_usage:    dict[str, int]           = {n: 0  for n in regions}
    region_sections: dict[str, list[Section]] = {n: [] for n in regions}
    unassigned: list[Section] = []

    for s in sections:
        if s.region:
            region_usage[s.region]    += s.size
            region_sections[s.region].append(s)
        else:
            unassigned.append(s)

    # --- Report ---
    if regions:
        print_summary(
            regions, region_usage, region_sections, unassigned,
            show_detail=show_detail,
            min_size=min_size,
            map_name=path.name,
        )
    else:
        # Fallback: just dump sections sorted by size
        print(f"\n{'Section':<32} {'Address':>12}  {'Size':>10}")
        print("-" * 60)
        for s in sorted(sections, key=lambda x: -x.size):
            if s.size >= min_size or show_all:
                print(f"{s.name:<32}  0x{s.address:010X}  {fmt_size(s.size):>10}")
        print()


if __name__ == "__main__":
    main()
