#!/usr/bin/env python3
"""Run C2Scope icount with its optional merge hooks disabled.

Only used as a fallback when C2Scope's full icount trace fails to resolve a
late-flow merge hook for this particular VC9 build. The compiler's pass hooks
and instruction-count analysis remain enabled. No C2Scope files are edited.
"""

import os
from pathlib import Path
import sys


def main():
    c2root = Path(os.environ.get("PCODE2CPP_C2SCOPE_ROOT", os.getcwd())).resolve()
    tools = c2root / "tools"
    if not (tools / "icount.py").is_file():
        raise SystemExit(f"C2Scope tool directory not found: {tools}")
    sys.path.insert(0, str(tools))
    import c2trace
    import c2merges
    import icount

    build = c2trace.c2build.name()
    if build != "15.00.30729.1":
        raise SystemExit(
            f"Merge-hook bypass is only validated for C2Scope's VC9 build, got {build}"
        )
    if build not in c2merges.BUILDS:
        raise SystemExit(f"No optional merge-hook configuration found for {build}")
    del c2merges.BUILDS[build]
    print(
        "C2Scope: optional late-flow merge hooks disabled for VC9; "
        "instruction-count and compiler-pass tracing remain enabled.",
        flush=True,
    )
    return c2trace.pipe_safe(icount.main)


if __name__ == "__main__":
    raise SystemExit(main())
