"""Command-line interface for win-bg-pipeline."""

from __future__ import annotations

import argparse
import json
import os
import sys

from .orchestrator import BackgroundOrchestrator
from .probe import enumerate_windows, probe_window


def _add_target_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--hwnd", type=lambda x: int(x, 0), help="Target HWND (decimal or 0x hex)")
    parser.add_argument("--pid", type=int, help="Target Process ID")
    parser.add_argument("--process", type=str, help="Target executable name (e.g. D2R.exe, notepad.exe)")
    parser.add_argument("--class-name", type=str, help="Window class substring (e.g. OsWindow)")
    parser.add_argument("--title", type=str, help="Window title substring")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="win-bg-pipeline",
        description="Windows Background Screen Capture & Input Automation Pipeline",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # list
    p_list = sub.add_parser("list", help="List visible top-level windows")
    p_list.add_argument("--process", type=str, help="Filter by process name")
    p_list.add_argument("--title", type=str, help="Filter by window title substring")
    p_list.add_argument("--all", action="store_true", help="Include invisible windows")

    # probe
    p_probe = sub.add_parser("probe", help="Run pre-flight compatibility diagnosis on a target window")
    _add_target_args(p_probe)

    # capture
    p_cap = sub.add_parser("capture", help="Run multi-stage background capture pipeline")
    _add_target_args(p_cap)
    p_cap.add_argument("--out", "-o", type=str, required=True, help="Output PNG file path")

    # input
    p_inp = sub.add_parser("input", help="Run multi-stage background input pipeline")
    _add_target_args(p_inp)
    p_inp.add_argument("--key", type=str, help="Key name or VK code (e.g. ENTER, ESC, Q, 0x51)")
    p_inp.add_argument("--char", type=str, help="Optional WM_CHAR character")
    p_inp.add_argument("--text", type=str, help="Text string to type via WM_CHAR")
    p_inp.add_argument("--click", type=str, help="Client x,y coordinates to click (e.g. 450,300)")
    p_inp.add_argument("--button", type=str, default="left", choices=["left", "right", "middle"])
    p_inp.add_argument("--verify", action="store_true", help="Verify visual frame change after key input")
    p_inp.add_argument(
        "--allow-foreground-fallback",
        action="store_true",
        help="Allow guarded foreground SendInput fallback if background messages fail",
    )

    # run
    p_run = sub.add_parser("run", help="Execute a declarative JSON workflow pipeline")
    p_run.add_argument("spec_path", type=str, help="Path to workflow JSON file")
    p_run.add_argument(
        "--allow-foreground-fallback",
        action="store_true",
        help="Allow guarded foreground SendInput fallback",
    )

    args = parser.parse_args(argv)

    if args.cmd == "list":
        wins = enumerate_windows(
            process_name=args.process,
            title_substring=args.title,
            visible_only=not args.all,
        )
        out = [
            {
                "hwnd": w.hwnd,
                "hwnd_hex": f"0x{w.hwnd:08X}",
                "pid": w.pid,
                "class_name": w.class_name,
                "title": w.title,
                "client_size": f"{w.client_width}x{w.client_height}",
                "minimized": w.minimized,
            }
            for w in wins
        ]
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 0

    orch = BackgroundOrchestrator(
        allow_foreground_fallback=getattr(args, "allow_foreground_fallback", False)
    )

    if args.cmd == "run":
        spec_abs = os.path.abspath(args.spec_path)
        with open(spec_abs, "r", encoding="utf-8") as f:
            spec = json.load(f)
        receipt = orch.run_pipeline(spec, base_dir=os.path.dirname(spec_abs))
        print(json.dumps(receipt, ensure_ascii=False, indent=2))
        return 0 if receipt["allStepsSucceeded"] else 1

    cand = orch.resolve_target(
        hwnd=args.hwnd,
        pid=args.pid,
        process_name=args.process,
        class_name=args.class_name,
        title_substring=args.title,
    )

    if args.cmd == "probe":
        report = probe_window(cand.hwnd)
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "capture":
        out_abs = os.path.abspath(args.out)
        os.makedirs(os.path.dirname(out_abs), exist_ok=True)
        res = orch.capture_pipeline.capture(cand.hwnd, output_png=out_abs)
        print(json.dumps(res.to_dict(), ensure_ascii=False, indent=2))
        return 0 if res.success else 1

    if args.cmd == "input":
        if args.key:
            res = orch.input_pipeline.send_key(
                cand.hwnd,
                key=args.key,
                char=args.char,
                verify_visual_change=args.verify,
            )
        elif args.text:
            res = orch.input_pipeline.send_text(cand.hwnd, text=args.text)
        elif args.click:
            parts = [int(p.strip()) for p in args.click.split(",")]
            res = orch.input_pipeline.send_click(
                cand.hwnd,
                x=parts[0],
                y=parts[1],
                button=args.button,
            )
        else:
            parser.error("Specify one of --key, --text, or --click")
            return 2

        print(json.dumps(res.to_dict(), ensure_ascii=False, indent=2))
        return 0 if res.success else 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
