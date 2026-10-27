"""Declarative workflow runner for Windows background capture & input automation."""

from __future__ import annotations

import ctypes
import datetime
import json
import os
import sys
import tempfile
import time
from typing import Any

from .capture_pipeline import CapturePipeline
from .input_pipeline import InputPipeline
from .probe import WindowCandidate, enumerate_windows, probe_window
from .win32_api import shell32


class BackgroundOrchestrator:
    """End-to-end orchestrator combining Pre-flight Probe, Capture Pipeline, and Input Pipeline."""

    def __init__(
        self,
        allow_foreground_fallback: bool = False,
        auto_elevate_on_uipi: bool = True,
    ) -> None:
        self.capture_pipeline = CapturePipeline()
        self.input_pipeline = InputPipeline(
            capture_pipeline=self.capture_pipeline,
            allow_foreground_fallback=allow_foreground_fallback,
        )
        self.allow_foreground_fallback = allow_foreground_fallback
        self.auto_elevate_on_uipi = auto_elevate_on_uipi

    @staticmethod
    def _run_elevated_worker(spec: dict[str, Any], base_dir: str | None) -> dict[str, Any]:
        """Delegate pipeline execution to an elevated Administrator worker process when UIPI blocks access."""
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        ipc_dir = os.path.join(repo_root, ".elevated_ipc")
        os.makedirs(ipc_dir, exist_ok=True)

        spec_copy = dict(spec)
        receipt_out = spec_copy.get("receipt_output")
        if receipt_out and base_dir and not os.path.isabs(receipt_out):
            abs_receipt = os.path.join(base_dir, receipt_out)
        elif receipt_out:
            abs_receipt = os.path.abspath(receipt_out)
        else:
            abs_receipt = os.path.join(ipc_dir, "elevated_receipt.json")
        spec_copy["receipt_output"] = abs_receipt

        # Convert relative step capture outputs to absolute paths
        resolved_steps = []
        for st in spec_copy.get("steps", []):
            st_copy = dict(st)
            if st_copy.get("type") == "capture" and st_copy.get("output"):
                out_p = st_copy["output"]
                if base_dir and not os.path.isabs(out_p):
                    st_copy["output"] = os.path.join(base_dir, out_p)
                else:
                    st_copy["output"] = os.path.abspath(out_p)
                os.makedirs(os.path.dirname(st_copy["output"]), exist_ok=True)
                with open(st_copy["output"], "wb") as pf:
                    pf.write(b"")
            resolved_steps.append(st_copy)
        spec_copy["steps"] = resolved_steps

        spec_file = os.path.join(ipc_dir, "elevated_spec.json")
        with open(spec_file, "w", encoding="utf-8") as f:
            json.dump(spec_copy, f, ensure_ascii=False, indent=2)

        # Pre-create receipt file from non-elevated process so DACL grants read/write to current user
        with open(abs_receipt, "w", encoding="utf-8") as rf:
            rf.write("")

        worker_script = os.path.join(ipc_dir, "run_elevated_worker.py")
        with open(worker_script, "w", encoding="utf-8") as wf:
            wf.write(
                f"import sys, json\n"
                f"sys.path.insert(0, {repo_root!r})\n"
                f"from win_bg_pipeline.orchestrator import BackgroundOrchestrator\n"
                f"with open({spec_file!r}, 'r', encoding='utf-8') as f:\n"
                f"    spec = json.load(f)\n"
                f"orch = BackgroundOrchestrator(allow_foreground_fallback=bool(spec.get('allow_foreground_fallback', False)), auto_elevate_on_uipi=False)\n"
                f"orch.run_pipeline(spec, base_dir={base_dir!r})\n"
            )

        ret = ctypes.cast(
            shell32.ShellExecuteW(
                None,
                "runas",
                sys.executable,
                f'"{worker_script}"',
                repo_root,
                0,
            ),
            ctypes.c_void_p,
        ).value or 0
        if ret <= 32:
            raise RuntimeError(f"ShellExecuteW(runas) failed with code {ret}")

        for _ in range(120):
            if os.path.exists(abs_receipt) and os.path.getsize(abs_receipt) > 10:
                time.sleep(0.15)
                try:
                    with open(abs_receipt, "r", encoding="utf-8") as rf:
                        data = json.load(rf)
                    data["elevatedViaRunAs"] = True
                    return data
                except Exception:
                    pass
            time.sleep(0.25)

        raise TimeoutError("Timed out waiting for elevated pipeline worker to finish.")

    def resolve_target(
        self,
        hwnd: int | None = None,
        pid: int | None = None,
        process_name: str | None = None,
        class_name: str | None = None,
        title_substring: str | None = None,
    ) -> WindowCandidate:
        if hwnd is not None:
            candidates = [
                c
                for c in enumerate_windows(visible_only=False)
                if c.hwnd == hwnd
            ]
            if candidates:
                return candidates[0]
            raise ValueError(f"Window handle {hwnd} not found.")

        candidates = enumerate_windows(
            pid=pid,
            process_name=process_name,
            class_name=class_name,
            title_substring=title_substring,
            visible_only=True,
        )
        if not candidates:
            candidates = enumerate_windows(
                pid=pid,
                process_name=process_name,
                class_name=class_name,
                title_substring=title_substring,
                visible_only=False,
            )
        if not candidates:
            raise LookupError(
                f"No matching window found for pid={pid}, process={process_name}, "
                f"class={class_name}, title={title_substring}"
            )
        return candidates[0]

    def run_pipeline(
        self,
        spec: dict[str, Any],
        base_dir: str | None = None,
    ) -> dict[str, Any]:
        """Execute a declarative JSON pipeline specification and return a structured audit receipt."""
        target_cfg = spec.get("target", {})
        cand = self.resolve_target(
            hwnd=target_cfg.get("hwnd"),
            pid=target_cfg.get("pid"),
            process_name=target_cfg.get("process"),
            class_name=target_cfg.get("class_name"),
            title_substring=target_cfg.get("title"),
        )
        hwnd = cand.hwnd
        probe_report = probe_window(hwnd)

        if probe_report.uipi_blocked and self.auto_elevate_on_uipi:
            spec_with_flags = dict(spec)
            spec_with_flags["allow_foreground_fallback"] = self.allow_foreground_fallback
            return self._run_elevated_worker(spec_with_flags, base_dir=base_dir)

        steps_log: list[dict[str, Any]] = []
        started_at = datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat()

        for idx, step in enumerate(spec.get("steps", []), start=1):
            stype = step.get("type", "").lower()
            step_record: dict[str, Any] = {"step": idx, "type": stype}

            if stype == "wait":
                sec = float(step.get("seconds", 0.5))
                time.sleep(sec)
                step_record["seconds"] = sec
                step_record["success"] = True

            elif stype == "probe":
                p = probe_window(hwnd)
                step_record["probe"] = p.to_dict()
                step_record["success"] = True

            elif stype == "capture":
                out_file = step.get("output")
                if out_file and base_dir and not os.path.isabs(out_file):
                    out_file = os.path.join(base_dir, out_file)
                if out_file:
                    os.makedirs(os.path.dirname(os.path.abspath(out_file)), exist_ok=True)
                cap_res = self.capture_pipeline.capture(
                    hwnd=hwnd,
                    output_png=out_file,
                    stages=step.get("stages"),
                )
                step_record["result"] = cap_res.to_dict()
                step_record["success"] = cap_res.success

            elif stype == "key":
                key_res = self.input_pipeline.send_key(
                    hwnd=hwnd,
                    key=step["key"],
                    char=step.get("char"),
                    hold_sec=float(step.get("hold_sec", 0.06)),
                    verify_visual_change=bool(step.get("verify_visual_change", False)),
                    settle_sec=float(step.get("settle_sec", 0.35)),
                )
                step_record["result"] = key_res.to_dict()
                step_record["success"] = key_res.success

            elif stype == "click":
                click_res = self.input_pipeline.send_click(
                    hwnd=hwnd,
                    x=int(step["x"]),
                    y=int(step["y"]),
                    button=step.get("button", "left"),
                    hold_sec=float(step.get("hold_sec", 0.05)),
                    verify_visual_change=bool(step.get("verify_visual_change", False)),
                    settle_sec=float(step.get("settle_sec", 0.4)),
                )
                step_record["result"] = click_res.to_dict()
                step_record["success"] = click_res.success

            elif stype == "text":
                txt_res = self.input_pipeline.send_text(
                    hwnd=hwnd,
                    text=str(step["text"]),
                    char_delay_sec=float(step.get("char_delay_sec", 0.015)),
                )
                step_record["result"] = txt_res.to_dict()
                step_record["success"] = txt_res.success

            else:
                raise ValueError(f"Unsupported pipeline step type: {stype!r}")

            steps_log.append(step_record)

        finished_at = datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat()
        receipt = {
            "pipelineName": spec.get("name", "unnamed-pipeline"),
            "startedAt": started_at,
            "finishedAt": finished_at,
            "targetWindow": probe_report.to_dict(),
            "allStepsSucceeded": all(s.get("success", False) for s in steps_log),
            "steps": steps_log,
        }

        receipt_path = spec.get("receipt_output")
        if receipt_path:
            if base_dir and not os.path.isabs(receipt_path):
                receipt_path = os.path.join(base_dir, receipt_path)
            os.makedirs(os.path.dirname(os.path.abspath(receipt_path)), exist_ok=True)
            with open(receipt_path, "w", encoding="utf-8") as f:
                json.dump(receipt, f, ensure_ascii=False, indent=2)

        return receipt
