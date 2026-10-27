"""Declarative workflow runner for Windows background capture & input automation."""

from __future__ import annotations

import datetime
import json
import os
import time
from typing import Any

from .capture_pipeline import CapturePipeline
from .input_pipeline import InputPipeline
from .probe import WindowCandidate, enumerate_windows, probe_window


class BackgroundOrchestrator:
    """End-to-end orchestrator combining Pre-flight Probe, Capture Pipeline, and Input Pipeline."""

    def __init__(self, allow_foreground_fallback: bool = False) -> None:
        self.capture_pipeline = CapturePipeline()
        self.input_pipeline = InputPipeline(
            capture_pipeline=self.capture_pipeline,
            allow_foreground_fallback=allow_foreground_fallback,
        )

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
