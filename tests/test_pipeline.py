"""End-to-end verification tests for win_bg_pipeline using a real background Win32 test window."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
import unittest

from win_bg_pipeline.capture_pipeline import CapturePipeline, analyze_bgra_frame
from win_bg_pipeline.input_pipeline import InputPipeline
from win_bg_pipeline.orchestrator import BackgroundOrchestrator
from win_bg_pipeline.probe import enumerate_windows, probe_window


# Helper script that spawns a real Win32 Tkinter window in the background (without stealing focus)
# and changes its canvas background color & label whenever it receives WM_KEYDOWN / WM_CHAR / clicks.
BG_TEST_APP_CODE = r"""
import sys
import tkinter as tk

root = tk.Tk()
root.title("WinBgPipelineTestTarget")
root.geometry("420x260+80+80")

canvas = tk.Canvas(root, width=420, height=260, bg="#1e293b", highlightthickness=0)
canvas.pack(fill="both", expand=True)
rect = canvas.create_rectangle(20, 20, 400, 240, fill="#3b82f6", outline="#93c5fd", width=3)
text_id = canvas.create_text(210, 130, text="READY", fill="#ffffff", font=("Consolas", 24, "bold"))

state = {"count": 0}
palette = ["#ef4444", "#10b981", "#f59e0b", "#8b5cf6", "#ec4899"]

def on_key(event):
    state["count"] += 1
    color = palette[state["count"] % len(palette)]
    canvas.itemconfig(rect, fill=color)
    canvas.itemconfig(text_id, text=f"KEY:{event.keysym}:{state['count']}")
    root.update_idletasks()

def on_click(event):
    state["count"] += 1
    color = palette[state["count"] % len(palette)]
    canvas.itemconfig(rect, fill=color)
    canvas.itemconfig(text_id, text=f"CLICK:{event.x},{event.y}")
    root.update_idletasks()

root.bind("<Key>", on_key)
canvas.bind("<Button-1>", on_click)
root.mainloop()
"""


class TestWinBgPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.proc = subprocess.Popen([sys.executable, "-c", BG_TEST_APP_CODE])
        cls.hwnd = None
        for _ in range(30):
            time.sleep(0.15)
            wins = enumerate_windows(title_substring="WinBgPipelineTestTarget", visible_only=True)
            if wins:
                cls.hwnd = wins[0].hwnd
                break
        if not cls.hwnd:
            cls.proc.kill()
            raise RuntimeError("Failed to find test target window")
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.proc and cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=3)
            except Exception:
                cls.proc.kill()

    def test_01_frame_validator_rejects_black_and_solid(self) -> None:
        black_bgra = b"\x00\x00\x00\xff" * (100 * 100)
        v_black = analyze_bgra_frame(black_bgra, 100, 100)
        self.assertTrue(v_black.is_all_black)
        self.assertFalse(v_black.is_valid)

        solid_bgra = b"\x20\x40\x80\xff" * (100 * 100)
        v_solid = analyze_bgra_frame(solid_bgra, 100, 100)
        self.assertTrue(v_solid.is_solid_color)
        self.assertFalse(v_solid.is_valid)

    def test_02_probe_window_diagnostics(self) -> None:
        report = probe_window(self.hwnd)
        self.assertEqual(report.hwnd, self.hwnd)
        self.assertEqual(report.title, "WinBgPipelineTestTarget")
        self.assertTrue(report.is_visible)
        self.assertFalse(report.is_minimized)
        self.assertFalse(report.capture_protected)
        self.assertFalse(report.uipi_blocked)
        self.assertIn("printwindow_renderfullcontent", report.recommended_capture_stages)
        self.assertIn("postmessage_wndproc", report.recommended_input_stages)

    def test_03_background_capture_pipeline(self) -> None:
        cap = CapturePipeline()
        with tempfile.TemporaryDirectory() as tmpdir:
            out_png = os.path.join(tmpdir, "test_cap.png")
            res = cap.capture(self.hwnd, output_png=out_png)
            self.assertTrue(res.success)
            self.assertEqual(res.winning_stage, "printwindow_renderfullcontent")
            self.assertIsNotNone(res.validation)
            self.assertTrue(res.validation.is_valid)
            self.assertFalse(res.validation.is_all_black)
            self.assertTrue(os.path.exists(out_png))
            self.assertGreater(os.path.getsize(out_png), 500)

    def test_04_background_input_with_visual_verification(self) -> None:
        cap = CapturePipeline()
        inp = InputPipeline(capture_pipeline=cap)
        res = inp.send_key(
            self.hwnd,
            key="Q",
            char="q",
            verify_visual_change=True,
            settle_sec=0.25,
            diff_threshold=0.01,
        )
        self.assertTrue(res.success)
        self.assertIsNotNone(res.visual_diff_ratio)
        self.assertGreater(res.visual_diff_ratio, 0.05)

    def test_05_orchestrator_declarative_workflow(self) -> None:
        orch = BackgroundOrchestrator()
        with tempfile.TemporaryDirectory() as tmpdir:
            spec = {
                "name": "unit-test-pipeline",
                "target": {"hwnd": self.hwnd},
                "receipt_output": "receipt.json",
                "steps": [
                    {"type": "probe"},
                    {"type": "capture", "output": "before.png"},
                    {"type": "key", "key": "A", "char": "a", "verify_visual_change": True, "settle_sec": 0.25},
                    {"type": "capture", "output": "after.png"},
                ],
            }
            receipt = orch.run_pipeline(spec, base_dir=tmpdir)
            self.assertTrue(receipt["allStepsSucceeded"])
            self.assertTrue(os.path.exists(os.path.join(tmpdir, "before.png")))
            self.assertTrue(os.path.exists(os.path.join(tmpdir, "after.png")))
            self.assertTrue(os.path.exists(os.path.join(tmpdir, "receipt.json")))


if __name__ == "__main__":
    unittest.main()
