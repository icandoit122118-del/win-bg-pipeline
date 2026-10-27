"""Multi-stage background keyboard & mouse input pipeline with visual diff verification."""

from __future__ import annotations

import ctypes
from dataclasses import asdict, dataclass, field
import time
from typing import Any

from .capture_pipeline import CapturePipeline
from .probe import is_process_elevated
from .win32_api import (
    INPUT,
    INPUT_KEYBOARD,
    KEYBDINPUT,
    KEYEVENTF_KEYUP,
    KEYEVENTF_SCANCODE,
    MK_LBUTTON,
    MK_MBUTTON,
    MK_RBUTTON,
    POINT,
    WA_ACTIVE,
    WM_ACTIVATE,
    WM_CHAR,
    WM_KEYDOWN,
    WM_KEYUP,
    WM_LBUTTONDOWN,
    WM_LBUTTONUP,
    WM_MBUTTONDOWN,
    WM_MBUTTONUP,
    WM_MOUSEMOVE,
    WM_RBUTTONDOWN,
    WM_RBUTTONUP,
    WM_SETFOCUS,
    WNDENUMPROC,
    resolve_vk_and_scan,
    user32,
)


@dataclass
class InputStageAttempt:
    stage_name: str
    dispatched: bool
    elapsed_ms: float
    visual_diff_ratio: float | None = None
    verified_effect: bool | None = None
    notes: str | None = None


@dataclass
class InputResult:
    success: bool
    hwnd: int
    action: str
    winning_stage: str | None
    uipi_blocked: bool
    visual_diff_ratio: float | None = None
    attempts: list[InputStageAttempt] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def compute_frame_diff_ratio(bgra_a: bytes, bgra_b: bytes) -> float:
    """Compute the fraction of sampled pixels that changed significantly between two frames."""
    if not bgra_a or not bgra_b or len(bgra_a) != len(bgra_b):
        return 0.0
    total_pixels = len(bgra_a) // 4
    if total_pixels <= 0:
        return 0.0
    step = max(1, total_pixels // 4096)
    changed = 0
    sampled = 0
    for idx in range(0, total_pixels, step):
        off = idx * 4
        db = abs(bgra_a[off] - bgra_b[off])
        dg = abs(bgra_a[off + 1] - bgra_b[off + 1])
        dr = abs(bgra_a[off + 2] - bgra_b[off + 2])
        sampled += 1
        if db + dg + dr > 18:
            changed += 1
    return round(changed / sampled, 4) if sampled else 0.0


def enum_child_hwnds(parent_hwnd: int) -> list[int]:
    children: list[int] = []

    def _cb(ch: int, _: int) -> bool:
        children.append(ch)
        return True

    user32.EnumChildWindows(parent_hwnd, WNDENUMPROC(_cb), 0)
    return children


def pack_lparam_key(scan: int, repeat: int = 1, is_up: bool = False, extended: bool = False) -> int:
    lparam = (repeat & 0xFFFF) | ((scan & 0xFF) << 16)
    if extended:
        lparam |= 1 << 24
    if is_up:
        lparam |= (1 << 30) | (1 << 31)
    return lparam


def pack_lparam_point(x: int, y: int) -> int:
    return ((y & 0xFFFF) << 16) | (x & 0xFFFF)


class InputPipeline:
    """Cascading background keyboard/mouse input dispatcher with optional visual verification."""

    def __init__(
        self,
        capture_pipeline: CapturePipeline | None = None,
        allow_foreground_fallback: bool = False,
    ) -> None:
        self.capture_pipeline = capture_pipeline or CapturePipeline()
        self.allow_foreground_fallback = allow_foreground_fallback

    def _check_uipi(self, hwnd: int) -> bool:
        pid = ctypes.wintypes.DWORD(0)
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        caller_elev = bool(is_process_elevated(None))
        target_elev = is_process_elevated(pid.value)
        return bool(target_elev is True and not caller_elev)

    def _spoof_focus(self, hwnd: int) -> None:
        user32.PostMessageW(hwnd, WM_ACTIVATE, WA_ACTIVE, 0)
        user32.PostMessageW(hwnd, WM_SETFOCUS, 0, 0)

    def _post_key_sequence(
        self,
        target_hwnd: int,
        vk: int,
        scan: int,
        char: str | None,
        hold_sec: float,
        spoof_activate: bool,
    ) -> bool:
        if spoof_activate:
            self._spoof_focus(target_hwnd)
        lp_down = pack_lparam_key(scan, repeat=1, is_up=False)
        lp_up = pack_lparam_key(scan, repeat=1, is_up=True)
        ok_down = bool(user32.PostMessageW(target_hwnd, WM_KEYDOWN, vk, lp_down))
        if char:
            user32.PostMessageW(target_hwnd, WM_CHAR, ord(char), lp_down)
        time.sleep(max(0.01, hold_sec))
        ok_up = bool(user32.PostMessageW(target_hwnd, WM_KEYUP, vk, lp_up))
        return ok_down and ok_up

    def _foreground_sendinput_guarded(self, hwnd: int, vk: int, scan: int, hold_sec: float) -> bool:
        prev_fg = user32.GetForegroundWindow()
        pt = POINT()
        user32.GetCursorPos(ctypes.byref(pt))
        try:
            user32.SetForegroundWindow(hwnd)
            time.sleep(0.04)

            inp_down = INPUT()
            inp_down.type = INPUT_KEYBOARD
            inp_down.u.ki = KEYBDINPUT(
                wVk=vk,
                wScan=scan,
                dwFlags=KEYEVENTF_SCANCODE,
                time=0,
                dwExtraInfo=0,
            )
            user32.SendInput(1, ctypes.byref(inp_down), ctypes.sizeof(INPUT))
            time.sleep(max(0.02, hold_sec))

            inp_up = INPUT()
            inp_up.type = INPUT_KEYBOARD
            inp_up.u.ki = KEYBDINPUT(
                wVk=vk,
                wScan=scan,
                dwFlags=KEYEVENTF_SCANCODE | KEYEVENTF_KEYUP,
                time=0,
                dwExtraInfo=0,
            )
            sent = user32.SendInput(1, ctypes.byref(inp_up), ctypes.sizeof(INPUT))
            time.sleep(0.03)
            return sent == 1
        finally:
            if prev_fg and prev_fg != hwnd and user32.IsWindow(prev_fg):
                user32.SetForegroundWindow(prev_fg)
            user32.SetCursorPos(pt.x, pt.y)

    def send_key(
        self,
        hwnd: int,
        key: str | int,
        char: str | None = None,
        hold_sec: float = 0.06,
        verify_visual_change: bool = False,
        settle_sec: float = 0.35,
        diff_threshold: float = 0.002,
    ) -> InputResult:
        """Dispatch a key press through cascading stages until accepted (and visually verified if enabled)."""
        if not user32.IsWindow(hwnd):
            raise ValueError(f"Invalid HWND: {hwnd}")

        uipi_blocked = self._check_uipi(hwnd)
        vk, scan = resolve_vk_and_scan(key)
        attempts: list[InputStageAttempt] = []

        if uipi_blocked:
            attempts.append(
                InputStageAttempt(
                    stage_name="uipi_precheck",
                    dispatched=False,
                    elapsed_ms=0.0,
                    notes="Blocked by UIPI: Target process is elevated while caller is non-elevated.",
                )
            )
            return InputResult(
                success=False,
                hwnd=hwnd,
                action=f"key:{key}",
                winning_stage=None,
                uipi_blocked=True,
                visual_diff_ratio=0.0,
                attempts=attempts,
            )

        before_bgra = b""
        if verify_visual_change:
            cap_before = self.capture_pipeline.capture(hwnd)
            if cap_before.success:
                before_bgra = cap_before.bgra_bytes

        stages = ["postmessage_activate_spoof", "postmessage_wndproc", "child_hwnd_broadcast"]
        if self.allow_foreground_fallback:
            stages.append("foreground_sendinput_restore_guard")

        for stage in stages:
            t0 = time.perf_counter()
            dispatched = False
            note: str | None = None

            if stage == "postmessage_activate_spoof":
                dispatched = self._post_key_sequence(
                    hwnd, vk, scan, char, hold_sec, spoof_activate=True
                )
                note = "Sent WM_ACTIVATE(WA_ACTIVE) + WM_SETFOCUS + WM_KEYDOWN/WM_KEYUP"
            elif stage == "postmessage_wndproc":
                dispatched = self._post_key_sequence(
                    hwnd, vk, scan, char, hold_sec, spoof_activate=False
                )
                note = "Sent direct WM_KEYDOWN/WM_KEYUP without focus spoofing"
            elif stage == "child_hwnd_broadcast":
                children = enum_child_hwnds(hwnd)
                if children:
                    ok_any = False
                    for ch in children:
                        if self._post_key_sequence(
                            ch, vk, scan, char, hold_sec, spoof_activate=True
                        ):
                            ok_any = True
                    dispatched = ok_any
                    note = f"Broadcasted key sequence to {len(children)} child HWNDs"
                else:
                    dispatched = False
                    note = "No child HWNDs present"
            elif stage == "foreground_sendinput_restore_guard":
                dispatched = self._foreground_sendinput_guarded(hwnd, vk, scan, hold_sec)
                note = "Guarded foreground switch + hardware scan-code SendInput + focus restore"

            elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)

            if not verify_visual_change:
                attempts.append(
                    InputStageAttempt(
                        stage_name=stage,
                        dispatched=dispatched,
                        elapsed_ms=elapsed_ms,
                        visual_diff_ratio=None,
                        verified_effect=None,
                        notes=note,
                    )
                )
                if dispatched:
                    return InputResult(
                        success=True,
                        hwnd=hwnd,
                        action=f"key:{key}",
                        winning_stage=stage,
                        uipi_blocked=False,
                        visual_diff_ratio=None,
                        attempts=attempts,
                    )
            else:
                diff_ratio = 0.0
                verified = False
                if dispatched and before_bgra:
                    time.sleep(max(0.05, settle_sec))
                    cap_after = self.capture_pipeline.capture(hwnd)
                    if cap_after.success:
                        diff_ratio = compute_frame_diff_ratio(before_bgra, cap_after.bgra_bytes)
                        verified = diff_ratio >= diff_threshold
                attempts.append(
                    InputStageAttempt(
                        stage_name=stage,
                        dispatched=dispatched,
                        elapsed_ms=elapsed_ms,
                        visual_diff_ratio=diff_ratio,
                        verified_effect=verified,
                        notes=note,
                    )
                )
                if dispatched and verified:
                    return InputResult(
                        success=True,
                        hwnd=hwnd,
                        action=f"key:{key}",
                        winning_stage=stage,
                        uipi_blocked=False,
                        visual_diff_ratio=diff_ratio,
                        attempts=attempts,
                    )

        best_diff = max((a.visual_diff_ratio or 0.0 for a in attempts), default=0.0)
        any_dispatched = any(a.dispatched for a in attempts)
        return InputResult(
            success=any_dispatched and not verify_visual_change,
            hwnd=hwnd,
            action=f"key:{key}",
            winning_stage=attempts[0].stage_name if any_dispatched else None,
            uipi_blocked=False,
            visual_diff_ratio=best_diff if verify_visual_change else None,
            attempts=attempts,
        )

    def _foreground_click_guarded(self, hwnd: int, x: int, y: int, button: str, hold_sec: float) -> bool:
        from .win32_api import INPUT_MOUSE, MOUSEINPUT
        prev_fg = user32.GetForegroundWindow()
        orig_pt = POINT()
        user32.GetCursorPos(ctypes.byref(orig_pt))
        try:
            user32.SetForegroundWindow(hwnd)
            time.sleep(0.05)

            target_pt = POINT(x, y)
            user32.ClientToScreen(hwnd, ctypes.byref(target_pt))
            user32.SetCursorPos(target_pt.x, target_pt.y)
            time.sleep(0.03)

            btn = button.lower()
            if btn == "right":
                down_flag, up_flag = 0x0008, 0x0010
            elif btn == "middle":
                down_flag, up_flag = 0x0020, 0x0040
            else:
                down_flag, up_flag = 0x0002, 0x0004  # MOUSEEVENTF_LEFTDOWN / LEFTUP

            inp_down = INPUT()
            inp_down.type = INPUT_MOUSE
            inp_down.u.mi = MOUSEINPUT(0, 0, 0, down_flag, 0, 0)
            user32.SendInput(1, ctypes.byref(inp_down), ctypes.sizeof(INPUT))
            time.sleep(max(0.03, hold_sec))

            inp_up = INPUT()
            inp_up.type = INPUT_MOUSE
            inp_up.u.mi = MOUSEINPUT(0, 0, 0, up_flag, 0, 0)
            sent = user32.SendInput(1, ctypes.byref(inp_up), ctypes.sizeof(INPUT))
            time.sleep(0.03)
            return sent == 1
        finally:
            user32.SetCursorPos(orig_pt.x, orig_pt.y)
            if prev_fg and prev_fg != hwnd and user32.IsWindow(prev_fg):
                user32.SetForegroundWindow(prev_fg)

    def send_click(
        self,
        hwnd: int,
        x: int,
        y: int,
        button: str = "left",
        hold_sec: float = 0.05,
        spoof_activate: bool = True,
        verify_visual_change: bool = False,
        settle_sec: float = 0.4,
        diff_threshold: float = 0.002,
    ) -> InputResult:
        """Send a client-coordinate mouse click via PostMessageW, falling back to guarded SendInput if needed."""
        if not user32.IsWindow(hwnd):
            raise ValueError(f"Invalid HWND: {hwnd}")

        uipi_blocked = self._check_uipi(hwnd)
        if uipi_blocked:
            return InputResult(
                success=False,
                hwnd=hwnd,
                action=f"click:{button}@({x},{y})",
                winning_stage=None,
                uipi_blocked=True,
                attempts=[
                    InputStageAttempt(
                        stage_name="uipi_precheck",
                        dispatched=False,
                        elapsed_ms=0.0,
                        notes="Blocked by UIPI.",
                    )
                ],
            )

        before_bgra = b""
        if verify_visual_change:
            cap_before = self.capture_pipeline.capture(hwnd)
            if cap_before.success:
                before_bgra = cap_before.bgra_bytes

        t0 = time.perf_counter()
        if spoof_activate:
            self._spoof_focus(hwnd)

        lparam = pack_lparam_point(x, y)
        btn = button.lower()
        if btn == "right":
            down_msg, up_msg, mk = WM_RBUTTONDOWN, WM_RBUTTONUP, MK_RBUTTON
        elif btn == "middle":
            down_msg, up_msg, mk = WM_MBUTTONDOWN, WM_MBUTTONUP, MK_MBUTTON
        else:
            down_msg, up_msg, mk = WM_LBUTTONDOWN, WM_LBUTTONUP, MK_LBUTTON

        user32.PostMessageW(hwnd, WM_MOUSEMOVE, 0, lparam)
        ok1 = bool(user32.PostMessageW(hwnd, down_msg, mk, lparam))
        time.sleep(max(0.01, hold_sec))
        ok2 = bool(user32.PostMessageW(hwnd, up_msg, 0, lparam))
        elapsed = round((time.perf_counter() - t0) * 1000.0, 2)

        attempts: list[InputStageAttempt] = []
        diff_ratio = 0.0
        verified = False
        if verify_visual_change and before_bgra:
            time.sleep(max(0.05, settle_sec))
            cap_after = self.capture_pipeline.capture(hwnd)
            if cap_after.success:
                diff_ratio = compute_frame_diff_ratio(before_bgra, cap_after.bgra_bytes)
                verified = diff_ratio >= diff_threshold

        attempts.append(
            InputStageAttempt(
                stage_name="postmessage_activate_spoof" if spoof_activate else "postmessage_wndproc",
                dispatched=ok1 and ok2,
                elapsed_ms=elapsed,
                visual_diff_ratio=diff_ratio if verify_visual_change else None,
                verified_effect=verified if verify_visual_change else None,
                notes=f"Sent WM_MOUSEMOVE + button down/up at client ({x}, {y})",
            )
        )

        if (ok1 and ok2) and (not verify_visual_change or verified):
            return InputResult(
                success=True,
                hwnd=hwnd,
                action=f"click:{button}@({x},{y})",
                winning_stage="postmessage_activate_spoof" if spoof_activate else "postmessage_wndproc",
                uipi_blocked=False,
                visual_diff_ratio=diff_ratio if verify_visual_change else None,
                attempts=attempts,
            )

        if self.allow_foreground_fallback:
            t1 = time.perf_counter()
            fg_ok = self._foreground_click_guarded(hwnd, x, y, button, hold_sec)
            fg_elapsed = round((time.perf_counter() - t1) * 1000.0, 2)
            fg_diff = 0.0
            fg_verified = True
            if verify_visual_change and before_bgra:
                time.sleep(max(0.05, settle_sec))
                cap_after2 = self.capture_pipeline.capture(hwnd)
                if cap_after2.success:
                    fg_diff = compute_frame_diff_ratio(before_bgra, cap_after2.bgra_bytes)
                    fg_verified = fg_diff >= diff_threshold
            attempts.append(
                InputStageAttempt(
                    stage_name="foreground_sendinput_restore_guard",
                    dispatched=fg_ok,
                    elapsed_ms=fg_elapsed,
                    visual_diff_ratio=fg_diff if verify_visual_change else None,
                    verified_effect=fg_verified if verify_visual_change else None,
                    notes=f"Guarded foreground cursor move + SendInput click at client ({x}, {y}) + restore",
                )
            )
            if fg_ok and fg_verified:
                return InputResult(
                    success=True,
                    hwnd=hwnd,
                    action=f"click:{button}@({x},{y})",
                    winning_stage="foreground_sendinput_restore_guard",
                    uipi_blocked=False,
                    visual_diff_ratio=fg_diff if verify_visual_change else None,
                    attempts=attempts,
                )

        return InputResult(
            success=(ok1 and ok2) and not verify_visual_change,
            hwnd=hwnd,
            action=f"click:{button}@({x},{y})",
            winning_stage=None,
            uipi_blocked=False,
            visual_diff_ratio=diff_ratio if verify_visual_change else None,
            attempts=attempts,
        )

    def send_text(self, hwnd: int, text: str, char_delay_sec: float = 0.015) -> InputResult:
        """Send a string of characters via WM_KEYDOWN + WM_CHAR + WM_KEYUP."""
        if not user32.IsWindow(hwnd):
            raise ValueError(f"Invalid HWND: {hwnd}")

        uipi_blocked = self._check_uipi(hwnd)
        if uipi_blocked:
            return InputResult(
                success=False,
                hwnd=hwnd,
                action=f"text:{text!r}",
                winning_stage=None,
                uipi_blocked=True,
            )

        t0 = time.perf_counter()
        self._spoof_focus(hwnd)
        for ch in text:
            vk = ord(ch.upper())
            scan = user32.MapVirtualKeyW(vk, 0) & 0xFF
            lp_down = pack_lparam_key(scan, 1, is_up=False)
            lp_up = pack_lparam_key(scan, 1, is_up=True)
            user32.PostMessageW(hwnd, WM_KEYDOWN, vk, lp_down)
            user32.PostMessageW(hwnd, WM_CHAR, ord(ch), lp_down)
            user32.PostMessageW(hwnd, WM_KEYUP, vk, lp_up)
            time.sleep(max(0.005, char_delay_sec))

        elapsed = round((time.perf_counter() - t0) * 1000.0, 2)
        return InputResult(
            success=True,
            hwnd=hwnd,
            action=f"text:{text!r}",
            winning_stage="postmessage_activate_spoof",
            uipi_blocked=False,
            attempts=[
                InputStageAttempt(
                    stage_name="postmessage_activate_spoof",
                    dispatched=True,
                    elapsed_ms=elapsed,
                    notes=f"Typed {len(text)} characters via WM_CHAR",
                )
            ],
        )
