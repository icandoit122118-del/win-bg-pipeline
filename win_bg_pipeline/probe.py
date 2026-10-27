"""Pre-flight compatibility probe & diagnostic inspector for Windows capture and input."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import asdict, dataclass, field
import os
from typing import Any

from .win32_api import (
    DWMWA_CLOAKED,
    GWL_EXSTYLE,
    GWL_STYLE,
    PROCESS_QUERY_LIMITED_INFORMATION,
    RECT,
    TOKEN_ELEVATION,
    TOKEN_QUERY,
    TokenElevation,
    WDA_EXCLUDEFROMCAPTURE,
    WDA_MONITOR,
    WDA_NONE,
    WNDENUMPROC,
    WS_CAPTION,
    WS_MINIMIZE,
    WS_POPUP,
    advapi32,
    dwmapi,
    kernel32,
    user32,
)

KNOWN_ANTICHEAT_PROCESSES = {
    "easyanticheat.exe": "EasyAntiCheat (EAC)",
    "easyanticheat_eos.exe": "EasyAntiCheat EOS",
    "beservice.exe": "BattlEye",
    "bedaisy.sys": "BattlEye Driver",
    "vgk.sys": "Riot Vanguard",
    "vgc.exe": "Riot Vanguard",
    "xigncode": "XIGNCODE3",
    "gameguard.des": "nProtect GameGuard",
    "gamemon.des": "nProtect GameGuard",
    "blackcipher.aes": "Nexon Game Security (NGS)",
    "blackcipher64.aes": "Nexon Game Security (NGS)",
}

RAW_INPUT_MODULES = {
    "dinput.dll": "DirectInput (Legacy)",
    "dinput8.dll": "DirectInput8",
    "xinput1_4.dll": "XInput 1.4",
    "xinput1_3.dll": "XInput 1.3",
    "xinput9_1_0.dll": "XInput 9.1.0",
    "hid.dll": "HID Raw Input",
}

GRAPHICS_MODULES = {
    "d3d12.dll": "DirectX 12",
    "d3d11.dll": "DirectX 11",
    "d3d9.dll": "DirectX 9",
    "dxgi.dll": "DXGI",
    "vulkan-1.dll": "Vulkan",
    "opengl32.dll": "OpenGL",
    "dcomp.dll": "DirectComposition",
}


@dataclass
class WindowCandidate:
    hwnd: int
    pid: int
    tid: int
    class_name: str
    title: str
    visible: bool
    minimized: bool
    width: int
    height: int
    client_width: int
    client_height: int
    style: int
    ex_style: int


@dataclass
class ProbeReport:
    hwnd: int
    pid: int
    tid: int
    process_name: str
    class_name: str
    title: str
    window_rect: dict[str, int]
    client_rect: dict[str, int]
    is_visible: bool
    is_minimized: bool
    is_cloaked: bool
    is_hung: bool
    is_foreground: bool
    window_mode: str  # "windowed", "borderless_fullscreen", "exclusive_or_fullscreen_popup", "minimized"
    display_affinity: int
    display_affinity_name: str
    capture_protected: bool
    caller_elevated: bool
    target_elevated: bool | None
    uipi_blocked: bool
    graphics_apis: list[str] = field(default_factory=list)
    input_apis: list[str] = field(default_factory=list)
    anticheat_detected: list[str] = field(default_factory=list)
    recommended_capture_stages: list[str] = field(default_factory=list)
    recommended_input_stages: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def get_window_text(hwnd: int) -> str:
    length = user32.GetWindowTextLengthW(hwnd)
    if length <= 0:
        return ""
    buf = ctypes.create_unicode_buffer(length + 1)
    user32.GetWindowTextW(hwnd, buf, length + 1)
    return buf.value


def get_class_name(hwnd: int) -> str:
    buf = ctypes.create_unicode_buffer(256)
    user32.GetClassNameW(hwnd, buf, 256)
    return buf.value


def is_process_elevated(pid: int | None = None) -> bool | None:
    """Return True if target process (or current process when pid=None) is elevated."""
    if pid is None:
        h_proc = kernel32.GetCurrentProcess()
        close_proc = False
    else:
        h_proc = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h_proc:
            return None
        close_proc = True

    try:
        h_token = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(h_proc, TOKEN_QUERY, ctypes.byref(h_token)):
            return None
        try:
            elevation = TOKEN_ELEVATION()
            ret_len = wintypes.DWORD()
            ok = advapi32.GetTokenInformation(
                h_token,
                TokenElevation,
                ctypes.byref(elevation),
                ctypes.sizeof(elevation),
                ctypes.byref(ret_len),
            )
            if not ok:
                return None
            return bool(elevation.TokenIsElevated)
        finally:
            kernel32.CloseHandle(h_token)
    finally:
        if close_proc:
            kernel32.CloseHandle(h_proc)


def is_window_cloaked(hwnd: int) -> bool:
    cloaked = wintypes.DWORD(0)
    hr = dwmapi.DwmGetWindowAttribute(
        hwnd,
        DWMWA_CLOAKED,
        ctypes.byref(cloaked),
        ctypes.sizeof(cloaked),
    )
    return hr == 0 and bool(cloaked.value)


def get_display_affinity(hwnd: int) -> tuple[int, str]:
    affinity = wintypes.DWORD(0)
    ok = user32.GetWindowDisplayAffinity(hwnd, ctypes.byref(affinity))
    if not ok:
        return 0, "WDA_NONE (or cross-process query restricted)"
    val = affinity.value
    if val == WDA_NONE:
        return val, "WDA_NONE"
    if val == WDA_MONITOR:
        return val, "WDA_MONITOR (Black Mask)"
    if val == WDA_EXCLUDEFROMCAPTURE:
        return val, "WDA_EXCLUDEFROMCAPTURE"
    return val, f"WDA_UNKNOWN(0x{val:08X})"


def enumerate_windows(
    pid: int | None = None,
    process_name: str | None = None,
    class_name: str | None = None,
    title_substring: str | None = None,
    visible_only: bool = True,
) -> list[WindowCandidate]:
    """Find top-level windows matching the given filters, sorted by pixel area descending."""
    target_pids: set[int] | None = None
    if pid is not None:
        target_pids = {pid}
    elif process_name:
        target_pids = _find_pids_by_name(process_name)

    results: list[WindowCandidate] = []

    def _cb(hwnd: int, _: int) -> bool:
        vis = bool(user32.IsWindowVisible(hwnd))
        if visible_only and not vis:
            return True

        win_pid = wintypes.DWORD(0)
        tid = user32.GetWindowThreadProcessId(hwnd, ctypes.byref(win_pid))
        if target_pids is not None and win_pid.value not in target_pids:
            return True

        cls = get_class_name(hwnd)
        if class_name and class_name.lower() not in cls.lower():
            return True

        title = get_window_text(hwnd)
        if title_substring and title_substring.lower() not in title.lower():
            return True

        rc = RECT()
        user32.GetWindowRect(hwnd, ctypes.byref(rc))
        crc = RECT()
        user32.GetClientRect(hwnd, ctypes.byref(crc))
        style = user32.GetWindowLongW(hwnd, GWL_STYLE)
        ex_style = user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
        minimized = bool(user32.IsIconic(hwnd)) or bool(style & WS_MINIMIZE)

        results.append(
            WindowCandidate(
                hwnd=hwnd,
                pid=win_pid.value,
                tid=tid,
                class_name=cls,
                title=title,
                visible=vis,
                minimized=minimized,
                width=rc.width,
                height=rc.height,
                client_width=crc.width,
                client_height=crc.height,
                style=style,
                ex_style=ex_style,
            )
        )
        return True

    user32.EnumWindows(WNDENUMPROC(_cb), 0)
    results.sort(key=lambda w: (w.visible, not w.minimized, w.client_width * w.client_height), reverse=True)
    return results


def _find_pids_by_name(process_name: str) -> set[int]:
    pids: set[int] = set()
    target = process_name.lower()
    if not target.endswith(".exe"):
        target_exe = target + ".exe"
    else:
        target_exe = target

    try:
        import psutil

        for proc in psutil.process_iter(["pid", "name"]):
            pname = (proc.info.get("name") or "").lower()
            if pname in (target, target_exe):
                pids.add(proc.info["pid"])
    except Exception:
        pass
    return pids


def inspect_process_modules_and_anticheat(pid: int) -> tuple[str, list[str], list[str], list[str]]:
    """Inspect process name, loaded graphics DLLs, input DLLs, and running anti-cheat processes."""
    proc_name = f"pid:{pid}"
    gfx: list[str] = []
    inp: list[str] = []
    ac: list[str] = []

    try:
        import psutil

        p = psutil.Process(pid)
        proc_name = p.name()
        try:
            for mmap in p.memory_maps():
                base = os.path.basename(mmap.path).lower()
                if base in GRAPHICS_MODULES and GRAPHICS_MODULES[base] not in gfx:
                    gfx.append(GRAPHICS_MODULES[base])
                if base in RAW_INPUT_MODULES and RAW_INPUT_MODULES[base] not in inp:
                    inp.append(RAW_INPUT_MODULES[base])
        except Exception:
            pass

        for running in psutil.process_iter(["name"]):
            rname = (running.info.get("name") or "").lower()
            for ac_key, ac_label in KNOWN_ANTICHEAT_PROCESSES.items():
                if ac_key in rname and ac_label not in ac:
                    ac.append(ac_label)
    except Exception:
        pass

    return proc_name, gfx, inp, ac


def probe_window(hwnd: int) -> ProbeReport:
    """Run a comprehensive pre-flight compatibility diagnosis on a target HWND."""
    if not user32.IsWindow(hwnd):
        raise ValueError(f"Invalid window handle: {hwnd}")

    win_pid = wintypes.DWORD(0)
    tid = user32.GetWindowThreadProcessId(hwnd, ctypes.byref(win_pid))
    pid = win_pid.value

    cls = get_class_name(hwnd)
    title = get_window_text(hwnd)

    rc = RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(rc))
    crc = RECT()
    user32.GetClientRect(hwnd, ctypes.byref(crc))

    vis = bool(user32.IsWindowVisible(hwnd))
    style = user32.GetWindowLongW(hwnd, GWL_STYLE)
    minimized = bool(user32.IsIconic(hwnd)) or bool(style & WS_MINIMIZE)
    cloaked = is_window_cloaked(hwnd)
    hung = bool(user32.IsHungAppWindow(hwnd))
    fg_hwnd = user32.GetForegroundWindow()
    is_fg = fg_hwnd == hwnd

    # Screen dimensions to detect borderless / fullscreen
    screen_w = user32.GetSystemMetrics(0)
    screen_h = user32.GetSystemMetrics(1)

    if minimized:
        window_mode = "minimized"
    elif (rc.width >= screen_w and rc.height >= screen_h) and not (style & WS_CAPTION):
        if style & WS_POPUP:
            window_mode = "borderless_fullscreen"
        else:
            window_mode = "exclusive_or_fullscreen_popup"
    else:
        window_mode = "windowed"

    aff_val, aff_name = get_display_affinity(hwnd)
    capture_protected = aff_val in (WDA_MONITOR, WDA_EXCLUDEFROMCAPTURE)

    caller_elev = bool(is_process_elevated(None))
    target_elev = is_process_elevated(pid)
    uipi_blocked = bool(target_elev is True and not caller_elev)

    proc_name, gfx_apis, inp_apis, anticheats = inspect_process_modules_and_anticheat(pid)

    warnings: list[str] = []
    rec_capture: list[str] = []
    rec_input: list[str] = []

    # Evaluate capture pipeline stages
    if minimized:
        warnings.append(
            "Target window is minimized (WS_MINIMIZE). OS halts DWM surface updates; "
            "restore no-activate or move off-screen before capturing."
        )
        rec_capture.append("restore_noactivate_then_printwindow_fullcontent")
    if capture_protected:
        warnings.append(
            f"Target window has DisplayAffinity={aff_name} (SetWindowDisplayAffinity). "
            "Standard PrintWindow/BitBlt will return a black mask."
        )
    if window_mode == "exclusive_or_fullscreen_popup":
        warnings.append(
            "Target appears to be in fullscreen mode without standard caption. "
            "If Exclusive Fullscreen bypasses DWM, PrintWindow will capture black frames."
        )

    rec_capture.extend(
        [
            "printwindow_renderfullcontent",
            "printwindow_default",
            "wm_printclient",
            "gdi_window_dc_bitblt",
            "desktop_crop_bitblt",
        ]
    )

    # Evaluate input pipeline stages
    if uipi_blocked:
        warnings.append(
            "UIPI Restriction: Target process runs elevated (Administrator) while caller is non-elevated. "
            "PostMessageW and SendInput will be silently dropped by the kernel."
        )
    if anticheats:
        warnings.append(
            f"Kernel/User Anti-Cheat detected ({', '.join(anticheats)}). "
            "External PostMessageW or synthetic SendInput flags (LLMHF_INJECTED) may be blocked."
        )
    if inp_apis:
        warnings.append(
            f"Hardware/Raw input libraries loaded ({', '.join(inp_apis)}). "
            "3D movement/camera polling via DirectInput/RawInput ignores PostMessageW; "
            "UI hotkeys/menus via WndProc will still work, or fallback to guarded foreground SendInput."
        )

    rec_input.extend(
        [
            "postmessage_wndproc",
            "postmessage_activate_spoof",
            "child_hwnd_broadcast",
            "foreground_sendinput_restore_guard",
        ]
    )

    return ProbeReport(
        hwnd=hwnd,
        pid=pid,
        tid=tid,
        process_name=proc_name,
        class_name=cls,
        title=title,
        window_rect={"left": rc.left, "top": rc.top, "right": rc.right, "bottom": rc.bottom, "width": rc.width, "height": rc.height},
        client_rect={"width": crc.width, "height": crc.height},
        is_visible=vis,
        is_minimized=minimized,
        is_cloaked=cloaked,
        is_hung=hung,
        is_foreground=is_fg,
        window_mode=window_mode,
        display_affinity=aff_val,
        display_affinity_name=aff_name,
        capture_protected=capture_protected,
        caller_elevated=caller_elev,
        target_elevated=target_elev,
        uipi_blocked=uipi_blocked,
        graphics_apis=gfx_apis,
        input_apis=inp_apis,
        anticheat_detected=anticheats,
        recommended_capture_stages=rec_capture,
        recommended_input_stages=rec_input,
        warnings=warnings,
    )
