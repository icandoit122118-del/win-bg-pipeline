"""Multi-stage background window capture pipeline with black-screen/solid-mask validation."""

from __future__ import annotations

import ctypes
from dataclasses import asdict, dataclass, field
import hashlib
import struct
import time
from typing import Any
import zlib

from .win32_api import (
    BI_RGB,
    BITMAPINFOHEADER,
    CAPTUREBLT,
    DIB_RGB_COLORS,
    PRF_CHILDREN,
    PRF_CLIENT,
    PRF_ERASEBKGND,
    PRF_NONCLIENT,
    PW_CLIENTONLY,
    PW_RENDERFULLCONTENT,
    RECT,
    SMTO_ABORTIFHUNG,
    SRCCOPY,
    SW_SHOWNOACTIVATE,
    WM_PRINT,
    WM_PRINTCLIENT,
    gdi32,
    user32,
)


@dataclass
class FrameValidation:
    width: int
    height: int
    mean_luma: float
    std_luma: float
    non_black_ratio: float
    unique_sampled_colors: int
    is_all_black: bool
    is_solid_color: bool
    is_valid: bool
    frame_sha256: str


@dataclass
class StageAttempt:
    stage_name: str
    api_returned_ok: bool
    elapsed_ms: float
    validation: FrameValidation | None = None
    error: str | None = None


@dataclass
class CaptureResult:
    success: bool
    hwnd: int
    winning_stage: str | None
    width: int
    height: int
    validation: FrameValidation | None
    output_path: str | None
    attempts: list[StageAttempt] = field(default_factory=list)
    bgra_bytes: bytes = field(default=b"", repr=False)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("bgra_bytes", None)
        return d


def analyze_bgra_frame(bgra: bytes, width: int, height: int) -> FrameValidation:
    """Validate whether a captured BGRA frame is real content vs black/masked/blank buffer."""
    total_pixels = width * height
    if total_pixels <= 0 or len(bgra) < total_pixels * 4:
        return FrameValidation(
            width=width,
            height=height,
            mean_luma=0.0,
            std_luma=0.0,
            non_black_ratio=0.0,
            unique_sampled_colors=0,
            is_all_black=True,
            is_solid_color=True,
            is_valid=False,
            frame_sha256="",
        )

    # Sample up to ~4096 pixels evenly across the frame for fast deterministic statistics
    step = max(1, total_pixels // 4096)
    lumas: list[float] = []
    non_black = 0
    colors: set[tuple[int, int, int]] = set()

    for idx in range(0, total_pixels, step):
        offset = idx * 4
        b = bgra[offset]
        g = bgra[offset + 1]
        r = bgra[offset + 2]
        luma = 0.299 * r + 0.587 * g + 0.114 * b
        lumas.append(luma)
        if r > 4 or g > 4 or b > 4:
            non_black += 1
        colors.add((r >> 2, g >> 2, b >> 2))

    n = len(lumas)
    mean_luma = sum(lumas) / n if n else 0.0
    variance = sum((x - mean_luma) ** 2 for x in lumas) / n if n else 0.0
    std_luma = variance ** 0.5
    non_black_ratio = non_black / n if n else 0.0
    unique_colors = len(colors)

    is_all_black = non_black_ratio < 0.005 or mean_luma < 1.0
    is_solid = unique_colors <= 1 and std_luma < 0.5
    is_valid = (not is_all_black) and (not is_solid)
    digest = hashlib.sha256(bgra).hexdigest()

    return FrameValidation(
        width=width,
        height=height,
        mean_luma=round(mean_luma, 3),
        std_luma=round(std_luma, 3),
        non_black_ratio=round(non_black_ratio, 4),
        unique_sampled_colors=unique_colors,
        is_all_black=is_all_black,
        is_solid_color=is_solid,
        is_valid=is_valid,
        frame_sha256=digest,
    )


def save_bgra_as_png(bgra_bytes: bytes, width: int, height: int, out_png: str) -> None:
    """Zero-dependency pure-Python PNG encoder for 32-bit BGRA buffers."""
    raw_rows = bytearray()
    stride = width * 4
    for y in range(height):
        raw_rows.append(0)  # Filter type 0 (None)
        row = bgra_bytes[y * stride : (y + 1) * stride]
        rgb = bytearray(width * 3)
        rgb[0::3] = row[2::4]  # R
        rgb[1::3] = row[1::4]  # G
        rgb[2::3] = row[0::4]  # B
        raw_rows.extend(rgb)

    def _chunk(tag: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    idat = zlib.compress(bytes(raw_rows), 6)
    with open(out_png, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n")
        f.write(_chunk(b"IHDR", ihdr))
        f.write(_chunk(b"IDAT", idat))
        f.write(_chunk(b"IEND", b""))


class CapturePipeline:
    """Cascading background screen capture pipeline for Win32/DirectX/Vulkan/Electron windows."""

    def __init__(self, auto_unminimize_noactivate: bool = True) -> None:
        self.auto_unminimize_noactivate = auto_unminimize_noactivate

    def _allocate_dib_and_extract(
        self,
        hwnd: int,
        width: int,
        height: int,
        render_fn: Any,
    ) -> tuple[bool, bytes]:
        hwnd_dc = user32.GetWindowDC(hwnd)
        if not hwnd_dc:
            return False, b""
        mem_dc = gdi32.CreateCompatibleDC(hwnd_dc)
        if not mem_dc:
            user32.ReleaseDC(hwnd, hwnd_dc)
            return False, b""
        hbmp = gdi32.CreateCompatibleBitmap(hwnd_dc, width, height)
        if not hbmp:
            gdi32.DeleteDC(mem_dc)
            user32.ReleaseDC(hwnd, hwnd_dc)
            return False, b""

        old_obj = gdi32.SelectObject(mem_dc, hbmp)
        try:
            ok = bool(render_fn(hwnd_dc, mem_dc))
            bmi = BITMAPINFOHEADER()
            bmi.biSize = ctypes.sizeof(BITMAPINFOHEADER)
            bmi.biWidth = width
            bmi.biHeight = -height  # top-down DIB
            bmi.biPlanes = 1
            bmi.biBitCount = 32
            bmi.biCompression = BI_RGB

            buf = ctypes.create_string_buffer(width * height * 4)
            lines = gdi32.GetDIBits(mem_dc, hbmp, 0, height, buf, ctypes.byref(bmi), DIB_RGB_COLORS)
            if lines != height:
                return False, b""
            return ok, buf.raw
        finally:
            gdi32.SelectObject(mem_dc, old_obj)
            gdi32.DeleteObject(hbmp)
            gdi32.DeleteDC(mem_dc)
            user32.ReleaseDC(hwnd, hwnd_dc)

    def capture(
        self,
        hwnd: int,
        output_png: str | None = None,
        stages: list[str] | None = None,
    ) -> CaptureResult:
        """Run the capture pipeline across stages until a valid non-black frame is acquired."""
        if not user32.IsWindow(hwnd):
            raise ValueError(f"Invalid HWND: {hwnd}")

        if user32.IsIconic(hwnd) and self.auto_unminimize_noactivate:
            from .win32_api import SW_RESTORE
            prev_fg = user32.GetForegroundWindow()
            user32.ShowWindow(hwnd, SW_RESTORE)
            # Also send WM_SYSCOMMAND(SC_RESTORE = 0xF120) for game windows that ignore ShowWindow
            user32.PostMessageW(hwnd, 0x0112, 0xF120, 0)
            for _ in range(15):
                time.sleep(0.05)
                if not user32.IsIconic(hwnd):
                    break
            time.sleep(0.15)
            if prev_fg and prev_fg != hwnd and user32.IsWindow(prev_fg):
                user32.SetForegroundWindow(prev_fg)

        rc = RECT()
        user32.GetWindowRect(hwnd, ctypes.byref(rc))
        width, height = rc.width, rc.height
        if width <= 0 or height <= 0:
            crc = RECT()
            user32.GetClientRect(hwnd, ctypes.byref(crc))
            width, height = max(1, crc.width), max(1, crc.height)

        stage_order = stages or [
            "printwindow_renderfullcontent",
            "printwindow_client_fullcontent",
            "printwindow_default",
            "wm_printclient",
            "gdi_window_dc_bitblt",
            "desktop_crop_bitblt",
        ]

        attempts: list[StageAttempt] = []
        best_fallback_bgra = b""
        best_fallback_val: FrameValidation | None = None
        best_fallback_stage: str | None = None

        for stage in stage_order:
            t0 = time.perf_counter()
            error_msg: str | None = None
            api_ok = False
            bgra = b""

            try:
                if stage == "printwindow_renderfullcontent":
                    api_ok, bgra = self._allocate_dib_and_extract(
                        hwnd,
                        width,
                        height,
                        lambda _hdc, mdc: user32.PrintWindow(hwnd, mdc, PW_RENDERFULLCONTENT),
                    )
                elif stage == "printwindow_client_fullcontent":
                    api_ok, bgra = self._allocate_dib_and_extract(
                        hwnd,
                        width,
                        height,
                        lambda _hdc, mdc: user32.PrintWindow(
                            hwnd, mdc, PW_CLIENTONLY | PW_RENDERFULLCONTENT
                        ),
                    )
                elif stage == "printwindow_default":
                    api_ok, bgra = self._allocate_dib_and_extract(
                        hwnd,
                        width,
                        height,
                        lambda _hdc, mdc: user32.PrintWindow(hwnd, mdc, 0),
                    )
                elif stage == "wm_printclient":
                    def _wm_print(_hdc: int, mdc: int) -> bool:
                        res = ctypes.c_ulonglong(0)
                        flags = PRF_CLIENT | PRF_NONCLIENT | PRF_CHILDREN | PRF_ERASEBKGND
                        ret = user32.SendMessageTimeoutW(
                            hwnd,
                            WM_PRINT,
                            mdc,
                            flags,
                            SMTO_ABORTIFHUNG,
                            500,
                            ctypes.byref(res),
                        )
                        if not ret:
                            ret = user32.SendMessageTimeoutW(
                                hwnd,
                                WM_PRINTCLIENT,
                                mdc,
                                PRF_CLIENT | PRF_CHILDREN,
                                SMTO_ABORTIFHUNG,
                                500,
                                ctypes.byref(res),
                            )
                        return bool(ret)

                    api_ok, bgra = self._allocate_dib_and_extract(hwnd, width, height, _wm_print)
                elif stage == "gdi_window_dc_bitblt":
                    api_ok, bgra = self._allocate_dib_and_extract(
                        hwnd,
                        width,
                        height,
                        lambda hdc, mdc: gdi32.BitBlt(
                            mdc, 0, 0, width, height, hdc, 0, 0, SRCCOPY | CAPTUREBLT
                        ),
                    )
                elif stage == "desktop_crop_bitblt":
                    def _desktop_blt(_hdc: int, mdc: int) -> bool:
                        desk_dc = user32.GetDC(0)
                        if not desk_dc:
                            return False
                        try:
                            return bool(
                                gdi32.BitBlt(
                                    mdc,
                                    0,
                                    0,
                                    width,
                                    height,
                                    desk_dc,
                                    rc.left,
                                    rc.top,
                                    SRCCOPY | CAPTUREBLT,
                                )
                            )
                        finally:
                            user32.ReleaseDC(0, desk_dc)

                    api_ok, bgra = self._allocate_dib_and_extract(hwnd, width, height, _desktop_blt)
                else:
                    error_msg = f"Unknown capture stage: {stage}"
            except Exception as exc:
                error_msg = str(exc)

            elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            val = analyze_bgra_frame(bgra, width, height) if bgra else None
            attempts.append(
                StageAttempt(
                    stage_name=stage,
                    api_returned_ok=api_ok,
                    elapsed_ms=elapsed_ms,
                    validation=val,
                    error=error_msg,
                )
            )

            if val and best_fallback_val is None:
                best_fallback_bgra = bgra
                best_fallback_val = val
                best_fallback_stage = stage

            if val and val.is_valid:
                if output_png:
                    save_bgra_as_png(bgra, width, height, output_png)
                return CaptureResult(
                    success=True,
                    hwnd=hwnd,
                    winning_stage=stage,
                    width=width,
                    height=height,
                    validation=val,
                    output_path=output_png,
                    attempts=attempts,
                    bgra_bytes=bgra,
                )

        # If all stages yielded black/solid frames, still save fallback if requested
        if output_png and best_fallback_bgra:
            save_bgra_as_png(best_fallback_bgra, width, height, output_png)

        return CaptureResult(
            success=False,
            hwnd=hwnd,
            winning_stage=best_fallback_stage,
            width=width,
            height=height,
            validation=best_fallback_val,
            output_path=output_png if best_fallback_bgra else None,
            attempts=attempts,
            bgra_bytes=best_fallback_bgra,
        )
