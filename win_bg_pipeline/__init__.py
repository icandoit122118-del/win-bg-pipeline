"""Windows Background Capture & Input Pipeline package."""

from .capture_pipeline import CapturePipeline, CaptureResult, FrameValidation, analyze_bgra_frame
from .input_pipeline import InputPipeline, InputResult
from .orchestrator import BackgroundOrchestrator
from .probe import ProbeReport, WindowCandidate, enumerate_windows, probe_window

__all__ = [
    "BackgroundOrchestrator",
    "CapturePipeline",
    "CaptureResult",
    "FrameValidation",
    "InputPipeline",
    "InputResult",
    "ProbeReport",
    "WindowCandidate",
    "analyze_bgra_frame",
    "enumerate_windows",
    "probe_window",
]

__version__ = "1.0.0"
