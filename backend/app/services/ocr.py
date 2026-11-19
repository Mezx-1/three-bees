"""OCR + QR extraction with graceful degradation.

Engine order: Tesseract (if the binary is on PATH) -> RapidOCR (pip, ONNX) -> unavailable.
Nothing here executes the file; images are decoded as pixel data only.
"""
from __future__ import annotations

import io
import shutil
from functools import lru_cache

_engine_name: str | None = None


@lru_cache(maxsize=1)
def _rapid():
    from rapidocr import RapidOCR  # type: ignore

    return RapidOCR()


def ocr_engine() -> str:
    global _engine_name
    if _engine_name is not None:
        return _engine_name
    if shutil.which("tesseract"):
        try:
            import pytesseract  # type: ignore  # noqa: F401

            _engine_name = "tesseract"
            return _engine_name
        except Exception:
            pass
    try:
        _rapid()
        _engine_name = "rapidocr"
    except Exception:
        _engine_name = "unavailable"
    return _engine_name


def _to_rgb_array(data: bytes):
    import numpy as np
    from PIL import Image

    img = Image.open(io.BytesIO(data))
    img.load()
    if getattr(img, "n_frames", 1) > 1:
        img.seek(0)
    img = img.convert("RGB")
    # Bound work on huge images.
    if max(img.size) > 2400:
        img.thumbnail((2400, 2400))
    return np.array(img)


def extract_text(data: bytes) -> dict:
    engine = ocr_engine()
    if engine == "unavailable":
        return {"engine": engine, "text": "", "available": False,
                "note": "No OCR engine installed (install Tesseract or `pip install rapidocr onnxruntime`)."}
    try:
        if engine == "tesseract":
            import pytesseract  # type: ignore
            from PIL import Image

            text = pytesseract.image_to_string(Image.open(io.BytesIO(data)), lang="eng")
        else:
            arr = _to_rgb_array(data)
            result = _rapid()(arr)
            txts = getattr(result, "txts", None) or ()
            text = "\n".join(t for t in txts if t)
        return {"engine": engine, "text": text.strip(), "available": True}
    except Exception as exc:  # corrupted image etc.
        return {"engine": engine, "text": "", "available": True, "error": f"OCR failed: {exc}"}


def decode_qr(data: bytes) -> dict:
    try:
        import cv2
        import numpy as np
    except Exception:
        return {"available": False, "codes": [], "note": "OpenCV not installed"}
    try:
        arr = _to_rgb_array(data)
        bgr = cv2.cvtColor(arr, cv2.COLOR_RGB2BGR)
        det = cv2.QRCodeDetector()
        codes: list[str] = []
        ok, decoded, _, _ = det.detectAndDecodeMulti(bgr)
        if ok:
            codes = [d for d in decoded if d]
        if not codes:
            single, _, _ = det.detectAndDecode(bgr)
            if single:
                codes = [single]
        if not codes:  # retry on an upscaled grayscale copy for small codes
            gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
            up = cv2.resize(gray, None, fx=2, fy=2, interpolation=cv2.INTER_NEAREST)
            single, _, _ = det.detectAndDecode(up)
            if single:
                codes = [single]
        return {"available": True, "codes": list(dict.fromkeys(codes)), "engine": f"OpenCV {cv2.__version__}"}
    except Exception as exc:
        return {"available": True, "codes": [], "error": f"QR decode failed: {exc}"}
