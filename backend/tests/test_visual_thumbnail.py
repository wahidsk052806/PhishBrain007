"""The visual layer's evidence image.

The dashboard used to report a perceptual-hash *distance* and nothing else, so
a reader had no way to see what was actually compared. The visual layer now
hands back a downscaled data URL of the captured screenshot — in `pixels` mode
as a JPEG, in `wireframe` mode as an edge-only PNG that keeps the layout while
dropping colour and legible text, and not at all in `off` mode.
"""
from __future__ import annotations

import base64
import io

import pytest
from PIL import Image

from app.analyzers.webpage import visual as visual_module


def _screenshot_bytes(width: int = 240, height: int = 160) -> bytes:
    """A synthetic page: a coloured field with a high-contrast block on it."""
    img = Image.new("RGB", (width, height), (210, 60, 60))
    for x in range(30, 120):
        for y in range(30, 110):
            img.putpixel((x, y), (20, 20, 230))
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return buffer.getvalue()


class _Cfg:
    VISUAL_SCREENSHOT_MODE = "pixels"
    VISUAL_SCREENSHOT_MAX_WIDTH = 160


@pytest.fixture
def cfg(monkeypatch):
    settings = _Cfg()
    monkeypatch.setattr(visual_module, "get_settings", lambda: settings)
    return settings


def _decode(data_url: str) -> Image.Image:
    header, _, payload = data_url.partition(",")
    return Image.open(io.BytesIO(base64.b64decode(payload))), header


def test_off_mode_returns_no_image(cfg):
    cfg.VISUAL_SCREENSHOT_MODE = "off"

    assert visual_module._thumbnail_data_url(_screenshot_bytes()) is None


def test_pixels_mode_returns_a_downscaled_jpeg(cfg):
    data_url = visual_module._thumbnail_data_url(_screenshot_bytes())

    assert data_url is not None
    img, header = _decode(data_url)
    assert header == "data:image/jpeg;base64"
    assert img.width == 160, "width is capped so the data URL stays small"
    assert img.height < 160, "aspect ratio is preserved"


def test_wireframe_mode_is_edge_only_and_colourless(cfg):
    cfg.VISUAL_SCREENSHOT_MODE = "wireframe"

    data_url = visual_module._thumbnail_data_url(_screenshot_bytes())

    assert data_url is not None
    img, header = _decode(data_url)
    assert header == "data:image/png;base64"

    # Every pixel is either a line (black) or background (white): the page's
    # own colours and any legible text are gone.
    pixels = list(img.convert("L").getdata())
    assert max(pixels) == 255 and min(pixels) == 0, "wireframe needs lines and background"
    extremes = sum(1 for p in pixels if p <= 8 or p >= 247)
    assert extremes == len(pixels), "wireframe must not retain intermediate greys"
    assert 0 < sum(1 for p in pixels if p <= 8) < len(pixels), "some edges must survive"


def test_a_wireframe_is_not_the_same_image_as_the_pixels_thumbnail(cfg):
    cfg.VISUAL_SCREENSHOT_MODE = "pixels"
    pixels_url = visual_module._thumbnail_data_url(_screenshot_bytes())
    cfg.VISUAL_SCREENSHOT_MODE = "wireframe"
    wireframe_url = visual_module._thumbnail_data_url(_screenshot_bytes())

    assert pixels_url != wireframe_url


def test_undecodable_bytes_do_not_raise(cfg):
    assert visual_module._thumbnail_data_url(b"not an image") is None
