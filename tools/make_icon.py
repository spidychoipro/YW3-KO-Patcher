"""프로그램 아이콘(app.ico)을 만든다. 외부 라이브러리 없이 PNG를 직접 인코딩한다."""

from __future__ import annotations

import math
import struct
import sys
import zlib
from pathlib import Path

SIZE = 256
SS = 4  # 슈퍼샘플링 배율


def rounded_rect(x: float, y: float, size: int) -> bool:
    radius = size * 0.22
    r = radius
    if x < r and y < r:
        return (x - r) ** 2 + (y - r) ** 2 <= r * r
    if x > size - r and y < r:
        return (x - (size - r)) ** 2 + (y - r) ** 2 <= r * r
    if x < r and y > size - r:
        return (x - r) ** 2 + (y - (size - r)) ** 2 <= r * r
    if x > size - r and y > size - r:
        return (x - (size - r)) ** 2 + (y - (size - r)) ** 2 <= r * r
    return 0 <= x <= size and 0 <= y <= size


def ghost(x: float, y: float, size: int) -> bool:
    """요괴 느낌의 둥근 몸통 + 물결 밑단."""
    cx = size * 0.5
    body_top = size * 0.30
    body_bottom = size * 0.74
    half_width = size * 0.235
    head_r = half_width
    head_cy = body_top + head_r

    if (x - cx) ** 2 + (y - head_cy) ** 2 <= head_r * head_r:
        return True
    if body_top + head_r - 1 <= y <= body_bottom and abs(x - cx) <= half_width:
        # 밑단 물결
        wave = math.sin((x - cx) / half_width * math.pi * 1.5) * size * 0.028
        if y <= body_bottom + wave - size * 0.02:
            return True
    return False


def render() -> bytearray:
    pixels = bytearray(SIZE * SIZE * 3)
    for py in range(SIZE):
        for px in range(SIZE):
            hits_body = 0
            hits_ghost = 0
            for sy in range(SS):
                for sx in range(SS):
                    x = px + (sx + 0.5) / SS
                    y = py + (sy + 0.5) / SS
                    if rounded_rect(x, y, SIZE):
                        hits_body += 1
                    if ghost(x, y, SIZE):
                        hits_ghost += 1
            # 배경: 남색 그라데이션
            base_ratio = hits_body / (SS * SS)
            if base_ratio == 0:
                continue
            t = py / SIZE
            bg = (int(24 + 18 * t), int(30 + 20 * t), int(58 + 34 * t))
            # 요괴: 노란색
            ratio = hits_ghost / (SS * SS)
            fg = (250, 206, 74)
            color = tuple(
                int(base * (1 - ratio) + fg[i] * ratio) for i, base in enumerate(bg)
            )
            # 눈
            for eye_x in (0.425, 0.575):
                ex = px + 0.5 - SIZE * eye_x
                ey = py + 0.5 - SIZE * 0.415
                if ex * ex + ey * ey <= (SIZE * 0.045) ** 2:
                    color = (26, 32, 56)
            index = (py * SIZE + px) * 3
            pixels[index:index + 3] = bytes(color)
    return pixels


def alpha_from(pixels: bytearray) -> bytearray:
    alpha = bytearray(SIZE * SIZE)
    for i in range(SIZE * SIZE):
        alpha[i] = 255 if any(pixels[i * 3:i * 3 + 3]) else 0
    return alpha


def png_bytes(pixels: bytearray, alpha: bytearray) -> bytes:
    raw = bytearray()
    for y in range(SIZE):
        raw.append(0)
        for x in range(SIZE):
            i = y * SIZE + x
            raw.extend(pixels[i * 3:i * 3 + 3])
            raw.append(alpha[i])
    compressed = zlib.compress(bytes(raw), 9)

    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data))

    header = struct.pack(">IIBBBBB", SIZE, SIZE, 8, 6, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header)
            + chunk(b"IDAT", compressed) + chunk(b"IEND", b""))


def ico_bytes(png: bytes) -> bytes:
    directory = struct.pack("<HHH", 0, 1, 1)
    entry = struct.pack("<BBBBHHII", 0, 0, 0, 0, 1, 32, len(png), 22)
    return directory + entry + png


def main() -> int:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "build/app.ico")
    pixels = render()
    png = png_bytes(pixels, alpha_from(pixels))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(ico_bytes(png))
    preview = out.with_suffix(".png")
    preview.write_bytes(png)
    print(f"아이콘 생성: {out}")
    print(f"미리보기: {preview}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
