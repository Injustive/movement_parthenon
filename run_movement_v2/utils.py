from aptos_sdk.async_client import ApiError
from utils.utils import sleep
from .aptos.client import AptosClient
from utils.models import RpcProviders
import io, math, secrets, hashlib, random
from typing import Tuple
import numpy as np
from PIL import Image, ImageDraw, ImageFilter, ImageFont
import string
import hashlib
from utils.utils import MaxLenException


COINS = {
    "MOVE": {
        "address": "0x000000000000000000000000000000000000000000000000000000000000000a",
        "decimals": 8,
        "meridian_ticket": "movement",
        "short_address": "0xa"
    },
    "USDC": {
        "address": "0x83121c9f9b0527d1f056e21a950d6bf3b9e9e2e8353d0e95ccea726713cbea39",
        "decimals": 6,
        "meridian_ticket": "usd-coin"
    },
    "USDT": {
        "address": "0x447721a30109c662dde9c73a0c2c9c9c459fb5e5a9c92f03c50fa69737f5d08d",
        "decimals": 6,
        "meridian_ticket": "tether"
    }
}

class FailedSimulatedTransaction(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.message = message

class NotEnoughMOVEException(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.message = message

class InvalidAccessToken(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.message = message

def retry(func):
    async def wrapper(obj, *args, **kwargs):
        attempts = 10
        while True:
            try:
                return await func(obj, *args, **kwargs)
            except ApiError as e:
                if 'used Cloudflare to restrict access' in str(e) or 'Just a moment' in str(e):
                    raise MaxLenException
                obj.logger.error(f'Aptos ApiError. Trying again...Attempt #{10-attempts}')
                obj.client = AptosClient(rest_api_url=RpcProviders.MOVEMENT_MAINNET.value).client
                await sleep(30, 90)
                attempts -= 1
                if attempts == 0:
                    raise
    return wrapper

def get_random_avatar():
    PALETTE = [
        "#3b82f6", "#22c55e", "#ef4444", "#a855f7", "#f59e0b",
        "#06b6d4", "#10b981", "#eab308", "#f472b6", "#94a3b8"
    ]
    def _hex_to_rgb(h: str) -> Tuple[int, int, int]:
        h = h.lstrip("#")
        return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))

    def _rng(seed: str):
        return random.Random(int(hashlib.sha256(seed.encode()).hexdigest(), 16))

    def avatar_blobs(seed, size=512):
        R = _rng(seed)
        bg1, bg2 = map(_hex_to_rgb, R.sample(PALETTE, 2))
        y, x = np.ogrid[:size, :size]
        cx, cy = size / 2, size / 2
        r = np.sqrt((x - cx) ** 2 + (y - cy) ** 2) / (size / 1.2)
        r = np.clip(r, 0, 1)
        grad = (np.outer(np.ones(size), np.linspace(0, 1, size)) + r) / 2
        grad = np.clip(grad, 0, 1)[..., None]
        bg = (np.array(bg1) * (1 - grad) + np.array(bg2) * grad).astype(np.uint8)
        base = Image.fromarray(bg, mode="RGB")

        layer = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        d = ImageDraw.Draw(layer)
        for _ in range(R.randint(3, 5)):
            w = R.randint(size // 3, int(size * 0.8))
            h = R.randint(size // 3, int(size * 0.8))
            x0 = R.randint(-w // 5, size - int(w * 0.8))
            y0 = R.randint(-h // 5, size - int(h * 0.8))
            color = _hex_to_rgb(R.choice(PALETTE))
            alpha = R.randint(110, 170)
            blob = Image.new("RGBA", (size, size), (0, 0, 0, 0))
            ImageDraw.Draw(blob).ellipse((x0, y0, x0 + w, y0 + h), fill=(*color, alpha))
            blob = blob.filter(ImageFilter.GaussianBlur(radius=R.randint(12, 28)))
            layer = Image.alpha_composite(layer, blob)
        out = base.convert("RGBA")
        out = Image.alpha_composite(out, layer)

        noise = (np.random.default_rng(int(seed.encode().hex(), 16) & 0xffffffff)
                 .integers(0, 16, (size, size, 1), np.uint8))
        tex = Image.fromarray(np.repeat(noise, 4, axis=2), "RGBA").filter(ImageFilter.GaussianBlur(0.8))
        out = Image.alpha_composite(out, tex.putalpha(25) or tex)
        buf = io.BytesIO()
        out.convert("RGB").save(buf, format="PNG", optimize=True)
        return buf.getvalue()

    def avatar_waves(seed, size=512):
        R = _rng(seed)
        c1, c2 = map(_hex_to_rgb, R.sample(PALETTE, 2))
        y, x = np.mgrid[0:size, 0:size].astype(np.float32) / size
        a1, a2 = R.uniform(6, 12), R.uniform(6, 12)
        ph1, ph2 = R.uniform(0, 2 * math.pi), R.uniform(0, 2 * math.pi)
        z = (np.sin(2 * math.pi * (a1 * x + a2 * y) + ph1) + np.sin(2 * math.pi * (a2 * x - a1 * y) + ph2)) * 0.5
        z = (z - z.min()) / (z.max() - z.min() + 1e-8)
        img = (np.array(c1) * (1 - z[..., None]) + np.array(c2) * z[..., None]).astype(np.uint8)
        im = Image.fromarray(img, "RGB").filter(ImageFilter.GaussianBlur(0.7))
        b = io.BytesIO();
        im.save(b, "PNG", optimize=True);
        return b.getvalue()

    def avatar_initials(seed, size=512):
        initials = ''.join(random.sample(string.ascii_uppercase, 2))
        R = _rng(seed)
        bg1, bg2 = map(_hex_to_rgb, R.sample(PALETTE, 2))
        t = np.linspace(0, 1, size, dtype=np.float32)[:, None]
        bg = (np.array(bg1, dtype=np.float32) * (1 - t) + np.array(bg2, dtype=np.float32) * t).astype(
            np.uint8)
        im = Image.fromarray(np.repeat(bg[None, ...], size, axis=0), "RGB")
        draw = ImageDraw.Draw(im)
        circle = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        ImageDraw.Draw(circle).ellipse((size * 0.18, size * 0.18, size * 0.82, size * 0.82),
                                       fill=(*_hex_to_rgb(R.choice(PALETTE)), 220))
        im = Image.alpha_composite(im.convert("RGBA"), circle)
        try:
            font = ImageFont.truetype("DejaVuSans-Bold.ttf", int(size * 0.32))
        except Exception:
            font = ImageFont.load_default()
        w, h = draw.textlength(initials, font=font), font.size
        draw = ImageDraw.Draw(im)
        draw.text(((size - w) / 2, (size - h) / 2), initials, fill="white", font=font)
        buf = io.BytesIO()
        im.convert("RGB").save(buf, "PNG", optimize=True)
        return buf.getvalue()
    seed = secrets.token_hex(6)
    random_func = random.choice([avatar_blobs, avatar_waves, avatar_initials])
    png = random_func(seed, size=512)
    return png

def generate_additional_wallet(parent_priv_hex, label = b"child:0"):
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # порядок secp256k1
    h = parent_priv_hex[2:] if parent_priv_hex.startswith("0x") else parent_priv_hex
    k = int(h, 16)
    tweak = int.from_bytes(hashlib.sha256(k.to_bytes(32, "big") + label).digest(), "big") % N
    child = (k + tweak) % N
    return "0x" + child.to_bytes(32, "big").hex()