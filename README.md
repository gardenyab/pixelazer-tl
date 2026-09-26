# pixelazer-tl

Telegram MTProto client library for **Pixelazer Userbot**, based on AstralixTL and Telethon.

Repository: https://github.com/gardentab/pixelazer-tl. No project Telegram channels or chats.

## Install from source

```bash
uv venv .venv
uv pip install --python .venv/bin/python .
```

The distribution is named `pixelazer-tl`; Python imports use `pixelazertl`:

```python
from pixelazer import TelegramClient
```

The build generates Telegram types from the included schemas. Build a wheel with `uv build --wheel`.

## Security changes

This fork bounds packet lengths and gzip output, validates MTProto framing and DH responses with checks active under Python optimization, restricts web downloads to public HTTP(S) endpoints with TLS verification and size/time limits, hardens session-file permissions, and inspects renamed session uploads without optional dependencies.

These changes have regression tests in `tests/test_security.py`. They are a targeted review, not a guarantee that all vulnerabilities have been found. New DH primes and downloads above the configured limits require review. Live Telegram login has not been tested in this revision.

```bash
uv pip install --python .venv/bin/python aiohttp
.venv/bin/python -I -m unittest discover -s tests -v
.venv/bin/python -I -O -m unittest discover -s tests -v
```

## License and origins

MIT; see [LICENSE.md](LICENSE.md). Copyright notices for the upstream code and pixelazer modifications are retained. See [NOTICE.md](NOTICE.md).
