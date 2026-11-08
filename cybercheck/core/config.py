"""Small, bounded settings surface, shared by CLI and UI."""

import os
from dataclasses import dataclass
from pathlib import Path
from time import monotonic


class LimitReached(RuntimeError):
    pass


@dataclass(frozen=True)
class Settings:
    db_path: Path = Path("data/cybercheck.sqlite3")
    timeout: float = 5
    max_dns: int = 48
    max_http: int = 8
    max_redirects: int = 3
    max_seconds: float = 90

    def __post_init__(self) -> None:
        for name, low, high in (
            ("timeout", 0.1, 15),
            ("max_dns", 8, 100),
            ("max_http", 2, 20),
            ("max_redirects", 0, 5),
            ("max_seconds", 10, 180),
        ):
            if not low <= getattr(self, name) <= high:
                raise ValueError(f"{name} must be between {low} and {high}")

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            db_path=Path(os.getenv("CYBERCHECK_DB", "data/cybercheck.sqlite3")),
            timeout=float(os.getenv("CYBERCHECK_TIMEOUT", "5")),
            max_dns=int(os.getenv("CYBERCHECK_MAX_DNS", "48")),
            max_http=int(os.getenv("CYBERCHECK_MAX_HTTP", "8")),
            max_redirects=int(os.getenv("CYBERCHECK_MAX_REDIRECTS", "3")),
            max_seconds=float(os.getenv("CYBERCHECK_MAX_SECONDS", "90")),
        )


class Budget:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.started = monotonic()
        self.dns = 0
        self.http = 0

    def remaining(self) -> float:
        remaining = self.settings.max_seconds - (monotonic() - self.started)
        if remaining <= 0:
            raise LimitReached("Assessment time budget exhausted")
        return min(self.settings.timeout, remaining)

    def consume(self, kind: str) -> float:
        timeout = self.remaining()
        count = getattr(self, kind)
        if count >= getattr(self.settings, f"max_{kind}"):
            raise LimitReached(f"{kind.upper()} request budget exhausted")
        setattr(self, kind, count + 1)
        return timeout
