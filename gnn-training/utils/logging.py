import logging
from typing import Optional


def setup_logging(level: Optional[str] = "INFO") -> None:
    """Configure application logging."""
    logging.basicConfig(
        level=getattr(logging, (level or "INFO").upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )
