from datetime import datetime


def timestamp_now() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S%f")
