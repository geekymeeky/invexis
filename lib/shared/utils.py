from datetime import datetime
from functools import wraps
from sentry_sdk import capture_exception


def get_timestamp() -> str:
    """Get the current timestamp in the format of YYYY-MM-DD HH:MM:SS"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def exception():

    def decorator(func):

        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                # Log the exception
                capture_exception(e)

        return wrapper

    return decorator
