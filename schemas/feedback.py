from dataclasses import dataclass
from typing import Optional

ALLOWED_FEEDBACK_TYPES = {"suggestion", "bug", "praise", "other"}
MIN_MSG_LEN = 3
MAX_MSG_LEN = 4000


@dataclass(frozen=True)
class FeedbackInput:
    feedback_type: str
    message: str
    page_url: Optional[str]
    page_title: Optional[str]
    user_id: Optional[int]
    user_email: Optional[str]
    ip_addr: str
    user_agent: Optional[str]


class ValidationError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


def validate_feedback_input(
    feedback_type: str,
    message: str,
    page_url: Optional[str],
    page_title: Optional[str],
    user_id: Optional[int],
    user_email: Optional[str],
    ip_addr: str,
    user_agent: Optional[str],
) -> FeedbackInput:
    ftype = (feedback_type or "other").strip().lower()
    msg   = (message or "").strip()
    url   = (page_url or "").strip()[:2048] or None
    title = (page_title or "").strip()[:512] or None
    uagent= (user_agent or "").strip()[:512] or None

    if ftype not in ALLOWED_FEEDBACK_TYPES:
        raise ValidationError("Invalid feedback type.")
    if not (MIN_MSG_LEN <= len(msg) <= MAX_MSG_LEN):
        raise ValidationError("Message length out of range.")

    if not ip_addr:
        raise ValidationError("Missing IP address.")

    return FeedbackInput(
        feedback_type=ftype,
        message=msg,
        page_url=url,
        page_title=title,
        user_id=user_id,
        user_email=(user_email or None),
        ip_addr=ip_addr,
        user_agent=uagent,
    )
