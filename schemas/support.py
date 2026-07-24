from dataclasses import dataclass
from typing import Optional

MIN_MSG_LEN = 3
MAX_MSG_LEN = 4000
MAX_SUBJECT_LEN = 200


@dataclass(frozen=True)
class SupportRequestInput:
    subject: Optional[str]
    message: str
    page_url: Optional[str]
    user_id: Optional[int]
    user_email: Optional[str]
    ip_addr: str
    user_agent: Optional[str]


class ValidationError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


def validate_support_input(
    subject: Optional[str],
    message: str,
    page_url: Optional[str],
    user_id: Optional[int],
    user_email: Optional[str],
    ip_addr: str,
    user_agent: Optional[str],
) -> SupportRequestInput:
    subj  = (subject or "").strip()[:MAX_SUBJECT_LEN] or None
    msg   = (message or "").strip()
    url   = (page_url or "").strip()[:2048] or None
    uagent= (user_agent or "").strip()[:512] or None

    if not (MIN_MSG_LEN <= len(msg) <= MAX_MSG_LEN):
        raise ValidationError(
            f"Please describe your issue in {MIN_MSG_LEN}–{MAX_MSG_LEN} characters."
        )

    if not ip_addr:
        raise ValidationError("Missing IP address.")

    return SupportRequestInput(
        subject=subj,
        message=msg,
        page_url=url,
        user_id=user_id,
        user_email=(user_email or None),
        ip_addr=ip_addr,
        user_agent=uagent,
    )
