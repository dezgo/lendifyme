"""Email utility functions for abuse prevention."""


def normalize_email(email: str) -> str:
    """
    Normalize email address to prevent trial abuse via aliases.

    This prevents users from getting multiple trials with:
    - Plus aliases: joe+test@gmail.com -> joe@gmail.com
    - Gmail dots: j.o.e@gmail.com -> joe@gmail.com

    Args:
        email: Raw email address

    Returns:
        Normalized email address (lowercase, no aliases, no dots for Gmail)

    Examples:
        >>> normalize_email("Joe+Test@Gmail.com")
        'joe@gmail.com'
        >>> normalize_email("j.o.e+test@gmail.com")
        'joe@gmail.com'
        >>> normalize_email("Alice+work@example.com")
        'alice@example.com'
    """
    if not email or '@' not in email:
        return email.lower().strip()

    email = email.lower().strip()
    local, domain = email.split('@', 1)

    # Remove +alias for all providers (common trick)
    if '+' in local:
        local = local.split('+')[0]

    # Gmail-specific: remove dots from local part
    # Gmail and GoogleMail ignore dots in addresses
    if domain in ['gmail.com', 'googlemail.com']:
        local = local.replace('.', '')

    return f"{local}@{domain}"
