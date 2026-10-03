"""Account names excluded from human user administration."""


def account_name(user: str) -> str:
    account = user.strip().rsplit("\\", 1)[-1]
    return account.split("@", 1)[0]


def is_excluded_user(user: str) -> bool:
    account = account_name(user).casefold()
    return account == "krbtgt" or account.startswith("msol_")
