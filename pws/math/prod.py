from typing import List


def prod(*args: int) -> int:
    """Returnthe product of `args`"""

    result = 1

    for e in args:
        result *= e

    return result

