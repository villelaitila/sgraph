from dataclasses import dataclass
from typing import List


@dataclass
class CommandResult:
    errors: List[str]
    output: List[str]
    return_code: int = 0

    def is_success(self):
        return self.return_code == 0
