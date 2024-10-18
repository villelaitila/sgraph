from enum import Enum


class FilterAssocations(Enum):
    Ignore = 1
    Direct = 2
    DirectAndIndirect = 3


class HaveAttributes(Enum):
    Ignore = 1
    IncludeCopy = 2
    IncludeReference = 3
