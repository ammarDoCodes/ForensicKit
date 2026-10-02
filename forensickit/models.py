from dataclasses import dataclass
from .constants import SCHEMA_VERSION
@dataclass(frozen=True)
class Diagnostic:
    severity: str
    code: str
    message: str
    source_file_id: str | None = None
    source_locator: str | None = None
    def as_dict(self) -> dict: return {"schema_version": SCHEMA_VERSION, **{k: v for k, v in self.__dict__.items() if v is not None}}

