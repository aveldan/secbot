from pydantic import BaseModel

class Context(BaseModel):
    package_name: str
    package_version: str | None = None
    package_ecosystem: str | None = None
    package_vulnerabilities: list[dict] | str | None = None