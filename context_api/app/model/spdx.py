from pydantic import BaseModel
from datetime import datetime

class CreationInfo(BaseModel):
    comment: str| None = None
    creators: list[str] | None
    created: datetime | None
    licenseListVersion: str | None

class Checksum(BaseModel):
    algorithm: str
    checkumValue: str

class ExternalRef(BaseModel):
    referenceCategory: str
    referenceType: str
    referenceLocator: str

class Package(BaseModel):
    SPDXID: str
    name: str
    versionInfo: str | None
    primaryPackagePurpose: str
    supplier: str
    downloadLocation: str
    filesAnalyzed: bool
    checksums: list[Checksum] | None = None
    licenseConcluded: str
    licenseDeclared: str
    licenseComments: str | None = None
    copyrightText: str
    summary: str | None = None
    externalRefs: list[ExternalRef] | None = None

class Relationship(BaseModel):
    spdxElementId: str
    relatedSpdxElement: str
    relationshipType: str

class SPDXDocument(BaseModel):
    SPDXID: str
    spdxVersion: str
    creationInfo: CreationInfo
    name: str | None
    dataLicense: str
    documentNamespace: str
    packages: list[Package]
    relationships: list[Relationship]
