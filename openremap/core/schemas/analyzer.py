from typing import List, Optional
from pydantic import BaseModel, Field


class InstructionFlagSchema(BaseModel):
    """Annotation flag on a single instruction."""

    kind: str = Field(..., description="Flag type: VIN_SUSPECT, CHECKSUM_SUSPECT, etc.")
    reason: str = Field(..., description="Human-readable explanation")
    confidence: str = Field(..., description="HIGH, MEDIUM, or LOW")
    action: str = Field("REVIEW", description="Recommended action — always REVIEW")


class SupportedFamilySchema(BaseModel):
    manufacturer: str
    family: str
    extractor: str


class SupportedFamiliesResponseSchema(BaseModel):
    total: int
    families: List[SupportedFamilySchema]


class InstructionSchema(BaseModel):
    offset: int
    offset_hex: str
    size: int
    ob: str = Field(..., description="Original bytes at this offset (hex, uppercase)")
    mb: str = Field(..., description="Modified bytes to write (hex, uppercase)")
    ctx: str = Field(
        ...,
        description="Context bytes before the change — used as anchor (hex, uppercase)",
    )
    context_after: str
    context_size: int
    description: str
    flags: List[InstructionFlagSchema] = Field(
        default_factory=list,
        description="Annotation flags for suspicious changes (VIN, checksum, etc.)",
    )


class ECUIdentitySchema(BaseModel):
    """
    Lean ECU identity block.

    Used in two places:
      - POST /identify response
      - Embedded as the ``ecu`` block inside every recipe (consumed by the
        patcher pipeline for size and SW-version pre-flight checks).
    """

    manufacturer: Optional[str] = None
    match_key: Optional[str] = None
    ecu_family: Optional[str] = None
    ecu_variant: Optional[str] = None
    software_version: Optional[str] = Field(
        None, description="Software version string — also used for SW revision check"
    )
    hardware_number: Optional[str] = Field(
        None,
        description="Bosch hardware part number — present only when reliably found in the binary",
    )
    calibration_id: Optional[str] = Field(
        None,
        description=(
            "Calibration sub-version identifier. "
            "For most ECU families this supplements software_version (e.g. ME7 cal dataset). "
            "For LH-Jetronic Format A it is the sole identifier and drives match_key."
        ),
    )
    file_size: int
    sha256: str = Field(..., description="SHA-256 of the full binary file")


class AuthorSchema(BaseModel):
    """Recipe author identity."""

    name: Optional[str] = None
    handle: Optional[str] = None
    id: Optional[str] = Field(None, description="Platform-assigned UUID")


class CreatorSchema(BaseModel):
    """Recipe provenance metadata."""

    tool: str = Field(..., description="Tool that created the recipe")
    tool_version: str = Field(..., description="Tool version")
    created_at: str = Field(..., description="ISO 8601 UTC timestamp")
    author: Optional[AuthorSchema] = None
    signature: Optional[dict] = Field(None, description="Digital signature (future)")
    trust_level: str = Field(
        "UNSIGNED",
        description="UNSIGNED | COMMUNITY | SIGNED | VERIFIED",
    )


class AnalysisMetadataSchema(BaseModel):
    original_file: str
    modified_file: str
    original_size: int
    modified_size: int
    context_size: int
    format_version: str = "4.0"
    description: str


class AnalysisStatisticsSchema(BaseModel):
    total_changes: int
    total_bytes_changed: int
    percentage_changed: float
    single_byte_changes: int
    multi_byte_changes: int
    largest_change_size: int
    smallest_change_size: int
    context_size: int


class AnalyzerResponseSchema(BaseModel):
    """
    Full analysis response — format-4.0 recipe ready for serialisation
    and direct consumption by the patcher pipeline.
    """

    openremap: Optional[dict] = Field(
        None, description="Envelope with type and schema_version"
    )
    creator: Optional[CreatorSchema] = Field(
        None, description="Recipe provenance metadata"
    )
    fingerprint: Optional[str] = Field(
        None, description="SHA-256 fingerprint of instruction content"
    )
    metadata: AnalysisMetadataSchema
    ecu: ECUIdentitySchema
    statistics: AnalysisStatisticsSchema
    instructions: List[InstructionSchema]
