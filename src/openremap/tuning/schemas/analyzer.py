from typing import List, Optional
from pydantic import BaseModel, Field


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
    Full analysis response — format-4.0 recipe ready for MongoDB storage
    and direct consumption by the patcher pipeline.
    """

    metadata: AnalysisMetadataSchema
    ecu: ECUIdentitySchema
    statistics: AnalysisStatisticsSchema
    instructions: List[InstructionSchema]
