"""
Pydantic schemas for the ECU patcher endpoints.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Shared
# ---------------------------------------------------------------------------


class PatcherWarningsSchema(BaseModel):
    size_mismatch: bool = Field(
        False,
        description="True when the target file size differs from the recipe — possibly a different ECU model.",
    )
    size_mismatch_detail: str | None = Field(
        None,
        description="Human-readable explanation of the size mismatch. Null when size_mismatch is false.",
    )

    match_key_mismatch: bool = Field(
        False,
        description=(
            "True when the target binary's extracted match key differs from the "
            "recipe's recorded match key — this binary is a different ECU or calibration."
        ),
    )
    match_key_mismatch_detail: str | None = Field(
        None,
        description="Human-readable explanation of the match key mismatch. Null when match_key_mismatch is false.",
    )


# ---------------------------------------------------------------------------
# Strict validator — POST /patch/validate/strict
# ---------------------------------------------------------------------------


class StrictSummarySchema(BaseModel):
    total: int
    passed: int
    failed: int
    safe_to_patch: bool = Field(
        ...,
        description="True only when every instruction matched. Safe to call /patch/apply.",
    )


class ValidateStrictResponseSchema(BaseModel):
    """Response for POST /patch/validate/strict."""

    target_file: str
    target_md5: str
    warnings: PatcherWarningsSchema
    summary: StrictSummarySchema


# ---------------------------------------------------------------------------
# Existence validator — POST /patch/validate/exists
# ---------------------------------------------------------------------------


class ShiftedInstructionSchema(BaseModel):
    """An instruction whose ob was found, but at the wrong offset."""

    index: int
    expected_offset: str = Field(..., description="Offset from recipe (hex).")
    found_offset: str = Field(..., description="Closest match found (hex).")
    shift: int = Field(..., description="Byte difference: found minus expected.")
    match_count: int = Field(..., description="Total occurrences of ob in the binary.")


class MissingInstructionSchema(BaseModel):
    """An instruction whose ob was not found anywhere in the binary."""

    index: int
    expected_offset: str = Field(..., description="Offset from recipe (hex).")
    size: int


class ExistenceSummarySchema(BaseModel):
    total: int
    exact: int
    shifted: int
    missing: int
    verdict: str = Field(
        ...,
        description=(
            "'safe_exact' — all at correct offsets; "
            "'shifted_recoverable' — all present but some moved; "
            "'missing_unrecoverable' — one or more not found."
        ),
    )


class ValidateExistsResponseSchema(BaseModel):
    """Response for POST /patch/validate/exists."""

    target_file: str
    target_md5: str
    warnings: PatcherWarningsSchema
    summary: ExistenceSummarySchema
    shifted: List[ShiftedInstructionSchema] = Field(
        default_factory=list,
        description="Instructions found at a different offset than expected.",
    )
    missing: List[MissingInstructionSchema] = Field(
        default_factory=list,
        description="Instructions not found anywhere in the binary.",
    )


# ---------------------------------------------------------------------------
# Patched validator — POST /patch/validate/patched
# ---------------------------------------------------------------------------


class PatchedFailureSchema(BaseModel):
    """A single instruction whose mb was not confirmed after patching."""

    index: int
    offset: str = Field(..., description="Byte offset (hex).")
    size: int
    reason: str


class PatchedSummarySchema(BaseModel):
    total: int
    confirmed: int
    failed: int
    patch_confirmed: bool = Field(
        ...,
        description="True only when every instruction's mb was found at its offset.",
    )


class ValidatePatchedResponseSchema(BaseModel):
    """Response for POST /patch/validate/patched."""

    patched_file: str
    patched_md5: str
    warnings: PatcherWarningsSchema
    summary: PatchedSummarySchema
    failures: List[PatchedFailureSchema] = Field(
        default_factory=list,
        description="Instructions not confirmed. Empty when patch_confirmed is true.",
    )


# ---------------------------------------------------------------------------
# Patcher — POST /patch/apply
# (Binary returned as octet-stream; this schema lives in the X-Patch-Report header.)
# ---------------------------------------------------------------------------


class PatchFailedInstructionSchema(BaseModel):
    """An instruction the patcher could not apply."""

    index: int
    offset: str = Field(..., description="Expected offset (hex).")
    message: str


class PatchSummarySchema(BaseModel):
    total: int
    applied: int
    failed: int
    shifted: int = Field(
        ...,
        description="Applied at a different offset than recorded (ctx anchor moved).",
    )
    patch_applied: bool
    patched_md5: Optional[str] = Field(
        None,
        description="MD5 of the patched binary. Present only when patch_applied is true.",
    )


class PatchApplyResponseSchema(BaseModel):
    """Patch report embedded in X-Patch-Report header for POST /patch/apply."""

    target_file: str
    target_md5: str
    warnings: PatcherWarningsSchema
    summary: PatchSummarySchema
    failures: List[PatchFailedInstructionSchema] = Field(
        default_factory=list,
        description="Instructions that could not be applied. Empty on full success.",
    )
