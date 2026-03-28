"""
Tests for Pydantic schemas in:
  - openremap.tuning.schemas.analyzer
  - openremap.tuning.schemas.patcher

Coverage target: 100% of both schema files.

Strategy:
  - Instantiate every schema with valid data and verify all fields.
  - Verify default values where applicable.
  - Verify that optional fields default to None when omitted.
  - Verify that required fields raise ValidationError when missing.
"""

import pytest
from pydantic import ValidationError

from openremap.tuning.schemas.analyzer import (
    AnalysisMetadataSchema,
    AnalysisStatisticsSchema,
    AnalyzerResponseSchema,
    ECUIdentitySchema,
    InstructionSchema,
    SupportedFamiliesResponseSchema,
    SupportedFamilySchema,
)
from openremap.tuning.schemas.patcher import (
    ExistenceSummarySchema,
    MissingInstructionSchema,
    PatchApplyResponseSchema,
    PatchedFailureSchema,
    PatchedSummarySchema,
    PatcherWarningsSchema,
    PatchFailedInstructionSchema,
    PatchSummarySchema,
    ShiftedInstructionSchema,
    StrictSummarySchema,
    ValidateExistsResponseSchema,
    ValidatePatchedResponseSchema,
    ValidateStrictResponseSchema,
)


# ===========================================================================
# Shared minimal fixture builders
# ===========================================================================

SHA256 = "a" * 64  # 64 hex chars — valid SHA-256 placeholder
MD5 = "b" * 32  # 32 hex chars — valid MD5 placeholder


def _make_instruction(**overrides) -> dict:
    base = {
        "offset": 0x1234,
        "offset_hex": "0x1234",
        "size": 4,
        "ob": "DEADBEEF",
        "mb": "00000000",
        "ctx": "CAFECAFE",
        "context_after": "BEEFDEAD",
        "context_size": 4,
        "description": "Test change at 0x1234",
    }
    base.update(overrides)
    return base


def _make_ecu_identity(**overrides) -> dict:
    base = {"file_size": 262144, "sha256": SHA256}
    base.update(overrides)
    return base


def _make_metadata(**overrides) -> dict:
    base = {
        "original_file": "original.bin",
        "modified_file": "modified.bin",
        "original_size": 262144,
        "modified_size": 262144,
        "context_size": 8,
        "description": "Test analysis result",
    }
    base.update(overrides)
    return base


def _make_statistics(**overrides) -> dict:
    base = {
        "total_changes": 5,
        "total_bytes_changed": 20,
        "percentage_changed": 0.0076,
        "single_byte_changes": 3,
        "multi_byte_changes": 2,
        "largest_change_size": 8,
        "smallest_change_size": 1,
        "context_size": 8,
    }
    base.update(overrides)
    return base


def _make_patcher_warnings(**overrides) -> dict:
    base = {}
    base.update(overrides)
    return base


def _make_strict_summary(**overrides) -> dict:
    base = {"total": 10, "passed": 10, "failed": 0, "safe_to_patch": True}
    base.update(overrides)
    return base


def _make_existence_summary(**overrides) -> dict:
    base = {
        "total": 10,
        "exact": 10,
        "shifted": 0,
        "missing": 0,
        "verdict": "safe_exact",
    }
    base.update(overrides)
    return base


def _make_patched_summary(**overrides) -> dict:
    base = {"total": 10, "confirmed": 10, "failed": 0, "patch_confirmed": True}
    base.update(overrides)
    return base


def _make_patch_summary(**overrides) -> dict:
    base = {
        "total": 10,
        "applied": 10,
        "failed": 0,
        "shifted": 0,
        "patch_applied": True,
        "patched_md5": MD5,
    }
    base.update(overrides)
    return base


# ===========================================================================
# analyzer.py — SupportedFamilySchema
# ===========================================================================


class TestSupportedFamilySchema:
    def test_valid_instantiation(self):
        obj = SupportedFamilySchema(
            manufacturer="Bosch",
            family="EDC16C8",
            extractor="BoschEDC16Extractor",
        )
        assert obj.manufacturer == "Bosch"
        assert obj.family == "EDC16C8"
        assert obj.extractor == "BoschEDC16Extractor"

    def test_all_fields_are_strings(self):
        obj = SupportedFamilySchema(
            manufacturer="Bosch", family="EDC17", extractor="BoschEDC17Extractor"
        )
        assert isinstance(obj.manufacturer, str)
        assert isinstance(obj.family, str)
        assert isinstance(obj.extractor, str)

    def test_missing_manufacturer_raises(self):
        with pytest.raises(ValidationError):
            SupportedFamilySchema(family="EDC16", extractor="SomeExtractor")

    def test_missing_family_raises(self):
        with pytest.raises(ValidationError):
            SupportedFamilySchema(manufacturer="Bosch", extractor="SomeExtractor")

    def test_missing_extractor_raises(self):
        with pytest.raises(ValidationError):
            SupportedFamilySchema(manufacturer="Bosch", family="EDC16")

    def test_all_fields_missing_raises(self):
        with pytest.raises(ValidationError):
            SupportedFamilySchema()

    def test_different_manufacturers(self):
        for mfr in ("Bosch", "Siemens", "Delphi", "Marelli"):
            obj = SupportedFamilySchema(
                manufacturer=mfr, family="TestFamily", extractor="TestExtractor"
            )
            assert obj.manufacturer == mfr


# ===========================================================================
# analyzer.py — SupportedFamiliesResponseSchema
# ===========================================================================


class TestSupportedFamiliesResponseSchema:
    def test_valid_instantiation_empty_families(self):
        obj = SupportedFamiliesResponseSchema(total=0, families=[])
        assert obj.total == 0
        assert obj.families == []

    def test_valid_instantiation_with_families(self):
        family = SupportedFamilySchema(
            manufacturer="Bosch", family="EDC16", extractor="BoschEDC16Extractor"
        )
        obj = SupportedFamiliesResponseSchema(total=1, families=[family])
        assert obj.total == 1
        assert len(obj.families) == 1
        assert obj.families[0].family == "EDC16"

    def test_families_list_length_matches_total(self):
        fam = SupportedFamilySchema(
            manufacturer="Bosch", family="EDC15", extractor="BoschEDC15Extractor"
        )
        obj = SupportedFamiliesResponseSchema(total=1, families=[fam])
        assert obj.total == len(obj.families)

    def test_missing_total_raises(self):
        with pytest.raises(ValidationError):
            SupportedFamiliesResponseSchema(families=[])

    def test_missing_families_raises(self):
        with pytest.raises(ValidationError):
            SupportedFamiliesResponseSchema(total=0)

    def test_multiple_families(self):
        families = [
            SupportedFamilySchema(
                manufacturer="Bosch", family=f"EDC{i}", extractor=f"Ext{i}"
            )
            for i in range(3)
        ]
        obj = SupportedFamiliesResponseSchema(total=3, families=families)
        assert obj.total == 3
        assert len(obj.families) == 3

    def test_accepts_dict_list_for_families(self):
        obj = SupportedFamiliesResponseSchema(
            total=1,
            families=[
                {
                    "manufacturer": "Bosch",
                    "family": "ME7",
                    "extractor": "BoschME7Extractor",
                }
            ],
        )
        assert obj.families[0].family == "ME7"


# ===========================================================================
# analyzer.py — InstructionSchema
# ===========================================================================


class TestInstructionSchema:
    def test_valid_instantiation(self):
        obj = InstructionSchema(**_make_instruction())
        assert obj.offset == 0x1234
        assert obj.offset_hex == "0x1234"
        assert obj.size == 4
        assert obj.ob == "DEADBEEF"
        assert obj.mb == "00000000"
        assert obj.ctx == "CAFECAFE"
        assert obj.context_after == "BEEFDEAD"
        assert obj.context_size == 4
        assert obj.description == "Test change at 0x1234"

    def test_offset_is_int(self):
        obj = InstructionSchema(**_make_instruction())
        assert isinstance(obj.offset, int)

    def test_size_is_int(self):
        obj = InstructionSchema(**_make_instruction())
        assert isinstance(obj.size, int)

    def test_context_size_is_int(self):
        obj = InstructionSchema(**_make_instruction())
        assert isinstance(obj.context_size, int)

    def test_all_string_fields(self):
        obj = InstructionSchema(**_make_instruction())
        for field in ("offset_hex", "ob", "mb", "ctx", "context_after", "description"):
            assert isinstance(getattr(obj, field), str), f"{field} should be str"

    def test_missing_offset_raises(self):
        data = _make_instruction()
        del data["offset"]
        with pytest.raises(ValidationError):
            InstructionSchema(**data)

    def test_missing_ob_raises(self):
        data = _make_instruction()
        del data["ob"]
        with pytest.raises(ValidationError):
            InstructionSchema(**data)

    def test_missing_mb_raises(self):
        data = _make_instruction()
        del data["mb"]
        with pytest.raises(ValidationError):
            InstructionSchema(**data)

    def test_missing_ctx_raises(self):
        data = _make_instruction()
        del data["ctx"]
        with pytest.raises(ValidationError):
            InstructionSchema(**data)

    def test_missing_description_raises(self):
        data = _make_instruction()
        del data["description"]
        with pytest.raises(ValidationError):
            InstructionSchema(**data)

    def test_zero_offset_allowed(self):
        obj = InstructionSchema(**_make_instruction(offset=0, offset_hex="0x0"))
        assert obj.offset == 0

    def test_large_offset_allowed(self):
        obj = InstructionSchema(
            **_make_instruction(offset=0xFFFF00, offset_hex="0xFFFF00")
        )
        assert obj.offset == 0xFFFF00

    def test_single_byte_instruction(self):
        obj = InstructionSchema(**_make_instruction(size=1, ob="FF", mb="00"))
        assert obj.size == 1

    def test_empty_context_allowed(self):
        obj = InstructionSchema(**_make_instruction(ctx="", context_size=0))
        assert obj.ctx == ""
        assert obj.context_size == 0


# ===========================================================================
# analyzer.py — ECUIdentitySchema
# ===========================================================================


class TestECUIdentitySchema:
    def test_minimal_valid_instantiation(self):
        """Only file_size and sha256 are required; rest default to None."""
        obj = ECUIdentitySchema(file_size=262144, sha256=SHA256)
        assert obj.file_size == 262144
        assert obj.sha256 == SHA256

    def test_all_optional_fields_default_to_none(self):
        obj = ECUIdentitySchema(file_size=262144, sha256=SHA256)
        assert obj.manufacturer is None
        assert obj.match_key is None
        assert obj.ecu_family is None
        assert obj.ecu_variant is None
        assert obj.software_version is None
        assert obj.hardware_number is None
        assert obj.calibration_id is None

    def test_all_optional_fields_explicitly_none(self):
        obj = ECUIdentitySchema(
            file_size=262144,
            sha256=SHA256,
            manufacturer=None,
            match_key=None,
            ecu_family=None,
            ecu_variant=None,
            software_version=None,
            hardware_number=None,
            calibration_id=None,
        )
        assert obj.manufacturer is None
        assert obj.match_key is None
        assert obj.ecu_family is None
        assert obj.ecu_variant is None
        assert obj.software_version is None
        assert obj.hardware_number is None
        assert obj.calibration_id is None

    def test_all_fields_populated(self):
        obj = ECUIdentitySchema(
            manufacturer="Bosch",
            match_key="EDC16C8::1037369261",
            ecu_family="EDC16C8",
            ecu_variant="EDC16C8",
            software_version="1037369261",
            hardware_number="0281001658",
            calibration_id="C86BM500",
            file_size=1048576,
            sha256=SHA256,
        )
        assert obj.manufacturer == "Bosch"
        assert obj.match_key == "EDC16C8::1037369261"
        assert obj.ecu_family == "EDC16C8"
        assert obj.ecu_variant == "EDC16C8"
        assert obj.software_version == "1037369261"
        assert obj.hardware_number == "0281001658"
        assert obj.calibration_id == "C86BM500"
        assert obj.file_size == 1048576
        assert obj.sha256 == SHA256

    def test_missing_file_size_raises(self):
        with pytest.raises(ValidationError):
            ECUIdentitySchema(sha256=SHA256)

    def test_missing_sha256_raises(self):
        with pytest.raises(ValidationError):
            ECUIdentitySchema(file_size=262144)

    def test_both_required_missing_raises(self):
        with pytest.raises(ValidationError):
            ECUIdentitySchema()

    def test_file_size_is_int(self):
        obj = ECUIdentitySchema(file_size=65536, sha256=SHA256)
        assert isinstance(obj.file_size, int)

    def test_sha256_is_str(self):
        obj = ECUIdentitySchema(file_size=65536, sha256=SHA256)
        assert isinstance(obj.sha256, str)

    def test_software_version_field_description_exists(self):
        """Verify the field descriptor is accessible on the model."""
        fields = ECUIdentitySchema.model_fields
        assert "software_version" in fields

    def test_hardware_number_field_description_exists(self):
        fields = ECUIdentitySchema.model_fields
        assert "hardware_number" in fields

    def test_calibration_id_field_description_exists(self):
        fields = ECUIdentitySchema.model_fields
        assert "calibration_id" in fields


# ===========================================================================
# analyzer.py — AnalysisMetadataSchema
# ===========================================================================


class TestAnalysisMetadataSchema:
    def test_valid_instantiation(self):
        obj = AnalysisMetadataSchema(**_make_metadata())
        assert obj.original_file == "original.bin"
        assert obj.modified_file == "modified.bin"
        assert obj.original_size == 262144
        assert obj.modified_size == 262144
        assert obj.context_size == 8
        assert obj.description == "Test analysis result"

    def test_format_version_default(self):
        obj = AnalysisMetadataSchema(**_make_metadata())
        assert obj.format_version == "4.0"

    def test_format_version_can_be_overridden(self):
        obj = AnalysisMetadataSchema(**_make_metadata(format_version="5.0"))
        assert obj.format_version == "5.0"

    def test_missing_original_file_raises(self):
        data = _make_metadata()
        del data["original_file"]
        with pytest.raises(ValidationError):
            AnalysisMetadataSchema(**data)

    def test_missing_modified_file_raises(self):
        data = _make_metadata()
        del data["modified_file"]
        with pytest.raises(ValidationError):
            AnalysisMetadataSchema(**data)

    def test_missing_original_size_raises(self):
        data = _make_metadata()
        del data["original_size"]
        with pytest.raises(ValidationError):
            AnalysisMetadataSchema(**data)

    def test_missing_modified_size_raises(self):
        data = _make_metadata()
        del data["modified_size"]
        with pytest.raises(ValidationError):
            AnalysisMetadataSchema(**data)

    def test_missing_context_size_raises(self):
        data = _make_metadata()
        del data["context_size"]
        with pytest.raises(ValidationError):
            AnalysisMetadataSchema(**data)

    def test_missing_description_raises(self):
        data = _make_metadata()
        del data["description"]
        with pytest.raises(ValidationError):
            AnalysisMetadataSchema(**data)

    def test_file_sizes_are_ints(self):
        obj = AnalysisMetadataSchema(**_make_metadata())
        assert isinstance(obj.original_size, int)
        assert isinstance(obj.modified_size, int)
        assert isinstance(obj.context_size, int)

    def test_different_original_and_modified_sizes(self):
        obj = AnalysisMetadataSchema(
            **_make_metadata(original_size=65536, modified_size=65537)
        )
        assert obj.original_size == 65536
        assert obj.modified_size == 65537


# ===========================================================================
# analyzer.py — AnalysisStatisticsSchema
# ===========================================================================


class TestAnalysisStatisticsSchema:
    def test_valid_instantiation(self):
        obj = AnalysisStatisticsSchema(**_make_statistics())
        assert obj.total_changes == 5
        assert obj.total_bytes_changed == 20
        assert obj.percentage_changed == pytest.approx(0.0076)
        assert obj.single_byte_changes == 3
        assert obj.multi_byte_changes == 2
        assert obj.largest_change_size == 8
        assert obj.smallest_change_size == 1
        assert obj.context_size == 8

    def test_all_integer_fields(self):
        obj = AnalysisStatisticsSchema(**_make_statistics())
        for field in (
            "total_changes",
            "total_bytes_changed",
            "single_byte_changes",
            "multi_byte_changes",
            "largest_change_size",
            "smallest_change_size",
            "context_size",
        ):
            assert isinstance(getattr(obj, field), int), f"{field} should be int"

    def test_percentage_is_float(self):
        obj = AnalysisStatisticsSchema(**_make_statistics())
        assert isinstance(obj.percentage_changed, float)

    def test_zero_changes_allowed(self):
        obj = AnalysisStatisticsSchema(
            **_make_statistics(
                total_changes=0,
                total_bytes_changed=0,
                percentage_changed=0.0,
                single_byte_changes=0,
                multi_byte_changes=0,
                largest_change_size=0,
                smallest_change_size=0,
            )
        )
        assert obj.total_changes == 0
        assert obj.percentage_changed == 0.0

    def test_missing_total_changes_raises(self):
        data = _make_statistics()
        del data["total_changes"]
        with pytest.raises(ValidationError):
            AnalysisStatisticsSchema(**data)

    def test_missing_percentage_changed_raises(self):
        data = _make_statistics()
        del data["percentage_changed"]
        with pytest.raises(ValidationError):
            AnalysisStatisticsSchema(**data)

    def test_missing_largest_change_size_raises(self):
        data = _make_statistics()
        del data["largest_change_size"]
        with pytest.raises(ValidationError):
            AnalysisStatisticsSchema(**data)

    def test_missing_context_size_raises(self):
        data = _make_statistics()
        del data["context_size"]
        with pytest.raises(ValidationError):
            AnalysisStatisticsSchema(**data)

    def test_percentage_over_one_allowed(self):
        """Schema does not clamp percentage — 100% would be 1.0 or 100.0."""
        obj = AnalysisStatisticsSchema(**_make_statistics(percentage_changed=1.0))
        assert obj.percentage_changed == pytest.approx(1.0)


# ===========================================================================
# analyzer.py — AnalyzerResponseSchema
# ===========================================================================


class TestAnalyzerResponseSchema:
    def _make_full(self, instructions=None):
        if instructions is None:
            instructions = [InstructionSchema(**_make_instruction())]
        return AnalyzerResponseSchema(
            metadata=AnalysisMetadataSchema(**_make_metadata()),
            ecu=ECUIdentitySchema(**_make_ecu_identity()),
            statistics=AnalysisStatisticsSchema(**_make_statistics()),
            instructions=instructions,
        )

    def test_valid_instantiation(self):
        obj = self._make_full()
        assert obj.metadata is not None
        assert obj.ecu is not None
        assert obj.statistics is not None
        assert isinstance(obj.instructions, list)

    def test_instructions_list_is_list(self):
        obj = self._make_full()
        assert isinstance(obj.instructions, list)

    def test_empty_instructions_list_allowed(self):
        obj = self._make_full(instructions=[])
        assert obj.instructions == []

    def test_multiple_instructions(self):
        instructions = [
            InstructionSchema(**_make_instruction(offset=i, offset_hex=hex(i)))
            for i in range(5)
        ]
        obj = self._make_full(instructions=instructions)
        assert len(obj.instructions) == 5

    def test_missing_metadata_raises(self):
        with pytest.raises(ValidationError):
            AnalyzerResponseSchema(
                ecu=ECUIdentitySchema(**_make_ecu_identity()),
                statistics=AnalysisStatisticsSchema(**_make_statistics()),
                instructions=[],
            )

    def test_missing_ecu_raises(self):
        with pytest.raises(ValidationError):
            AnalyzerResponseSchema(
                metadata=AnalysisMetadataSchema(**_make_metadata()),
                statistics=AnalysisStatisticsSchema(**_make_statistics()),
                instructions=[],
            )

    def test_missing_statistics_raises(self):
        with pytest.raises(ValidationError):
            AnalyzerResponseSchema(
                metadata=AnalysisMetadataSchema(**_make_metadata()),
                ecu=ECUIdentitySchema(**_make_ecu_identity()),
                instructions=[],
            )

    def test_missing_instructions_raises(self):
        with pytest.raises(ValidationError):
            AnalyzerResponseSchema(
                metadata=AnalysisMetadataSchema(**_make_metadata()),
                ecu=ECUIdentitySchema(**_make_ecu_identity()),
                statistics=AnalysisStatisticsSchema(**_make_statistics()),
            )

    def test_accepts_dict_for_nested_schemas(self):
        obj = AnalyzerResponseSchema(
            metadata=_make_metadata(),
            ecu=_make_ecu_identity(),
            statistics=_make_statistics(),
            instructions=[_make_instruction()],
        )
        assert isinstance(obj.metadata, AnalysisMetadataSchema)
        assert isinstance(obj.ecu, ECUIdentitySchema)
        assert isinstance(obj.statistics, AnalysisStatisticsSchema)
        assert isinstance(obj.instructions[0], InstructionSchema)

    def test_ecu_fields_accessible(self):
        obj = self._make_full()
        assert obj.ecu.file_size == 262144
        assert obj.ecu.sha256 == SHA256

    def test_metadata_format_version_default_propagates(self):
        obj = self._make_full()
        assert obj.metadata.format_version == "4.0"


# ===========================================================================
# patcher.py — PatcherWarningsSchema
# ===========================================================================


class TestPatcherWarningsSchema:
    def test_default_instantiation_no_args(self):
        obj = PatcherWarningsSchema()
        assert obj.size_mismatch is False
        assert obj.size_mismatch_detail is None
        assert obj.match_key_mismatch is False
        assert obj.match_key_mismatch_detail is None

    def test_size_mismatch_default_false(self):
        obj = PatcherWarningsSchema()
        assert obj.size_mismatch is False

    def test_match_key_mismatch_default_false(self):
        obj = PatcherWarningsSchema()
        assert obj.match_key_mismatch is False

    def test_size_mismatch_detail_default_none(self):
        obj = PatcherWarningsSchema()
        assert obj.size_mismatch_detail is None

    def test_match_key_mismatch_detail_default_none(self):
        obj = PatcherWarningsSchema()
        assert obj.match_key_mismatch_detail is None

    def test_with_size_mismatch_true(self):
        obj = PatcherWarningsSchema(
            size_mismatch=True,
            size_mismatch_detail="Expected 262144 bytes, got 1048576 bytes.",
        )
        assert obj.size_mismatch is True
        assert obj.size_mismatch_detail == "Expected 262144 bytes, got 1048576 bytes."

    def test_with_match_key_mismatch_true(self):
        obj = PatcherWarningsSchema(
            match_key_mismatch=True,
            match_key_mismatch_detail="Binary key 'EDC16::1037369261' != recipe key 'EDC16::1037370634'.",
        )
        assert obj.match_key_mismatch is True
        assert "EDC16" in obj.match_key_mismatch_detail

    def test_all_warnings_set(self):
        obj = PatcherWarningsSchema(
            size_mismatch=True,
            size_mismatch_detail="Size differs.",
            match_key_mismatch=True,
            match_key_mismatch_detail="Key differs.",
        )
        assert obj.size_mismatch is True
        assert obj.match_key_mismatch is True
        assert obj.size_mismatch_detail == "Size differs."
        assert obj.match_key_mismatch_detail == "Key differs."

    def test_detail_can_be_explicitly_none(self):
        obj = PatcherWarningsSchema(size_mismatch=False, size_mismatch_detail=None)
        assert obj.size_mismatch_detail is None

    def test_field_descriptions_exist(self):
        fields = PatcherWarningsSchema.model_fields
        assert "size_mismatch" in fields
        assert "match_key_mismatch" in fields


# ===========================================================================
# patcher.py — StrictSummarySchema
# ===========================================================================


class TestStrictSummarySchema:
    def test_valid_instantiation_all_passed(self):
        obj = StrictSummarySchema(total=10, passed=10, failed=0, safe_to_patch=True)
        assert obj.total == 10
        assert obj.passed == 10
        assert obj.failed == 0
        assert obj.safe_to_patch is True

    def test_valid_instantiation_some_failed(self):
        obj = StrictSummarySchema(total=10, passed=7, failed=3, safe_to_patch=False)
        assert obj.safe_to_patch is False
        assert obj.failed == 3

    def test_safe_to_patch_has_no_default(self):
        """safe_to_patch is required — omitting it raises ValidationError."""
        with pytest.raises(ValidationError):
            StrictSummarySchema(total=10, passed=10, failed=0)

    def test_missing_total_raises(self):
        with pytest.raises(ValidationError):
            StrictSummarySchema(passed=10, failed=0, safe_to_patch=True)

    def test_missing_passed_raises(self):
        with pytest.raises(ValidationError):
            StrictSummarySchema(total=10, failed=0, safe_to_patch=True)

    def test_missing_failed_raises(self):
        with pytest.raises(ValidationError):
            StrictSummarySchema(total=10, passed=10, safe_to_patch=True)

    def test_zero_total_allowed(self):
        obj = StrictSummarySchema(total=0, passed=0, failed=0, safe_to_patch=True)
        assert obj.total == 0

    def test_all_fields_are_correct_types(self):
        obj = StrictSummarySchema(total=5, passed=5, failed=0, safe_to_patch=True)
        assert isinstance(obj.total, int)
        assert isinstance(obj.passed, int)
        assert isinstance(obj.failed, int)
        assert isinstance(obj.safe_to_patch, bool)


# ===========================================================================
# patcher.py — ValidateStrictResponseSchema
# ===========================================================================


class TestValidateStrictResponseSchema:
    def _make(self, **overrides):
        base = {
            "target_file": "target.bin",
            "target_md5": MD5,
            "warnings": PatcherWarningsSchema(),
            "summary": StrictSummarySchema(**_make_strict_summary()),
        }
        base.update(overrides)
        return ValidateStrictResponseSchema(**base)

    def test_valid_instantiation(self):
        obj = self._make()
        assert obj.target_file == "target.bin"
        assert obj.target_md5 == MD5
        assert isinstance(obj.warnings, PatcherWarningsSchema)
        assert isinstance(obj.summary, StrictSummarySchema)

    def test_missing_target_file_raises(self):
        with pytest.raises(ValidationError):
            ValidateStrictResponseSchema(
                target_md5=MD5,
                warnings=PatcherWarningsSchema(),
                summary=StrictSummarySchema(**_make_strict_summary()),
            )

    def test_missing_target_md5_raises(self):
        with pytest.raises(ValidationError):
            ValidateStrictResponseSchema(
                target_file="target.bin",
                warnings=PatcherWarningsSchema(),
                summary=StrictSummarySchema(**_make_strict_summary()),
            )

    def test_missing_warnings_raises(self):
        with pytest.raises(ValidationError):
            ValidateStrictResponseSchema(
                target_file="target.bin",
                target_md5=MD5,
                summary=StrictSummarySchema(**_make_strict_summary()),
            )

    def test_missing_summary_raises(self):
        with pytest.raises(ValidationError):
            ValidateStrictResponseSchema(
                target_file="target.bin",
                target_md5=MD5,
                warnings=PatcherWarningsSchema(),
            )

    def test_accepts_dict_for_warnings_and_summary(self):
        obj = ValidateStrictResponseSchema(
            target_file="target.bin",
            target_md5=MD5,
            warnings={},
            summary=_make_strict_summary(),
        )
        assert isinstance(obj.warnings, PatcherWarningsSchema)
        assert isinstance(obj.summary, StrictSummarySchema)

    def test_summary_safe_to_patch_accessible(self):
        obj = self._make()
        assert obj.summary.safe_to_patch is True

    def test_warnings_defaults_propagate(self):
        obj = self._make()
        assert obj.warnings.size_mismatch is False
        assert obj.warnings.match_key_mismatch is False


# ===========================================================================
# patcher.py — ShiftedInstructionSchema
# ===========================================================================


class TestShiftedInstructionSchema:
    def _make(self, **overrides):
        base = {
            "index": 0,
            "expected_offset": "0x1234",
            "found_offset": "0x1240",
            "shift": 12,
            "match_count": 1,
        }
        base.update(overrides)
        return ShiftedInstructionSchema(**base)

    def test_valid_instantiation(self):
        obj = self._make()
        assert obj.index == 0
        assert obj.expected_offset == "0x1234"
        assert obj.found_offset == "0x1240"
        assert obj.shift == 12
        assert obj.match_count == 1

    def test_negative_shift_allowed(self):
        obj = self._make(shift=-8)
        assert obj.shift == -8

    def test_missing_index_raises(self):
        with pytest.raises(ValidationError):
            ShiftedInstructionSchema(
                expected_offset="0x1234", found_offset="0x1240", shift=12, match_count=1
            )

    def test_missing_expected_offset_raises(self):
        with pytest.raises(ValidationError):
            ShiftedInstructionSchema(
                index=0, found_offset="0x1240", shift=12, match_count=1
            )

    def test_missing_found_offset_raises(self):
        with pytest.raises(ValidationError):
            ShiftedInstructionSchema(
                index=0, expected_offset="0x1234", shift=12, match_count=1
            )

    def test_missing_shift_raises(self):
        with pytest.raises(ValidationError):
            ShiftedInstructionSchema(
                index=0, expected_offset="0x1234", found_offset="0x1240", match_count=1
            )

    def test_missing_match_count_raises(self):
        with pytest.raises(ValidationError):
            ShiftedInstructionSchema(
                index=0, expected_offset="0x1234", found_offset="0x1240", shift=12
            )

    def test_high_match_count(self):
        obj = self._make(match_count=99)
        assert obj.match_count == 99

    def test_field_descriptions_exist(self):
        fields = ShiftedInstructionSchema.model_fields
        for f in ("expected_offset", "found_offset", "shift", "match_count"):
            assert f in fields


# ===========================================================================
# patcher.py — MissingInstructionSchema
# ===========================================================================


class TestMissingInstructionSchema:
    def test_valid_instantiation(self):
        obj = MissingInstructionSchema(index=2, expected_offset="0xABCD", size=4)
        assert obj.index == 2
        assert obj.expected_offset == "0xABCD"
        assert obj.size == 4

    def test_missing_index_raises(self):
        with pytest.raises(ValidationError):
            MissingInstructionSchema(expected_offset="0xABCD", size=4)

    def test_missing_expected_offset_raises(self):
        with pytest.raises(ValidationError):
            MissingInstructionSchema(index=0, size=4)

    def test_missing_size_raises(self):
        with pytest.raises(ValidationError):
            MissingInstructionSchema(index=0, expected_offset="0xABCD")

    def test_size_one_allowed(self):
        obj = MissingInstructionSchema(index=0, expected_offset="0x0", size=1)
        assert obj.size == 1

    def test_all_fields_correct_type(self):
        obj = MissingInstructionSchema(index=5, expected_offset="0xFF00", size=8)
        assert isinstance(obj.index, int)
        assert isinstance(obj.expected_offset, str)
        assert isinstance(obj.size, int)


# ===========================================================================
# patcher.py — ExistenceSummarySchema
# ===========================================================================


class TestExistenceSummarySchema:
    def test_valid_instantiation_all_exact(self):
        obj = ExistenceSummarySchema(**_make_existence_summary())
        assert obj.total == 10
        assert obj.exact == 10
        assert obj.shifted == 0
        assert obj.missing == 0
        assert obj.verdict == "safe_exact"

    def test_verdict_shifted_recoverable(self):
        obj = ExistenceSummarySchema(
            total=10, exact=8, shifted=2, missing=0, verdict="shifted_recoverable"
        )
        assert obj.verdict == "shifted_recoverable"

    def test_verdict_missing_unrecoverable(self):
        obj = ExistenceSummarySchema(
            total=10, exact=7, shifted=0, missing=3, verdict="missing_unrecoverable"
        )
        assert obj.verdict == "missing_unrecoverable"

    def test_missing_total_raises(self):
        data = _make_existence_summary()
        del data["total"]
        with pytest.raises(ValidationError):
            ExistenceSummarySchema(**data)

    def test_missing_verdict_raises(self):
        data = _make_existence_summary()
        del data["verdict"]
        with pytest.raises(ValidationError):
            ExistenceSummarySchema(**data)

    def test_missing_exact_raises(self):
        data = _make_existence_summary()
        del data["exact"]
        with pytest.raises(ValidationError):
            ExistenceSummarySchema(**data)

    def test_all_fields_correct_type(self):
        obj = ExistenceSummarySchema(**_make_existence_summary())
        assert isinstance(obj.total, int)
        assert isinstance(obj.exact, int)
        assert isinstance(obj.shifted, int)
        assert isinstance(obj.missing, int)
        assert isinstance(obj.verdict, str)


# ===========================================================================
# patcher.py — ValidateExistsResponseSchema
# ===========================================================================


class TestValidateExistsResponseSchema:
    def _make(self, **overrides):
        base = {
            "target_file": "target.bin",
            "target_md5": MD5,
            "warnings": PatcherWarningsSchema(),
            "summary": ExistenceSummarySchema(**_make_existence_summary()),
        }
        base.update(overrides)
        return ValidateExistsResponseSchema(**base)

    def test_valid_instantiation_no_shifted_or_missing(self):
        obj = self._make()
        assert obj.target_file == "target.bin"
        assert obj.shifted == []
        assert obj.missing == []

    def test_shifted_default_empty_list(self):
        obj = self._make()
        assert obj.shifted == []

    def test_missing_default_empty_list(self):
        obj = self._make()
        assert obj.missing == []

    def test_with_shifted_instructions(self):
        shifted = [
            ShiftedInstructionSchema(
                index=0,
                expected_offset="0x100",
                found_offset="0x110",
                shift=16,
                match_count=1,
            )
        ]
        obj = self._make(shifted=shifted)
        assert len(obj.shifted) == 1
        assert obj.shifted[0].shift == 16

    def test_with_missing_instructions(self):
        missing = [MissingInstructionSchema(index=1, expected_offset="0x200", size=4)]
        obj = self._make(missing=missing)
        assert len(obj.missing) == 1
        assert obj.missing[0].size == 4

    def test_missing_target_file_raises(self):
        with pytest.raises(ValidationError):
            ValidateExistsResponseSchema(
                target_md5=MD5,
                warnings=PatcherWarningsSchema(),
                summary=ExistenceSummarySchema(**_make_existence_summary()),
            )

    def test_missing_summary_raises(self):
        with pytest.raises(ValidationError):
            ValidateExistsResponseSchema(
                target_file="target.bin",
                target_md5=MD5,
                warnings=PatcherWarningsSchema(),
            )

    def test_accepts_dict_inputs(self):
        obj = ValidateExistsResponseSchema(
            target_file="f.bin",
            target_md5=MD5,
            warnings={},
            summary=_make_existence_summary(),
        )
        assert isinstance(obj.warnings, PatcherWarningsSchema)
        assert isinstance(obj.summary, ExistenceSummarySchema)


# ===========================================================================
# patcher.py — PatchedFailureSchema
# ===========================================================================


class TestPatchedFailureSchema:
    def test_valid_instantiation(self):
        obj = PatchedFailureSchema(
            index=3, offset="0x5678", size=2, reason="mb not found"
        )
        assert obj.index == 3
        assert obj.offset == "0x5678"
        assert obj.size == 2
        assert obj.reason == "mb not found"

    def test_missing_index_raises(self):
        with pytest.raises(ValidationError):
            PatchedFailureSchema(offset="0x5678", size=2, reason="mb not found")

    def test_missing_offset_raises(self):
        with pytest.raises(ValidationError):
            PatchedFailureSchema(index=0, size=2, reason="mb not found")

    def test_missing_size_raises(self):
        with pytest.raises(ValidationError):
            PatchedFailureSchema(index=0, offset="0x5678", reason="mb not found")

    def test_missing_reason_raises(self):
        with pytest.raises(ValidationError):
            PatchedFailureSchema(index=0, offset="0x5678", size=2)

    def test_all_fields_correct_type(self):
        obj = PatchedFailureSchema(index=0, offset="0xABCD", size=4, reason="test")
        assert isinstance(obj.index, int)
        assert isinstance(obj.offset, str)
        assert isinstance(obj.size, int)
        assert isinstance(obj.reason, str)

    def test_field_description_exists(self):
        fields = PatchedFailureSchema.model_fields
        assert "offset" in fields


# ===========================================================================
# patcher.py — PatchedSummarySchema
# ===========================================================================


class TestPatchedSummarySchema:
    def test_valid_instantiation_all_confirmed(self):
        obj = PatchedSummarySchema(**_make_patched_summary())
        assert obj.total == 10
        assert obj.confirmed == 10
        assert obj.failed == 0
        assert obj.patch_confirmed is True

    def test_patch_confirmed_false(self):
        obj = PatchedSummarySchema(
            total=10, confirmed=7, failed=3, patch_confirmed=False
        )
        assert obj.patch_confirmed is False

    def test_patch_confirmed_required(self):
        with pytest.raises(ValidationError):
            PatchedSummarySchema(total=10, confirmed=10, failed=0)

    def test_missing_total_raises(self):
        with pytest.raises(ValidationError):
            PatchedSummarySchema(confirmed=10, failed=0, patch_confirmed=True)

    def test_missing_confirmed_raises(self):
        with pytest.raises(ValidationError):
            PatchedSummarySchema(total=10, failed=0, patch_confirmed=True)

    def test_missing_failed_raises(self):
        with pytest.raises(ValidationError):
            PatchedSummarySchema(total=10, confirmed=10, patch_confirmed=True)

    def test_all_fields_correct_type(self):
        obj = PatchedSummarySchema(**_make_patched_summary())
        assert isinstance(obj.total, int)
        assert isinstance(obj.confirmed, int)
        assert isinstance(obj.failed, int)
        assert isinstance(obj.patch_confirmed, bool)


# ===========================================================================
# patcher.py — ValidatePatchedResponseSchema
# ===========================================================================


class TestValidatePatchedResponseSchema:
    def _make(self, **overrides):
        base = {
            "patched_file": "patched.bin",
            "patched_md5": MD5,
            "warnings": PatcherWarningsSchema(),
            "summary": PatchedSummarySchema(**_make_patched_summary()),
        }
        base.update(overrides)
        return ValidatePatchedResponseSchema(**base)

    def test_valid_instantiation(self):
        obj = self._make()
        assert obj.patched_file == "patched.bin"
        assert obj.patched_md5 == MD5
        assert obj.failures == []

    def test_failures_default_empty_list(self):
        obj = self._make()
        assert obj.failures == []

    def test_with_failures(self):
        failures = [
            PatchedFailureSchema(index=0, offset="0x100", size=4, reason="not found")
        ]
        obj = self._make(failures=failures)
        assert len(obj.failures) == 1
        assert obj.failures[0].reason == "not found"

    def test_missing_patched_file_raises(self):
        with pytest.raises(ValidationError):
            ValidatePatchedResponseSchema(
                patched_md5=MD5,
                warnings=PatcherWarningsSchema(),
                summary=PatchedSummarySchema(**_make_patched_summary()),
            )

    def test_missing_patched_md5_raises(self):
        with pytest.raises(ValidationError):
            ValidatePatchedResponseSchema(
                patched_file="patched.bin",
                warnings=PatcherWarningsSchema(),
                summary=PatchedSummarySchema(**_make_patched_summary()),
            )

    def test_missing_warnings_raises(self):
        with pytest.raises(ValidationError):
            ValidatePatchedResponseSchema(
                patched_file="patched.bin",
                patched_md5=MD5,
                summary=PatchedSummarySchema(**_make_patched_summary()),
            )

    def test_missing_summary_raises(self):
        with pytest.raises(ValidationError):
            ValidatePatchedResponseSchema(
                patched_file="patched.bin",
                patched_md5=MD5,
                warnings=PatcherWarningsSchema(),
            )

    def test_accepts_dict_inputs(self):
        obj = ValidatePatchedResponseSchema(
            patched_file="p.bin",
            patched_md5=MD5,
            warnings={},
            summary=_make_patched_summary(),
        )
        assert isinstance(obj.warnings, PatcherWarningsSchema)
        assert isinstance(obj.summary, PatchedSummarySchema)

    def test_summary_patch_confirmed_accessible(self):
        obj = self._make()
        assert obj.summary.patch_confirmed is True


# ===========================================================================
# patcher.py — PatchFailedInstructionSchema
# ===========================================================================


class TestPatchFailedInstructionSchema:
    def test_valid_instantiation(self):
        obj = PatchFailedInstructionSchema(
            index=0, offset="0xDEAD", message="context anchor not found"
        )
        assert obj.index == 0
        assert obj.offset == "0xDEAD"
        assert obj.message == "context anchor not found"

    def test_missing_index_raises(self):
        with pytest.raises(ValidationError):
            PatchFailedInstructionSchema(offset="0xDEAD", message="failed")

    def test_missing_offset_raises(self):
        with pytest.raises(ValidationError):
            PatchFailedInstructionSchema(index=0, message="failed")

    def test_missing_message_raises(self):
        with pytest.raises(ValidationError):
            PatchFailedInstructionSchema(index=0, offset="0xDEAD")

    def test_all_fields_correct_type(self):
        obj = PatchFailedInstructionSchema(index=5, offset="0x0", message="err")
        assert isinstance(obj.index, int)
        assert isinstance(obj.offset, str)
        assert isinstance(obj.message, str)

    def test_field_description_exists(self):
        fields = PatchFailedInstructionSchema.model_fields
        assert "offset" in fields


# ===========================================================================
# patcher.py — PatchSummarySchema
# ===========================================================================


class TestPatchSummarySchema:
    def test_valid_instantiation_all_applied(self):
        obj = PatchSummarySchema(**_make_patch_summary())
        assert obj.total == 10
        assert obj.applied == 10
        assert obj.failed == 0
        assert obj.shifted == 0
        assert obj.patch_applied is True
        assert obj.patched_md5 == MD5

    def test_patched_md5_default_none(self):
        obj = PatchSummarySchema(
            total=10, applied=0, failed=10, shifted=0, patch_applied=False
        )
        assert obj.patched_md5 is None

    def test_patched_md5_optional_field_explicitly_none(self):
        obj = PatchSummarySchema(
            total=10,
            applied=10,
            failed=0,
            shifted=0,
            patch_applied=True,
            patched_md5=None,
        )
        assert obj.patched_md5 is None

    def test_patch_applied_required(self):
        with pytest.raises(ValidationError):
            PatchSummarySchema(total=10, applied=10, failed=0, shifted=0)

    def test_missing_total_raises(self):
        with pytest.raises(ValidationError):
            PatchSummarySchema(applied=10, failed=0, shifted=0, patch_applied=True)

    def test_missing_applied_raises(self):
        with pytest.raises(ValidationError):
            PatchSummarySchema(total=10, failed=0, shifted=0, patch_applied=True)

    def test_missing_failed_raises(self):
        with pytest.raises(ValidationError):
            PatchSummarySchema(total=10, applied=10, shifted=0, patch_applied=True)

    def test_missing_shifted_raises(self):
        with pytest.raises(ValidationError):
            PatchSummarySchema(total=10, applied=10, failed=0, patch_applied=True)

    def test_shifted_with_some_applied_at_wrong_offset(self):
        obj = PatchSummarySchema(
            total=10,
            applied=10,
            failed=0,
            shifted=3,
            patch_applied=True,
            patched_md5=MD5,
        )
        assert obj.shifted == 3

    def test_all_fields_correct_type(self):
        obj = PatchSummarySchema(**_make_patch_summary())
        assert isinstance(obj.total, int)
        assert isinstance(obj.applied, int)
        assert isinstance(obj.failed, int)
        assert isinstance(obj.shifted, int)
        assert isinstance(obj.patch_applied, bool)

    def test_patched_md5_field_description_exists(self):
        fields = PatchSummarySchema.model_fields
        assert "patched_md5" in fields


# ===========================================================================
# patcher.py — PatchApplyResponseSchema
# ===========================================================================


class TestPatchApplyResponseSchema:
    def _make(self, **overrides):
        base = {
            "target_file": "target.bin",
            "target_md5": MD5,
            "warnings": PatcherWarningsSchema(),
            "summary": PatchSummarySchema(**_make_patch_summary()),
        }
        base.update(overrides)
        return PatchApplyResponseSchema(**base)

    def test_valid_instantiation(self):
        obj = self._make()
        assert obj.target_file == "target.bin"
        assert obj.target_md5 == MD5
        assert obj.failures == []

    def test_failures_default_empty_list(self):
        obj = self._make()
        assert obj.failures == []

    def test_with_failures(self):
        failures = [
            PatchFailedInstructionSchema(
                index=0, offset="0x100", message="anchor not found"
            )
        ]
        obj = self._make(failures=failures)
        assert len(obj.failures) == 1
        assert obj.failures[0].message == "anchor not found"

    def test_missing_target_file_raises(self):
        with pytest.raises(ValidationError):
            PatchApplyResponseSchema(
                target_md5=MD5,
                warnings=PatcherWarningsSchema(),
                summary=PatchSummarySchema(**_make_patch_summary()),
            )

    def test_missing_target_md5_raises(self):
        with pytest.raises(ValidationError):
            PatchApplyResponseSchema(
                target_file="target.bin",
                warnings=PatcherWarningsSchema(),
                summary=PatchSummarySchema(**_make_patch_summary()),
            )

    def test_missing_warnings_raises(self):
        with pytest.raises(ValidationError):
            PatchApplyResponseSchema(
                target_file="target.bin",
                target_md5=MD5,
                summary=PatchSummarySchema(**_make_patch_summary()),
            )

    def test_missing_summary_raises(self):
        with pytest.raises(ValidationError):
            PatchApplyResponseSchema(
                target_file="target.bin",
                target_md5=MD5,
                warnings=PatcherWarningsSchema(),
            )

    def test_accepts_dict_for_warnings(self):
        obj = PatchApplyResponseSchema(
            target_file="t.bin",
            target_md5=MD5,
            warnings={},
            summary=_make_patch_summary(),
        )
        assert isinstance(obj.warnings, PatcherWarningsSchema)

    def test_accepts_dict_for_summary(self):
        obj = PatchApplyResponseSchema(
            target_file="t.bin",
            target_md5=MD5,
            warnings=PatcherWarningsSchema(),
            summary=_make_patch_summary(),
        )
        assert isinstance(obj.summary, PatchSummarySchema)

    def test_summary_patch_applied_accessible(self):
        obj = self._make()
        assert obj.summary.patch_applied is True

    def test_summary_patched_md5_accessible(self):
        obj = self._make()
        assert obj.summary.patched_md5 == MD5

    def test_warnings_no_mismatch_by_default(self):
        obj = self._make()
        assert obj.warnings.size_mismatch is False
        assert obj.warnings.match_key_mismatch is False

    def test_with_size_mismatch_warning(self):
        warnings = PatcherWarningsSchema(
            size_mismatch=True, size_mismatch_detail="Size mismatch detected."
        )
        obj = self._make(warnings=warnings)
        assert obj.warnings.size_mismatch is True
        assert obj.warnings.size_mismatch_detail == "Size mismatch detected."

    def test_multiple_failures(self):
        failures = [
            PatchFailedInstructionSchema(
                index=i, offset=f"0x{i:04X}", message=f"err {i}"
            )
            for i in range(5)
        ]
        obj = self._make(failures=failures)
        assert len(obj.failures) == 5
        assert obj.failures[4].index == 4
