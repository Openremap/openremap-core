"""
Base class for all ECU manufacturer extractors.

Every manufacturer (Bosch, Siemens, Delphi, etc.) must implement this interface.
The analyzer uses the registry to auto-detect the manufacturer and delegate
all extraction logic to the correct implementation.
"""

import re
from abc import ABC, abstractmethod
from typing import Dict, List, Optional


class BaseManufacturerExtractor(ABC):
    """
    Abstract base class for ECU manufacturer-specific binary extractors.

    Subclass this for each manufacturer and implement:
      - name         : Human-readable manufacturer name
      - can_handle() : Detect if a binary belongs to this manufacturer
      - extract()    : Extract all identifying information from the binary

    Opt-in fallback key
    -------------------
    Some ECU architectures do not store a software_version in the binary at
    all (e.g. Bosch LH-Jetronic Format A).  For those families the base
    build_match_key() would always return None, making DB lookup impossible.

    Set the class attribute ``match_key_fallback_field`` to the name of the
    extraction dict field that should be used as the version component of the
    match key *only when software_version is absent*.

    Example — LH-Jetronic Format A uses calibration_id as the sole identifier:

        match_key_fallback_field = "calibration_id"

    The default value is None, which preserves the original behaviour for
    every extractor that does not explicitly opt in: if software_version is
    absent the match key remains None.

    Rules
    -----
    - software_version always wins when present — the fallback is never
      consulted if sw is non-empty.
    - The fallback is only used when the value it names is non-empty.
    - All other extractors are completely unaffected.

    To add the fallback to a future extractor (any manufacturer):
        1. Set  match_key_fallback_field = "<field_name>"  in the subclass.
        2. Make sure extract() populates that field in the returned dict.
        3. Pass the field's value to build_match_key() via the
           ``fallback_value`` keyword argument (see BoschLHExtractor for the
           reference implementation).
    """

    # Class-level opt-in.  None = disabled (default for all existing extractors).
    match_key_fallback_field: Optional[str] = None

    # -----------------------------------------------------------------------
    # Identity
    # -----------------------------------------------------------------------

    @property
    @abstractmethod
    def name(self) -> str:
        """
        Human-readable manufacturer name.
        e.g. "Bosch", "Siemens", "Delphi"
        """

    @property
    @abstractmethod
    def supported_families(self) -> List[str]:
        """
        List of ECU families this extractor handles.
        e.g. ["EDC17", "MEDC17", "MED17", "EDC16"]
        Used for documentation and family discovery.
        """

    # -----------------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------------

    @abstractmethod
    def can_handle(self, data: bytes) -> bool:
        """
        Return True if this binary belongs to this manufacturer.

        This method must be fast — it is called for every registered extractor
        on every uploaded binary. Avoid full-file scans here; use the first
        few KB only.

        Args:
            data: Raw bytes of the ECU binary file

        Returns:
            True if this extractor should handle the binary
        """

    # -----------------------------------------------------------------------
    # Extraction
    # -----------------------------------------------------------------------

    @abstractmethod
    def extract(self, data: bytes, filename: str) -> Dict:
        """
        Extract all identifying information from the binary.

        Must return a dict that is fully compatible with ECUIdentifiersSchema.
        All fields are optional except file_size, md5, and sha256_first_64kb
        which must always be present.

        Required fields:
            file_size         : int
            md5               : str
            sha256_first_64kb : str

        Optional fields (return None if not found):
            match_key         : str   — compound lookup key
            manufacturer      : str   — e.g. "Bosch"
            ecu_family        : str   — e.g. "MEDC17"
            ecu_variant       : str   — e.g. "EDC17C66"
            software_version  : str   — primary matching key
            hardware_number   : str   — Bosch/OEM hardware part number
            calibration_id    : str   — calibration sub-version
            calibration_version: str  — e.g. "CV182500"
            sw_base_version   : str   — e.g. "SB_V18.00.02/1793"
            serial_number     : str   — production serial
            dataset_number    : str   — dataset reference number
            oem_part_number   : str   — vehicle manufacturer part number
            raw_strings       : list  — printable ASCII strings from header

        Args:
            data:     Raw bytes of the ECU binary file
            filename: Original filename — used for display only

        Returns:
            Dict compatible with ECUIdentifiersSchema
        """

    # -----------------------------------------------------------------------
    # Match key builder — shared utility, can be overridden
    # -----------------------------------------------------------------------

    def build_match_key(
        self,
        ecu_family: Optional[str] = None,
        ecu_variant: Optional[str] = None,
        software_version: Optional[str] = None,
        fallback_value: Optional[str] = None,
    ) -> Optional[str]:
        """
        Build a normalised compound key used for recipe matching.

        Uses the most specific available identifier:
          - ecu_variant takes priority over ecu_family
          - software_version is the primary version component — always used
            when present.
          - hardware_number is intentionally excluded: it is not always present
            in the binary, so including it would produce different keys for the
            same software revision depending on the source file.

        Opt-in fallback
        ---------------
        When the subclass declares ``match_key_fallback_field`` (non-None) AND
        software_version is absent, ``fallback_value`` is used as the version
        component instead.  This is the only mechanism by which an extractor
        can produce a valid match key without a software_version.

        Callers must pass the resolved fallback value explicitly via the
        ``fallback_value`` keyword argument — the base class never reaches into
        the extraction dict itself.

        Format:
            "EDC17C66::1037541778126241V0"   ← normal (sw present)
            "MEDC17::1037541778126241V0"      ← normal (sw present)
            "ME7.5::1037368072"               ← normal (sw present)
            "LH-JETRONIC::1012621LH241RP"    ← fallback (sw absent, cal_id used)

        Returns:
            Normalised match key string, or None if no usable version component
            is available.
        """
        version_part = software_version

        # Fallback: only when this extractor opts in AND sw is genuinely absent.
        if not version_part and self.match_key_fallback_field and fallback_value:
            version_part = fallback_value

        if not version_part:
            return None

        family_part = (ecu_variant or ecu_family or "UNKNOWN").upper()

        # Collapse any internal whitespace so cal_id values like "9146179  P01"
        # produce a clean key "9146179 P01" rather than embedding double spaces.
        version_normalised = " ".join(version_part.upper().split())

        return "::".join([family_part, version_normalised])

    # -----------------------------------------------------------------------
    # Shared utilities — pattern engine
    # -----------------------------------------------------------------------

    def _run_all_patterns(
        self,
        data: bytes,
        patterns: Dict[str, bytes],
        pattern_regions: Dict[str, str],
        search_regions: Dict[str, slice],
    ) -> Dict[str, List[str]]:
        """
        Run all patterns against their assigned search regions.

        Returns a dict of pattern_name -> list of matched strings.
        Only patterns that produce at least one hit are included.

        Args:
            data:            Full binary data
            patterns:        Dict of name -> compiled regex pattern bytes
            pattern_regions: Dict of name -> region key
            search_regions:  Dict of region key -> slice
        """
        raw_hits: Dict[str, List[str]] = {}
        for name, pattern in patterns.items():
            region_key = pattern_regions.get(name, "full")
            region = search_regions[region_key]
            hits = self._search(data, pattern, region)
            if hits:
                raw_hits[name] = hits
        return raw_hits

    def _search(
        self,
        data: bytes,
        pattern: bytes,
        region: slice,
        max_results: int = 5,
    ) -> List[str]:
        """
        Search for a regex pattern in a bounded region of the binary.

        Stores the full match (group 0) as a decoded ASCII string.
        For patterns with capturing groups the full match contains all
        groups concatenated — resolvers split them as needed.

        Filters out empty strings and deduplicates.
        Returns up to max_results decoded ASCII strings.

        Args:
            data:        Full binary data
            pattern:     Raw bytes regex pattern
            region:      Slice of the binary to search
            max_results: Maximum number of results to return
        """
        results: List[str] = []
        try:
            for match in re.finditer(pattern, data[region]):
                try:
                    value = match.group(0).decode("ascii", errors="ignore").strip()
                    if value and value not in results:
                        results.append(value)
                        if len(results) >= max_results:
                            break
                except Exception:
                    pass
        except Exception:
            pass
        return results

    def _first_hit(self, raw_hits: Dict[str, List[str]], key: str) -> Optional[str]:
        """Return the first hit for a pattern key, or None."""
        hits = raw_hits.get(key)
        return hits[0] if hits else None

    # -----------------------------------------------------------------------
    # Shared utility — raw ASCII string extraction
    # -----------------------------------------------------------------------

    def extract_raw_strings(
        self,
        data: bytes,
        region: slice,
        min_length: int = 8,
        max_results: int = 20,
    ) -> List[str]:
        """
        Extract all printable ASCII strings of at least min_length characters
        from the given region of the binary.

        Used by all manufacturer extractors as a common utility.

        Args:
            data:        Full binary data
            region:      Slice of the binary to search
            min_length:  Minimum string length to include
            max_results: Maximum number of strings to return

        Returns:
            List of printable ASCII strings found in the region
        """
        results: List[str] = []
        current = ""

        for byte in data[region]:
            if 32 <= byte <= 126:
                current += chr(byte)
            else:
                stripped = current.strip()
                if len(stripped) >= min_length:
                    results.append(stripped)
                current = ""

        # Flush any remaining string
        stripped = current.strip()
        if len(stripped) >= min_length:
            results.append(stripped)

        return results[:max_results]

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} manufacturer={self.name!r} families={self.supported_families}>"
