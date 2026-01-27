"""Unit tests for MITRE ATT&CK integration."""

import pytest

from logmind.mitre.attack_data import ATTACKData
from logmind.mitre.mapper import ATTACKMapper


class TestATTACKData:
    """Tests for ATTACKData loader."""

    def setup_method(self):
        self.attack_data = ATTACKData()

    def test_load_embedded_data(self):
        """Test loading embedded ATT&CK data."""
        result = self.attack_data.load()
        assert result is True
        assert self.attack_data.technique_count > 0
        assert self.attack_data.tactic_count > 0

    def test_get_technique(self):
        """Test getting technique by ID."""
        self.attack_data.load()

        technique = self.attack_data.get_technique("T1110")
        assert technique is not None
        assert technique.name == "Brute Force"
        assert "Credential Access" in technique.tactics

    def test_get_subtechnique(self):
        """Test getting subtechnique."""
        self.attack_data.load()

        technique = self.attack_data.get_technique("T1110.001")
        assert technique is not None
        assert "Password" in technique.name

    def test_get_tactic(self):
        """Test getting tactic by ID."""
        self.attack_data.load()

        tactic = self.attack_data.get_tactic("TA0006")
        assert tactic is not None
        assert tactic.name == "Credential Access"

    def test_get_tactic_by_name(self):
        """Test getting tactic by name."""
        self.attack_data.load()

        tactic = self.attack_data.get_tactic_by_name("Initial Access")
        assert tactic is not None
        assert tactic.id == "TA0001"

        # Test with different formats
        tactic2 = self.attack_data.get_tactic_by_name("initial-access")
        assert tactic2 is not None

    def test_get_nonexistent_technique(self):
        """Test getting nonexistent technique returns None."""
        self.attack_data.load()

        technique = self.attack_data.get_technique("T9999")
        assert technique is None

    def test_search_techniques(self):
        """Test searching techniques."""
        self.attack_data.load()

        results = self.attack_data.search_techniques("password")
        assert len(results) > 0
        assert any("password" in t.name.lower() for t in results)


class TestATTACKMapper:
    """Tests for ATTACKMapper."""

    def setup_method(self):
        self.mapper = ATTACKMapper()

    def test_get_technique_details(self):
        """Test getting technique details."""
        info = self.mapper.get_technique_details("T1110")

        assert info is not None
        assert info.technique_id == "T1110"
        assert info.technique_name == "Brute Force"
        assert len(info.tactics) > 0
        assert "attack.mitre.org" in info.url

    def test_get_tactics_for_techniques(self):
        """Test getting tactics for techniques."""
        result = self.mapper.get_tactics_for_techniques(["T1110", "T1548"])

        assert "T1110" in result
        assert "T1548" in result
        assert "Credential Access" in result["T1110"]

    def test_generate_attack_narrative(self):
        """Test generating attack narrative."""
        techniques = [
            self.mapper.get_technique_details("T1110"),
            self.mapper.get_technique_details("T1548"),
        ]

        narrative = self.mapper.generate_attack_narrative(techniques)

        assert "Attack Progression" in narrative
        assert "T1110" in narrative
        assert "Brute Force" in narrative
