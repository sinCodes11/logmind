"""MITRE ATT&CK data loader and cache."""

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Technique:
    """MITRE ATT&CK Technique."""

    id: str
    name: str
    description: str
    tactics: list[str] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)
    detection: str = ""
    url: str = ""
    subtechniques: list["Technique"] = field(default_factory=list)


@dataclass
class Tactic:
    """MITRE ATT&CK Tactic."""

    id: str
    name: str
    shortname: str
    description: str
    url: str = ""


class ATTACKData:
    """
    MITRE ATT&CK data loader and cache.

    Loads ATT&CK data from STIX JSON format or uses embedded data.
    """

    EMBEDDED_TACTICS: dict[str, dict] = {
        "TA0001": {"name": "Initial Access", "shortname": "initial-access"},
        "TA0002": {"name": "Execution", "shortname": "execution"},
        "TA0003": {"name": "Persistence", "shortname": "persistence"},
        "TA0004": {"name": "Privilege Escalation", "shortname": "privilege-escalation"},
        "TA0005": {"name": "Defense Evasion", "shortname": "defense-evasion"},
        "TA0006": {"name": "Credential Access", "shortname": "credential-access"},
        "TA0007": {"name": "Discovery", "shortname": "discovery"},
        "TA0008": {"name": "Lateral Movement", "shortname": "lateral-movement"},
        "TA0009": {"name": "Collection", "shortname": "collection"},
        "TA0010": {"name": "Exfiltration", "shortname": "exfiltration"},
        "TA0011": {"name": "Command and Control", "shortname": "command-and-control"},
        "TA0040": {"name": "Impact", "shortname": "impact"},
        "TA0042": {"name": "Resource Development", "shortname": "resource-development"},
        "TA0043": {"name": "Reconnaissance", "shortname": "reconnaissance"},
    }

    EMBEDDED_TECHNIQUES: dict[str, dict] = {
        "T1110": {
            "name": "Brute Force",
            "tactics": ["Credential Access"],
            "description": "Adversaries may use brute force techniques to gain access to accounts.",
        },
        "T1110.001": {
            "name": "Password Guessing",
            "tactics": ["Credential Access"],
            "description": "Adversaries may guess passwords to attempt access to accounts.",
        },
        "T1110.003": {
            "name": "Password Spraying",
            "tactics": ["Credential Access"],
            "description": "Adversaries may use a single password against many accounts.",
        },
        "T1548": {
            "name": "Abuse Elevation Control Mechanism",
            "tactics": ["Privilege Escalation", "Defense Evasion"],
            "description": "Adversaries may circumvent mechanisms designed to control elevated privileges.",
        },
        "T1548.003": {
            "name": "Sudo and Sudo Caching",
            "tactics": ["Privilege Escalation", "Defense Evasion"],
            "description": "Adversaries may perform sudo caching and/or use the sudoers file.",
        },
        "T1505": {
            "name": "Server Software Component",
            "tactics": ["Persistence"],
            "description": "Adversaries may abuse legitimate server software components.",
        },
        "T1505.003": {
            "name": "Web Shell",
            "tactics": ["Persistence"],
            "description": "Adversaries may backdoor web servers with web shells.",
        },
        "T1190": {
            "name": "Exploit Public-Facing Application",
            "tactics": ["Initial Access"],
            "description": "Adversaries may exploit weaknesses in internet-facing applications.",
        },
        "T1189": {
            "name": "Drive-by Compromise",
            "tactics": ["Initial Access"],
            "description": "Adversaries may gain access through a user visiting a website.",
        },
        "T1083": {
            "name": "File and Directory Discovery",
            "tactics": ["Discovery"],
            "description": "Adversaries may enumerate files and directories.",
        },
        "T1046": {
            "name": "Network Service Discovery",
            "tactics": ["Discovery"],
            "description": "Adversaries may attempt to get a listing of services running on hosts.",
        },
        "T1564": {
            "name": "Hide Artifacts",
            "tactics": ["Defense Evasion"],
            "description": "Adversaries may attempt to hide artifacts associated with their behaviors.",
        },
    }

    def __init__(self, data_path: str | None = None) -> None:
        """
        Initialize ATT&CK data loader.

        Args:
            data_path: Optional path to STIX JSON file
        """
        self._data_path = Path(data_path) if data_path else None
        self._tactics: dict[str, Tactic] = {}
        self._techniques: dict[str, Technique] = {}
        self._loaded = False

    def load(self) -> bool:
        """
        Load ATT&CK data from file or use embedded data.

        Returns:
            True if loaded successfully
        """
        if self._loaded:
            return True

        if self._data_path and self._data_path.exists():
            try:
                self._load_from_stix()
                self._loaded = True
                return True
            except Exception:
                pass

        self._load_embedded()
        self._loaded = True
        return True

    def _load_from_stix(self) -> None:
        """Load ATT&CK data from STIX JSON file."""
        with open(self._data_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        for obj in data.get("objects", []):
            obj_type = obj.get("type", "")

            if obj_type == "x-mitre-tactic":
                external_refs = obj.get("external_references", [])
                tactic_id = ""
                url = ""
                for ref in external_refs:
                    if ref.get("source_name") == "mitre-attack":
                        tactic_id = ref.get("external_id", "")
                        url = ref.get("url", "")
                        break

                if tactic_id:
                    self._tactics[tactic_id] = Tactic(
                        id=tactic_id,
                        name=obj.get("name", ""),
                        shortname=obj.get("x_mitre_shortname", ""),
                        description=obj.get("description", ""),
                        url=url,
                    )

            elif obj_type == "attack-pattern":
                external_refs = obj.get("external_references", [])
                tech_id = ""
                url = ""
                for ref in external_refs:
                    if ref.get("source_name") == "mitre-attack":
                        tech_id = ref.get("external_id", "")
                        url = ref.get("url", "")
                        break

                if tech_id:
                    kill_chain = obj.get("kill_chain_phases", [])
                    tactics = [
                        kc.get("phase_name", "").replace("-", " ").title()
                        for kc in kill_chain
                    ]

                    self._techniques[tech_id] = Technique(
                        id=tech_id,
                        name=obj.get("name", ""),
                        description=obj.get("description", ""),
                        tactics=tactics,
                        platforms=obj.get("x_mitre_platforms", []),
                        detection=obj.get("x_mitre_detection", ""),
                        url=url,
                    )

    def _load_embedded(self) -> None:
        """Load embedded ATT&CK data."""
        for tactic_id, info in self.EMBEDDED_TACTICS.items():
            self._tactics[tactic_id] = Tactic(
                id=tactic_id,
                name=info["name"],
                shortname=info["shortname"],
                description="",
                url=f"https://attack.mitre.org/tactics/{tactic_id}/",
            )

        for tech_id, info in self.EMBEDDED_TECHNIQUES.items():
            self._techniques[tech_id] = Technique(
                id=tech_id,
                name=info["name"],
                description=info.get("description", ""),
                tactics=info.get("tactics", []),
                url=f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/",
            )

    def get_technique(self, technique_id: str) -> Technique | None:
        """Get technique by ID."""
        self.load()
        technique_id = technique_id.upper()
        return self._techniques.get(technique_id)

    def get_tactic(self, tactic_id: str) -> Tactic | None:
        """Get tactic by ID."""
        self.load()
        return self._tactics.get(tactic_id)

    def get_tactic_by_name(self, name: str) -> Tactic | None:
        """Get tactic by name."""
        self.load()
        name_lower = name.lower().replace("_", " ").replace("-", " ")
        for tactic in self._tactics.values():
            if tactic.name.lower() == name_lower:
                return tactic
            if tactic.shortname.lower().replace("-", " ") == name_lower:
                return tactic
        return None

    def search_techniques(self, query: str) -> list[Technique]:
        """Search techniques by name or description."""
        self.load()
        query_lower = query.lower()
        results = []
        for tech in self._techniques.values():
            if query_lower in tech.name.lower() or query_lower in tech.description.lower():
                results.append(tech)
        return results

    @property
    def technique_count(self) -> int:
        """Get number of loaded techniques."""
        self.load()
        return len(self._techniques)

    @property
    def tactic_count(self) -> int:
        """Get number of loaded tactics."""
        self.load()
        return len(self._tactics)
