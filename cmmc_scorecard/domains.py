"""CMMC 2.0 Level 2 domain and practice catalog.

CMMC 2.0 Level 2 maps 1:1 to the 110 security requirements in NIST SP 800-171
Rev. 2, organized into 14 families ("domains"). This module is the single source
of truth for the catalog and the helpers used to normalize the many control-id
formats found in scanner output into canonical CMMC practice identifiers
(e.g. ``AC.L2-3.1.1``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

# Domain code -> human-readable name.
DOMAIN_NAMES: dict[str, str] = {
    "AC": "Access Control",
    "AT": "Awareness and Training",
    "AU": "Audit and Accountability",
    "CM": "Configuration Management",
    "IA": "Identification and Authentication",
    "IR": "Incident Response",
    "MA": "Maintenance",
    "MP": "Media Protection",
    "PS": "Personnel Security",
    "PE": "Physical Protection",
    "RA": "Risk Assessment",
    "CA": "Security Assessment",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
}

# Order used for display / radar chart axes.
DOMAIN_ORDER: list[str] = [
    "AC", "AU", "CM", "IA", "IR", "MA", "MP",
    "PE", "PS", "RA", "CA", "SC", "SI", "AT",
]

# Maps the NIST 800-171 numbering prefix (3.<family>) to a domain code.
_PREFIX_TO_DOMAIN: dict[str, str] = {
    "3.1": "AC",
    "3.2": "AT",
    "3.3": "AU",
    "3.4": "CM",
    "3.5": "IA",
    "3.6": "IR",
    "3.7": "MA",
    "3.8": "MP",
    "3.9": "PS",
    "3.10": "PE",
    "3.11": "RA",
    "3.12": "CA",
    "3.13": "SC",
    "3.14": "SI",
}

# (nist_id, short description) grouped per domain. 110 practices total.
_PRACTICE_DATA: dict[str, list[tuple[str, str]]] = {
    "AC": [
        ("3.1.1", "Limit system access to authorized users, processes, and devices."),
        ("3.1.2", "Limit system access to the transactions and functions authorized users may execute."),
        ("3.1.3", "Control the flow of CUI in accordance with approved authorizations."),
        ("3.1.4", "Separate the duties of individuals to reduce risk of malevolent activity."),
        ("3.1.5", "Employ the principle of least privilege, including for privileged accounts."),
        ("3.1.6", "Use non-privileged accounts or roles when accessing nonsecurity functions."),
        ("3.1.7", "Prevent non-privileged users from executing privileged functions; audit such execution."),
        ("3.1.8", "Limit unsuccessful logon attempts."),
        ("3.1.9", "Provide privacy and security notices consistent with CUI rules."),
        ("3.1.10", "Use session lock with pattern-hiding displays after inactivity."),
        ("3.1.11", "Terminate a user session automatically after a defined condition."),
        ("3.1.12", "Monitor and control remote access sessions."),
        ("3.1.13", "Employ cryptographic mechanisms to protect remote access sessions."),
        ("3.1.14", "Route remote access via managed access control points."),
        ("3.1.15", "Authorize remote execution of privileged commands and access to security-relevant info."),
        ("3.1.16", "Authorize wireless access prior to allowing such connections."),
        ("3.1.17", "Protect wireless access using authentication and encryption."),
        ("3.1.18", "Control connection of mobile devices."),
        ("3.1.19", "Encrypt CUI on mobile devices and mobile computing platforms."),
        ("3.1.20", "Verify and control/limit connections to and use of external systems."),
        ("3.1.21", "Limit use of portable storage devices on external systems."),
        ("3.1.22", "Control CUI posted or processed on publicly accessible systems."),
    ],
    "AT": [
        ("3.2.1", "Ensure managers, administrators, and users are aware of security risks."),
        ("3.2.2", "Ensure personnel are trained to carry out assigned security duties."),
        ("3.2.3", "Provide security awareness training on insider threat indicators."),
    ],
    "AU": [
        ("3.3.1", "Create and retain system audit logs for monitoring and investigation."),
        ("3.3.2", "Ensure actions of individual users can be uniquely traced (accountability)."),
        ("3.3.3", "Review and update logged events."),
        ("3.3.4", "Alert in the event of an audit logging process failure."),
        ("3.3.5", "Correlate audit record review, analysis, and reporting for investigations."),
        ("3.3.6", "Provide audit record reduction and report generation."),
        ("3.3.7", "Synchronize internal system clocks with an authoritative time source."),
        ("3.3.8", "Protect audit information and tools from unauthorized access/modification/deletion."),
        ("3.3.9", "Limit management of audit logging functionality to a subset of privileged users."),
    ],
    "CM": [
        ("3.4.1", "Establish and maintain baseline configurations and inventories."),
        ("3.4.2", "Establish and enforce security configuration settings for IT products."),
        ("3.4.3", "Track, review, approve/disapprove, and log changes to systems."),
        ("3.4.4", "Analyze the security impact of changes prior to implementation."),
        ("3.4.5", "Define, document, and enforce access restrictions for changes."),
        ("3.4.6", "Employ least functionality by providing only essential capabilities."),
        ("3.4.7", "Restrict or disable nonessential programs, ports, protocols, and services."),
        ("3.4.8", "Apply deny-by-exception or allow-by-exception software execution policy."),
        ("3.4.9", "Control and monitor user-installed software."),
    ],
    "IA": [
        ("3.5.1", "Identify system users, processes, and devices."),
        ("3.5.2", "Authenticate identities of users, processes, or devices before granting access."),
        ("3.5.3", "Use multifactor authentication for privileged and network account access."),
        ("3.5.4", "Employ replay-resistant authentication mechanisms for network access."),
        ("3.5.5", "Prevent reuse of identifiers for a defined period."),
        ("3.5.6", "Disable identifiers after a defined period of inactivity."),
        ("3.5.7", "Enforce minimum password complexity and change of characters."),
        ("3.5.8", "Prohibit password reuse for a specified number of generations."),
        ("3.5.9", "Allow temporary password use with immediate change to a permanent password."),
        ("3.5.10", "Store and transmit only cryptographically-protected passwords."),
        ("3.5.11", "Obscure feedback of authentication information."),
    ],
    "IR": [
        ("3.6.1", "Establish an operational incident-handling capability."),
        ("3.6.2", "Track, document, and report incidents to designated officials."),
        ("3.6.3", "Test the organizational incident response capability."),
    ],
    "MA": [
        ("3.7.1", "Perform maintenance on organizational systems."),
        ("3.7.2", "Provide controls on tools, techniques, and personnel used for maintenance."),
        ("3.7.3", "Sanitize equipment removed for off-site maintenance of any CUI."),
        ("3.7.4", "Check media with diagnostic/test programs for malicious code before use."),
        ("3.7.5", "Require MFA to establish nonlocal maintenance sessions."),
        ("3.7.6", "Supervise maintenance activities of personnel without access authorization."),
    ],
    "MP": [
        ("3.8.1", "Protect (physically control and securely store) system media with CUI."),
        ("3.8.2", "Limit access to CUI on system media to authorized users."),
        ("3.8.3", "Sanitize or destroy system media before disposal or reuse."),
        ("3.8.4", "Mark media with necessary CUI markings and distribution limitations."),
        ("3.8.5", "Control access to and maintain accountability for media during transport."),
        ("3.8.6", "Implement cryptographic mechanisms to protect CUI on digital media in transport."),
        ("3.8.7", "Control the use of removable media on system components."),
        ("3.8.8", "Prohibit use of portable storage devices with no identifiable owner."),
        ("3.8.9", "Protect the confidentiality of backup CUI at storage locations."),
    ],
    "PS": [
        ("3.9.1", "Screen individuals prior to authorizing access to systems with CUI."),
        ("3.9.2", "Protect systems containing CUI during and after personnel actions."),
    ],
    "PE": [
        ("3.10.1", "Limit physical access to systems, equipment, and operating environments."),
        ("3.10.2", "Protect and monitor the physical facility and support infrastructure."),
        ("3.10.3", "Escort visitors and monitor visitor activity."),
        ("3.10.4", "Maintain audit logs of physical access."),
        ("3.10.5", "Control and manage physical access devices."),
        ("3.10.6", "Enforce safeguarding measures for CUI at alternate work sites."),
    ],
    "RA": [
        ("3.11.1", "Periodically assess risk to operations, assets, and individuals."),
        ("3.11.2", "Scan for vulnerabilities in systems and applications periodically."),
        ("3.11.3", "Remediate vulnerabilities in accordance with risk assessments."),
    ],
    "CA": [
        ("3.12.1", "Periodically assess security controls for effectiveness."),
        ("3.12.2", "Develop and implement plans of action to correct deficiencies."),
        ("3.12.3", "Monitor security controls on an ongoing basis."),
        ("3.12.4", "Develop and periodically update system security plans."),
    ],
    "SC": [
        ("3.13.1", "Monitor, control, and protect communications at boundaries."),
        ("3.13.2", "Employ secure architectural designs and engineering principles."),
        ("3.13.3", "Separate user functionality from system management functionality."),
        ("3.13.4", "Prevent unauthorized information transfer via shared system resources."),
        ("3.13.5", "Implement subnetworks for publicly accessible system components."),
        ("3.13.6", "Deny network traffic by default and allow by exception."),
        ("3.13.7", "Prevent split tunneling for remote devices."),
        ("3.13.8", "Implement cryptographic mechanisms to protect CUI in transmission."),
        ("3.13.9", "Terminate network connections at end of session or after inactivity."),
        ("3.13.10", "Establish and manage cryptographic keys."),
        ("3.13.11", "Employ FIPS-validated cryptography to protect CUI confidentiality."),
        ("3.13.12", "Prohibit remote activation of collaborative computing devices."),
        ("3.13.13", "Control and monitor the use of mobile code."),
        ("3.13.14", "Control and monitor the use of VoIP technologies."),
        ("3.13.15", "Protect the authenticity of communications sessions."),
        ("3.13.16", "Protect the confidentiality of CUI at rest."),
    ],
    "SI": [
        ("3.14.1", "Identify, report, and correct system flaws in a timely manner."),
        ("3.14.2", "Provide protection from malicious code at designated locations."),
        ("3.14.3", "Monitor system security alerts and advisories and act in response."),
        ("3.14.4", "Update malicious code protection mechanisms when new releases are available."),
        ("3.14.5", "Perform periodic and real-time scans of files from external sources."),
        ("3.14.6", "Monitor systems and traffic to detect attacks and indicators of attack."),
        ("3.14.7", "Identify unauthorized use of organizational systems."),
    ],
}


@dataclass(frozen=True)
class Practice:
    """A single CMMC 2.0 Level 2 practice (NIST 800-171 requirement)."""

    practice_id: str  # canonical, e.g. "AC.L2-3.1.1"
    nist_id: str  # e.g. "3.1.1"
    domain: str  # e.g. "AC"
    description: str

    @property
    def domain_name(self) -> str:
        return DOMAIN_NAMES[self.domain]


def _build_catalog() -> dict[str, Practice]:
    catalog: dict[str, Practice] = {}
    for domain, practices in _PRACTICE_DATA.items():
        for nist_id, description in practices:
            practice_id = f"{domain}.L2-{nist_id}"
            catalog[practice_id] = Practice(
                practice_id=practice_id,
                nist_id=nist_id,
                domain=domain,
                description=description,
            )
    return catalog


# Canonical practice_id -> Practice.
CATALOG: dict[str, Practice] = _build_catalog()

# nist_id -> canonical practice_id, for fast normalization.
_NIST_TO_PRACTICE: dict[str, str] = {p.nist_id: p.practice_id for p in CATALOG.values()}

# Regex that finds a NIST 800-171 control number anywhere in a string.
_NIST_RE = re.compile(r"3\.\d{1,2}\.\d{1,2}")


@lru_cache(maxsize=2048)
def normalize_control_id(raw: str) -> str | None:
    """Normalize a raw control reference to a canonical CMMC practice id.

    Accepts the many shapes seen in scanner output, e.g.::

        "3.1.1"                  -> "AC.L2-3.1.1"
        "AC.L2-3.1.1"            -> "AC.L2-3.1.1"
        "NIST.800-171.r2 3.1.1"  -> "AC.L2-3.1.1"
        "AC-3.1.1"               -> "AC.L2-3.1.1"

    Returns ``None`` if no recognizable NIST 800-171 control number is present.
    """
    if not raw:
        return None
    raw = raw.strip()
    if raw in CATALOG:
        return raw
    match = _NIST_RE.search(raw)
    if not match:
        return None
    return _NIST_TO_PRACTICE.get(match.group(0))


def domain_of(practice_id: str) -> str | None:
    """Return the domain code for a canonical practice id, or ``None``."""
    practice = CATALOG.get(practice_id)
    return practice.domain if practice else None


def practices_for_domain(domain: str) -> list[Practice]:
    """Return all practices belonging to a domain, in numeric order."""
    return [p for p in CATALOG.values() if p.domain == domain]


def total_practice_count() -> int:
    return len(CATALOG)
