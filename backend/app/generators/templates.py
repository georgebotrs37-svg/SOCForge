import base64
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from random import Random


class AttackTemplate(StrEnum):
    PHISHING_MACRO = "phishing_macro"
    BRUTE_FORCE = "brute_force"
    RANSOMWARE_PRECURSOR = "ransomware_precursor"


@dataclass(frozen=True, slots=True)
class ResponseExpectation:
    action_type: str
    target: str


@dataclass(frozen=True, slots=True)
class AttackEvent:
    offset_seconds: int
    index_name: str
    source_type: str
    event_code: str
    host: str
    username: str
    src_ip: str | None
    dst_ip: str | None
    event_data: dict[str, object]
    alert_title: str | None = None
    alert_severity: str | None = None


@dataclass(slots=True)
class TemplateContext:
    rng: Random
    duration_seconds: int
    host: str
    secondary_host: str
    username: str
    workstation_ip: str
    attacker_ip: str
    external_ip: str
    malicious_domain: str
    current_offset: int = 0

    def next_offset(self, minimum_gap: int = 25, maximum_gap: int = 90) -> int:
        self.current_offset = min(
            self.current_offset + self.rng.randint(minimum_gap, maximum_gap),
            self.duration_seconds - 1,
        )
        return self.current_offset


@dataclass(frozen=True, slots=True)
class TemplateDefinition:
    title: str
    technique_ids: tuple[str, ...]
    expected_actions: tuple[ResponseExpectation, ...]
    build: Callable[[TemplateContext], list[AttackEvent]]


def build_phishing_macro(context: TemplateContext) -> list[AttackEvent]:
    rng = context.rng
    attachment = f"Q{rng.randint(1, 4)}-invoice.xlsm"
    command = f"Write-Output 'invoice-{rng.randint(1000, 9999)}'"
    encoded_payload = base64.b64encode(command.encode("utf-16le")).decode("ascii")
    return [
        AttackEvent(
            0,
            "email",
            "email_gateway",
            "message_received",
            context.host,
            context.username,
            context.attacker_ip,
            None,
            {
                "sender": f"billing@{context.malicious_domain}",
                "recipient": context.username,
                "subject": "Updated supplier invoice",
                "attachment": attachment,
                "gateway_action": "delivered",
            },
            "Suspicious attachment delivered",
            "medium",
        ),
        AttackEvent(
            context.next_offset(),
            "sysmon",
            "sysmon",
            "11",
            context.host,
            context.username,
            None,
            None,
            {
                "target_filename": f"C:\\Users\\{context.username}\\Downloads\\{attachment}",
                "image": "OUTLOOK.EXE",
            },
        ),
        AttackEvent(
            context.next_offset(20, 50),
            "sysmon",
            "sysmon",
            "1",
            context.host,
            context.username,
            None,
            None,
            {
                "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "parent_image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                "command_line": encoded_payload,
            },
            "Office spawned encoded PowerShell",
            "high",
        ),
        AttackEvent(
            context.next_offset(60, 180),
            "sysmon",
            "sysmon",
            "13",
            context.host,
            context.username,
            None,
            None,
            {
                "target_object": (
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDriveUpdate"
                ),
                "details": "C:\\ProgramData\\OneDriveUpdate.exe",
            },
            "Unusual Run key persistence",
            "high",
        ),
        AttackEvent(
            context.next_offset(60, 180),
            "edr",
            "edr",
            "credential_access",
            context.host,
            context.username,
            None,
            None,
            {
                "behavior": "credential_store_access",
                "target_process": "lsass.exe",
                "confidence": 0.94,
            },
            "Credential access behavior detected",
            "critical",
        ),
        AttackEvent(
            context.next_offset(45, 120),
            "windows",
            "windows_security",
            "4624",
            context.secondary_host,
            context.username,
            context.workstation_ip,
            None,
            {"logon_type": 3, "authentication_package": "NTLM"},
            "Unusual network logon to file server",
            "high",
        ),
        AttackEvent(
            context.next_offset(15, 60),
            "sysmon",
            "sysmon",
            "3",
            context.secondary_host,
            context.username,
            context.workstation_ip,
            context.external_ip,
            {"destination_port": 443, "protocol": "tcp", "initiated": True},
        ),
        AttackEvent(
            context.next_offset(10, 45),
            "proxy",
            "proxy",
            "http_transaction",
            context.secondary_host,
            context.username,
            context.workstation_ip,
            context.external_ip,
            {
                "url": f"https://{context.malicious_domain}/upload",
                "method": "POST",
                "bytes_out": rng.randint(180_000, 640_000),
                "action": "allowed",
            },
            "Unusual outbound data transfer",
            "critical",
        ),
    ]


def build_brute_force(context: TemplateContext) -> list[AttackEvent]:
    events: list[AttackEvent] = []
    for attempt in range(1, 7):
        events.append(
            AttackEvent(
                context.next_offset(4, 12),
                "windows",
                "windows_security",
                "4625",
                context.host,
                context.username,
                context.attacker_ip,
                None,
                {
                    "status": "0xC000006D",
                    "sub_status": "0xC000006A",
                    "logon_type": 3,
                    "attempt": attempt,
                },
                "Repeated failed network logons" if attempt == 1 else None,
                "medium" if attempt == 1 else None,
            )
        )
    events.extend(
        [
            AttackEvent(
                context.next_offset(8, 20),
                "windows",
                "windows_security",
                "4624",
                context.host,
                context.username,
                context.attacker_ip,
                None,
                {"logon_type": 10, "authentication_package": "NTLM"},
                "Successful logon after repeated failures",
                "high",
            ),
            AttackEvent(
                context.next_offset(10, 30),
                "windows",
                "windows_security",
                "4672",
                context.host,
                context.username,
                context.attacker_ip,
                None,
                {"privileges": ["SeDebugPrivilege", "SeImpersonatePrivilege"]},
                "Special privileges assigned after remote logon",
                "high",
            ),
            AttackEvent(
                context.next_offset(15, 45),
                "sysmon",
                "sysmon",
                "1",
                context.host,
                context.username,
                None,
                None,
                {
                    "image": "C:\\Windows\\System32\\cmd.exe",
                    "parent_image": "C:\\Windows\\System32\\services.exe",
                    "command_line": "cmd.exe /c whoami /groups",
                },
            ),
            AttackEvent(
                context.next_offset(10, 30),
                "edr",
                "edr",
                "identity_risk",
                context.host,
                context.username,
                context.attacker_ip,
                None,
                {"risk": "new_source_and_privilege_use", "confidence": 0.91},
                "Privileged access from new source",
                "critical",
            ),
        ]
    )
    return events


def build_ransomware_precursor(context: TemplateContext) -> list[AttackEvent]:
    rng = context.rng
    return [
        AttackEvent(
            context.next_offset(),
            "sysmon",
            "sysmon",
            "1",
            context.host,
            context.username,
            None,
            None,
            {
                "image": "C:\\Windows\\System32\\vssadmin.exe",
                "parent_image": "C:\\Windows\\System32\\cmd.exe",
                "command_line": "vssadmin.exe list shadows",
            },
            "Shadow-copy discovery before file activity",
            "medium",
        ),
        *[
            AttackEvent(
                context.next_offset(5, 18),
                "sysmon",
                "sysmon",
                "11",
                context.host,
                context.username,
                None,
                None,
                {
                    "target_filename": (
                        f"C:\\Users\\{context.username}\\Documents\\"
                        f"budget-{rng.randint(100, 999)}.locked"
                    ),
                    "image": "C:\\ProgramData\\svc-host.exe",
                },
                "Rapid suspicious file modifications" if index == 0 else None,
                "critical" if index == 0 else None,
            )
            for index in range(4)
        ],
        AttackEvent(
            context.next_offset(20, 60),
            "sysmon",
            "sysmon",
            "3",
            context.host,
            context.username,
            context.workstation_ip,
            context.external_ip,
            {"destination_port": 443, "protocol": "tcp", "initiated": True},
            "Unexpected external connection during file changes",
            "high",
        ),
        AttackEvent(
            context.next_offset(10, 30),
            "firewall",
            "firewall",
            "connection",
            context.host,
            context.username,
            context.workstation_ip,
            context.external_ip,
            {"destination_port": 443, "action": "allowed", "rule": "outbound-default"},
        ),
        AttackEvent(
            context.next_offset(10, 30),
            "edr",
            "edr",
            "ransomware_behavior",
            context.host,
            context.username,
            None,
            None,
            {
                "behavior": "mass_file_rename",
                "files_changed": rng.randint(40, 85),
                "canary_triggered": True,
            },
            "Ransomware behavior blocked by endpoint control",
            "critical",
        ),
    ]


TEMPLATE_DEFINITIONS: dict[AttackTemplate, TemplateDefinition] = {
    AttackTemplate.PHISHING_MACRO: TemplateDefinition(
        title="Phishing, persistence, credential access, and exfiltration",
        technique_ids=("T1566.001", "T1204.002", "T1059.001", "T1547.001", "T1003.001", "T1041"),
        expected_actions=(
            ResponseExpectation("isolate_host", "{host}"),
            ResponseExpectation("disable_account", "{username}"),
            ResponseExpectation("block_ip", "{external_ip}"),
        ),
        build=build_phishing_macro,
    ),
    AttackTemplate.BRUTE_FORCE: TemplateDefinition(
        title="Brute force followed by successful privileged login",
        technique_ids=("T1110.001", "T1078", "T1068"),
        expected_actions=(
            ResponseExpectation("disable_account", "{username}"),
            ResponseExpectation("block_ip", "{attacker_ip}"),
            ResponseExpectation("reset_password", "{username}"),
        ),
        build=build_brute_force,
    ),
    AttackTemplate.RANSOMWARE_PRECURSOR: TemplateDefinition(
        title="Ransomware precursor activity",
        technique_ids=("T1490", "T1486", "T1071.001"),
        expected_actions=(
            ResponseExpectation("isolate_host", "{host}"),
            ResponseExpectation("block_ip", "{external_ip}"),
        ),
        build=build_ransomware_precursor,
    ),
}
