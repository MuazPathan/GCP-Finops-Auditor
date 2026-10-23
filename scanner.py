import os
import json
import logging
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List

from google.api_core.exceptions import GoogleAPICallError, Forbidden
from google.cloud import compute_v1
from google.cloud import storage

logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s", "level":"%(levelname)s", "message":"%(message)s"}',
)
logger = logging.getLogger("HygieneScanner")


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Finding:
    resource_id: str
    resource_type: str
    location: str
    severity: Severity
    title: str
    details: str
    monthly_waste_usd: float
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result["severity"] = self.severity.value
        return result


class CostEngine:
    DISK_RATES = {
        "pd-standard": 0.040,
        "pd-balanced": 0.100,
        "pd-ssd": 0.170,
        "pd-extreme": 0.125,
    }
    IDLE_STATIC_IP_MONTHLY = 7.30

    @classmethod
    def calculate_disk_mrc(cls, disk_type: str, size_gb: int, is_regional: bool = False) -> float:
        type_key = disk_type.split("/")[-1].lower()
        base_rate = cls.DISK_RATES.get(type_key, 0.040)
        multiplier = 2.0 if is_regional else 1.0
        return round(size_gb * base_rate * multiplier, 2)


class GCPHygieneScanner:
    def __init__(self, project_id: str):
        self.project_id = project_id
        self.findings: List[Finding] = []
        self.disks_client = compute_v1.DisksClient()
        self.addresses_client = compute_v1.AddressesClient()
        self.instances_client = compute_v1.InstancesClient()
        self.storage_client = storage.Client(project=project_id)

    def run_all_scans(self) -> List[Finding]:
        logger.info(f"Initiating hygiene scan for project: {self.project_id}")
        self._scan_persistent_disks()
        self._scan_static_ips()
        self._scan_stopped_instances()
        self._scan_storage_buckets()
        return self.findings

    def _scan_persistent_disks(self) -> None:
        try:
            agg_list = self.disks_client.aggregated_list(project=self.project_id)
            for location_path, scoped_list in agg_list:
                if not scoped_list.disks:
                    continue
                for disk in scoped_list.disks:
                    if not disk.users:
                        is_regional = "regions" in location_path
                        location = location_path.replace("zones/", "").replace("regions/", "")
                        size_gb = disk.size_gb or 0
                        mrc = CostEngine.calculate_disk_mrc(disk.type_, size_gb, is_regional)
                        severity = (
                            Severity.HIGH if mrc >= 50.0
                            else (Severity.MEDIUM if mrc >= 10.0 else Severity.LOW)
                        )

                        self.findings.append(Finding(
                            resource_id=disk.name,
                            resource_type="Compute Disk (Regional)" if is_regional else "Compute Disk (Zonal)",
                            location=location,
                            severity=severity,
                            title="Unattached Persistent Disk",
                            details=f"Unattached {disk.type_.split('/')[-1]} disk ({size_gb} GB). Incurring unutilized storage costs.",
                            monthly_waste_usd=mrc,
                            recommendation="Snapshot and delete disk if no longer required, or attach to an active VM."
                        ))
        except Forbidden as e:
            logger.error(f"Permission denied scanning Compute Disks: {e.message}")
        except GoogleAPICallError as e:
            logger.error(f"API failure scanning Compute Disks: {e.message}")

    def _scan_static_ips(self) -> None:
        try:
            agg_list = self.addresses_client.aggregated_list(project=self.project_id)
            for location_path, scoped_list in agg_list:
                if not scoped_list.addresses:
                    continue
                for addr in scoped_list.addresses:
                    if addr.status == "RESERVED" and not addr.users:
                        location = location_path.replace("regions/", "").replace("global", "global")
                        self.findings.append(Finding(
                            resource_id=addr.name,
                            resource_type="External Static IP",
                            location=location,
                            severity=Severity.MEDIUM,
                            title="Unattached Static External IP",
                            details=f"IP address {addr.address} is reserved but unassigned.",
                            monthly_waste_usd=CostEngine.IDLE_STATIC_IP_MONTHLY,
                            recommendation="Release the static IP address back to Google Cloud."
                        ))
        except Forbidden as e:
            logger.error(f"Permission denied scanning Static Addresses: {e.message}")
        except GoogleAPICallError as e:
            logger.error(f"API failure scanning Static Addresses: {e.message}")

    def _scan_stopped_instances(self) -> None:
        try:
            agg_list = self.instances_client.aggregated_list(project=self.project_id)
            for location_path, scoped_list in agg_list:
                if not scoped_list.instances:
                    continue
                for instance in scoped_list.instances:
                    if instance.status == "TERMINATED":
                        zone = location_path.replace("zones/", "")
                        attached_disk_mrc = sum(
                            CostEngine.calculate_disk_mrc("pd-standard", d.disk_size_gb or 10)
                            for d in instance.disks
                        )
                        self.findings.append(Finding(
                            resource_id=instance.name,
                            resource_type="Compute Instance",
                            location=zone,
                            severity=Severity.MEDIUM if attached_disk_mrc > 15 else Severity.LOW,
                            title="Stopped VM Instance",
                            details=f"VM instance is stopped, but attached storage incurs ~${attached_disk_mrc:.2f}/mo.",
                            monthly_waste_usd=attached_disk_mrc,
                            recommendation="Create a custom machine image for backup, then delete the instance."
                        ))
        except Forbidden as e:
            logger.error(f"Permission denied scanning Compute Instances: {e.message}")
        except GoogleAPICallError as e:
            logger.error(f"API failure scanning Compute Instances: {e.message}")

    def _scan_storage_buckets(self) -> None:
        public_principals = {"allUsers", "allAuthenticatedUsers"}
        try:
            for bucket in self.storage_client.list_buckets():
                try:
                    policy = bucket.get_iam_policy()
                    is_public = any(public_principals.intersection(b.get("members", [])) for b in policy.bindings)
                    if is_public:
                        self.findings.append(Finding(
                            resource_id=bucket.name,
                            resource_type="Cloud Storage Bucket",
                            location=bucket.location,
                            severity=Severity.CRITICAL,
                            title="Publicly Accessible Storage Bucket",
                            details="Bucket IAM grants access to allUsers or allAuthenticatedUsers.",
                            monthly_waste_usd=0.0,
                            recommendation="Enable Uniform Bucket-Level Access and revoke public IAM bindings."
                        ))
                    if not bucket.default_kms_key_name:
                        self.findings.append(Finding(
                            resource_id=bucket.name,
                            resource_type="Cloud Storage Bucket",
                            location=bucket.location,
                            severity=Severity.LOW,
                            title="Provider-Managed Encryption (No CMEK)",
                            details="Bucket uses default Google keys rather than Customer-Managed Keys (Cloud KMS).",
                            monthly_waste_usd=0.0,
                            recommendation="Configure CMEK if required by internal security baseline."
                        ))
                except Forbidden as e:
                    logger.warning(f"Access denied retrieving IAM for bucket {bucket.name}: {e.message}")
        except Forbidden as e:
            logger.error(f"Permission denied enumerating Storage Buckets: {e.message}")
        except GoogleAPICallError as e:
            logger.error(f"API failure scanning Storage Buckets: {e.message}")


class HygieneReportGenerator:
    @staticmethod
    def to_json(project_id: str, findings: List[Finding]) -> str:
        total_waste = sum(f.monthly_waste_usd for f in findings)
        payload = {
            "project_id": project_id,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_findings": len(findings),
                "total_projected_monthly_waste_usd": round(total_waste, 2),
                "severity_counts": {sev.value: sum(1 for f in findings if f.severity == sev) for sev in Severity}
            },
            "findings": [f.to_dict() for f in findings]
        }
        return json.dumps(payload, indent=2)

    @staticmethod
    def to_markdown(project_id: str, findings: List[Finding]) -> str:
        total_waste = sum(f.monthly_waste_usd for f in findings)
        crit_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)

        md = [
            f"# Cloud Hygiene & FinOps Audit: `{project_id}`",
            f"**Scan Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            f"**Total Projected Waste:** `${total_waste:,.2f} / month` | **Critical:** `{crit_count}` | **High:** `{high_count}`\n",
            "## Identified Inefficiencies",
            "| Severity | Resource | Type | Region | Est. Waste/Mo | Finding |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |"
        ]

        badges = {
            Severity.CRITICAL: "🔴 CRITICAL",
            Severity.HIGH: "🟠 HIGH",
            Severity.MEDIUM: "🟡 MEDIUM",
            Severity.LOW: "⚪ LOW"
        }

        for f in sorted(findings, key=lambda x: (x.severity.value, -x.monthly_waste_usd)):
            waste_str = f"${f.monthly_waste_usd:,.2f}" if f.monthly_waste_usd > 0 else "—"
            md.append(f"| {badges[f.severity]} | `{f.resource_id}` | {f.resource_type} | {f.location} | {waste_str} | {f.title} |")

        md.append("\n## Remediation Actions")
        for idx, f in enumerate(findings, start=1):
            if f.severity in (Severity.CRITICAL, Severity.HIGH):
                md.append(f"**{idx}. [{f.severity.value}] {f.resource_id} ({f.resource_type})**\n- **Details:** {f.details}\n- **Fix:** {f.recommendation}\n")

        return "\n".join(md)