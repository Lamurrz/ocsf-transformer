"""
ocsf_transformer.py
====================
Security Engineer Utility — Vendor Log → OCSF Schema Transformer
Supports:
  • Microsoft Entra ID  (Sign-In logs      → OCSF Authentication 3002)
  • Wiz                 (Issues/Findings   → OCSF Configuration Finding 5019)
  • Palo Alto Networks  (Auth logs PAN-OS  → OCSF Network Activity 4001)

Usage
-----
  python ocsf_transformer.py --vendor entra  --input entra_signin.json  --output ocsf_out.json
  python ocsf_transformer.py --vendor wiz    --input wiz_issues.json    --output ocsf_out.json
  python ocsf_transformer.py --vendor pan    --input pan_auth.json      --output ocsf_out.json
  python ocsf_transformer.py --vendor entra  --input entra_signin.json  --stdout
  python ocsf_transformer.py --list-vendors

Pipe mode (stdin → stdout):
  cat pan_auth.json | python ocsf_transformer.py --vendor pan --stdin

OCSF references
---------------
  Class 3002 : Authentication    — https://schema.ocsf.io/classes/authentication
  Class 4001 : Network Activity  — https://schema.ocsf.io/classes/network_activity
  Class 5019 : Configuration Finding — https://schema.ocsf.io/classes/config_finding
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("ocsf_transformer")

# ---------------------------------------------------------------------------
# OCSF constants
# ---------------------------------------------------------------------------
OCSF_VERSION = "1.3.0"
OCSF_SCHEMA_URL = "https://schema.ocsf.io"


class OCSFClassID:
    AUTHENTICATION = 3002       # Authentication event
    NETWORK_ACTIVITY = 4001     # Network Activity event
    CONFIG_FINDING = 5019       # Configuration Finding


class OCSFCategory:
    IDENTITY_ACCESS = 3          # Identity & Access Management
    NETWORK_ACTIVITY = 4         # Network Activity
    FINDINGS = 2                 # Findings


class OCSFActivityID:
    # Authentication (3002)
    AUTH_LOGON = 1
    AUTH_LOGOFF = 2
    AUTH_AUTHENTICATION_TICKET = 3
    AUTH_MFA_CHALLENGE = 4
    AUTH_OTHER = 99

    # Network Activity (4001)
    NET_OPEN = 1
    NET_CLOSE = 2
    NET_RESET = 3
    NET_FAIL = 4
    NET_REFUSE = 5
    NET_TRAFFIC = 6
    NET_OTHER = 99

    # Config Finding (5019)
    FINDING_CREATE = 1
    FINDING_UPDATE = 2
    FINDING_CLOSE = 3
    FINDING_OTHER = 99


class OCSFStatusID:
    UNKNOWN = 0
    SUCCESS = 1
    FAILURE = 2
    OTHER = 99


class OCSFSeverityID:
    UNKNOWN = 0
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5
    FATAL = 6


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _now_epoch_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _iso_to_epoch_ms(iso_str: str | None) -> int | None:
    """Convert an ISO-8601 string to epoch milliseconds."""
    if not iso_str:
        return None

    # Strip timezone offset (+HH:MM or -HH:MM) before naive parsing,
    # treating all times as UTC for consistency.
    import re as _re
    clean = _re.sub(r"[+-]\d{2}:\d{2}$", "", iso_str.strip())
    clean = clean.rstrip("Z").replace(" ", "T")

    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%d",
    ):
        try:
            dt = datetime.strptime(clean, fmt).replace(tzinfo=timezone.utc)
            return int(dt.timestamp() * 1000)
        except ValueError:
            continue
    log.warning("Could not parse timestamp: %s", iso_str)
    return None


def _stable_uid(*parts: str) -> str:
    """Deterministic UID based on content so re-ingestion is idempotent."""
    digest = hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()
    return str(uuid.UUID(digest[:32]))


def _get(d: dict, *keys: str, default: Any = None) -> Any:
    """Safe nested dict getter."""
    cur = d
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k, default)
        if cur is None:
            return default
    return cur


# ---------------------------------------------------------------------------
# Base transformer
# ---------------------------------------------------------------------------

class BaseTransformer(ABC):
    """Abstract base – one concrete class per vendor."""

    VENDOR_NAME: str = "unknown"

    @abstractmethod
    def can_handle(self, raw: dict) -> bool:
        """Return True if this transformer recognises the raw event."""

    @abstractmethod
    def transform(self, raw: dict) -> dict:
        """Return a fully-populated OCSF event dict."""

    # ------------------------------------------------------------------
    # Shared OCSF envelope builders
    # ------------------------------------------------------------------

    def _base_envelope(
        self,
        *,
        class_uid: int,
        category_uid: int,
        activity_id: int,
        activity_name: str,
        time_ms: int,
        uid: str,
        raw: dict,
    ) -> dict:
        return {
            "ocsf_version": OCSF_VERSION,
            "class_uid": class_uid,
            "category_uid": category_uid,
            "activity_id": activity_id,
            "activity_name": activity_name,
            "time": time_ms,
            "metadata": {
                "uid": uid,
                "version": OCSF_VERSION,
                "product": {
                    "vendor_name": self.VENDOR_NAME,
                    "name": self.VENDOR_NAME,
                },
                "processed_time": _now_epoch_ms(),
                "schema_url": OCSF_SCHEMA_URL,
            },
            "unmapped": {},          # catch-all for non-standard fields
            "_raw": raw,             # original event preserved for fidelity
        }


# ---------------------------------------------------------------------------
# Microsoft Entra ID → OCSF Authentication (3002)
# ---------------------------------------------------------------------------

class EntraSignInTransformer(BaseTransformer):
    """
    Transforms Microsoft Entra ID (Azure AD) Sign-In log entries.

    Entra log shape (simplified):
    {
      "id": "...",
      "createdDateTime": "2024-05-01T12:34:56Z",
      "userDisplayName": "Alice Smith",
      "userPrincipalName": "alice@contoso.com",
      "userId": "...",
      "appDisplayName": "Microsoft Teams",
      "appId": "...",
      "ipAddress": "203.0.113.5",
      "location": {"city": "Seattle", "state": "WA", "countryOrRegion": "US",
                   "geoCoordinates": {"latitude": 47.6, "longitude": -122.3}},
      "status": {"errorCode": 0, "failureReason": null},
      "conditionalAccessStatus": "success",
      "authenticationRequirement": "multiFactorAuthentication",
      "riskLevelDuringSignIn": "none",
      "clientAppUsed": "Browser",
      "deviceDetail": {"deviceId": "...", "displayName": "LAPTOP-01",
                       "operatingSystem": "Windows 10", "browser": "Chrome 124"},
      "mfaDetail": {"authMethod": "PhoneAppNotification", "authDetail": "Approved"},
      "tokenIssuanceType": "AzureAD"
    }
    """

    VENDOR_NAME = "Microsoft Entra ID"

    # Entra errorCode 0 == success
    _SUCCESS_CODES: frozenset[int] = frozenset({0})

    # Map Entra risk levels → OCSF severity
    _RISK_TO_SEVERITY: dict[str, int] = {
        "none":   OCSFSeverityID.INFORMATIONAL,
        "low":    OCSFSeverityID.LOW,
        "medium": OCSFSeverityID.MEDIUM,
        "high":   OCSFSeverityID.HIGH,
        "hidden": OCSFSeverityID.UNKNOWN,
    }

    def can_handle(self, raw: dict) -> bool:
        # Entra sign-in logs have createdDateTime + userPrincipalName
        return bool(raw.get("createdDateTime") and raw.get("userPrincipalName"))

    def transform(self, raw: dict) -> dict:
        event_id   = raw.get("id") or str(uuid.uuid4())
        time_ms    = _iso_to_epoch_ms(raw.get("createdDateTime")) or _now_epoch_ms()
        error_code = _get(raw, "status", "errorCode", default=None)
        is_success = error_code in self._SUCCESS_CODES if error_code is not None else None

        status_id   = OCSFStatusID.SUCCESS if is_success else (
                      OCSFStatusID.FAILURE if is_success is False else OCSFStatusID.UNKNOWN)
        status_str  = "Success" if is_success else (
                      _get(raw, "status", "failureReason") or "Failure")

        risk_level  = (raw.get("riskLevelDuringSignIn") or "none").lower()
        severity_id = self._RISK_TO_SEVERITY.get(risk_level, OCSFSeverityID.INFORMATIONAL)

        # Activity: MFA challenge vs. standard logon
        auth_req    = raw.get("authenticationRequirement", "")
        if "multiFactorAuthentication" in auth_req:
            activity_id   = OCSFActivityID.AUTH_MFA_CHALLENGE
            activity_name = "MFA Challenge"
        else:
            activity_id   = OCSFActivityID.AUTH_LOGON
            activity_name = "Logon"

        uid = _stable_uid("entra", event_id)
        envelope = self._base_envelope(
            class_uid=OCSFClassID.AUTHENTICATION,
            category_uid=OCSFCategory.IDENTITY_ACCESS,
            activity_id=activity_id,
            activity_name=activity_name,
            time_ms=time_ms,
            uid=uid,
            raw=raw,
        )

        # ── User object ──────────────────────────────────────────────
        envelope["user"] = {
            "uid":          raw.get("userId"),
            "name":         raw.get("userPrincipalName"),
            "full_name":    raw.get("userDisplayName"),
            "type":         "User",
            "type_id":      1,
        }

        # ── Service / Application ────────────────────────────────────
        envelope["service"] = {
            "name":   raw.get("appDisplayName"),
            "uid":    raw.get("appId"),
        }

        # ── Source endpoint ──────────────────────────────────────────
        loc = raw.get("location", {})
        geo = loc.get("geoCoordinates", {})
        envelope["src_endpoint"] = {
            "ip":       raw.get("ipAddress"),
            "location": {
                "city":        loc.get("city"),
                "region":      loc.get("state"),
                "country":     loc.get("countryOrRegion"),
                "lat":         geo.get("latitude"),
                "long":        geo.get("longitude"),
            },
        }

        # ── Device ───────────────────────────────────────────────────
        dev = raw.get("deviceDetail", {})
        envelope["device"] = {
            "uid":         dev.get("deviceId"),
            "name":        dev.get("displayName"),
            "os": {
                "name":    dev.get("operatingSystem"),
            },
            "type":        raw.get("clientAppUsed"),
        }

        # ── Auth protocol / MFA ──────────────────────────────────────
        mfa = raw.get("mfaDetail", {})
        envelope["authentication"] = {
            "auth_protocol":        raw.get("authenticationRequirement"),
            "token_issuance_type":  raw.get("tokenIssuanceType"),
            "mfa_method":           mfa.get("authMethod"),
            "mfa_detail":           mfa.get("authDetail"),
            "conditional_access":   raw.get("conditionalAccessStatus"),
        }

        # ── Status & severity ────────────────────────────────────────
        envelope["status"]      = status_str
        envelope["status_id"]   = status_id
        envelope["status_code"] = str(error_code) if error_code is not None else None
        envelope["severity"]    = risk_level.capitalize()
        envelope["severity_id"] = severity_id

        # ── Risk ─────────────────────────────────────────────────────
        envelope["risk_details"] = {
            "level_during_signin":    raw.get("riskLevelDuringSignIn"),
            "level_aggregated":       raw.get("riskLevelAggregated"),
            "state":                  raw.get("riskState"),
            "detail":                 raw.get("riskDetail"),
        }

        # ── Unmapped remainder ────────────────────────────────────────
        mapped_keys = {
            "id", "createdDateTime", "userDisplayName", "userPrincipalName",
            "userId", "appDisplayName", "appId", "ipAddress", "location",
            "status", "conditionalAccessStatus", "authenticationRequirement",
            "riskLevelDuringSignIn", "riskLevelAggregated", "riskState",
            "riskDetail", "clientAppUsed", "deviceDetail", "mfaDetail",
            "tokenIssuanceType",
        }
        envelope["unmapped"] = {k: v for k, v in raw.items() if k not in mapped_keys}

        return envelope


# ---------------------------------------------------------------------------
# Wiz → OCSF Configuration Finding (5019)
# ---------------------------------------------------------------------------

class WizFindingTransformer(BaseTransformer):
    """
    Transforms Wiz issue/finding exports.

    Wiz finding shape (simplified):
    {
      "id": "...",
      "createdAt": "2024-05-10T08:00:00Z",
      "updatedAt": "2024-05-10T08:05:00Z",
      "resolvedAt": null,
      "status": "OPEN",
      "severity": "HIGH",
      "name": "S3 bucket is publicly accessible",
      "description": "The S3 bucket allows public read access.",
      "remediation": "Disable public access block settings.",
      "type": {"name": "Misconfiguration"},
      "resource": {
        "id": "...",
        "name": "my-data-bucket",
        "type": "BUCKET",
        "cloudProvider": "AWS",
        "region": "us-east-1",
        "subscription": {"id": "...", "name": "prod-account",
                         "externalId": "123456789012"}
      },
      "rule": {"id": "...", "name": "S3 bucket public access",
               "shortId": "WIZ-0042"},
      "note": "Reviewed by security team"
    }
    """

    VENDOR_NAME = "Wiz"

    _SEVERITY_MAP: dict[str, int] = {
        "INFORMATIONAL": OCSFSeverityID.INFORMATIONAL,
        "LOW":           OCSFSeverityID.LOW,
        "MEDIUM":        OCSFSeverityID.MEDIUM,
        "HIGH":          OCSFSeverityID.HIGH,
        "CRITICAL":      OCSFSeverityID.CRITICAL,
    }

    _STATUS_MAP: dict[str, tuple[int, str]] = {
        "OPEN":      (OCSFStatusID.OTHER, "Open"),
        "IN_PROGRESS": (OCSFStatusID.OTHER, "In Progress"),
        "RESOLVED":  (OCSFStatusID.SUCCESS, "Resolved"),
        "REJECTED":  (OCSFStatusID.OTHER, "Rejected"),
    }

    _ACTIVITY_MAP: dict[str, int] = {
        "OPEN":        OCSFActivityID.FINDING_CREATE,
        "IN_PROGRESS": OCSFActivityID.FINDING_UPDATE,
        "RESOLVED":    OCSFActivityID.FINDING_CLOSE,
        "REJECTED":    OCSFActivityID.FINDING_CLOSE,
    }

    def can_handle(self, raw: dict) -> bool:
        # Wiz findings have 'severity' (uppercase) + 'resource' + 'rule'
        return bool(
            raw.get("severity")
            and raw.get("resource")
            and raw.get("rule")
        )

    def transform(self, raw: dict) -> dict:
        event_id  = raw.get("id") or str(uuid.uuid4())
        time_ms   = _iso_to_epoch_ms(raw.get("createdAt")) or _now_epoch_ms()
        wiz_status = (raw.get("status") or "OPEN").upper()

        status_id, status_str = self._STATUS_MAP.get(
            wiz_status, (OCSFStatusID.UNKNOWN, wiz_status.capitalize()))

        sev_str    = (raw.get("severity") or "MEDIUM").upper()
        severity_id = self._SEVERITY_MAP.get(sev_str, OCSFSeverityID.UNKNOWN)

        activity_id   = self._ACTIVITY_MAP.get(wiz_status, OCSFActivityID.FINDING_OTHER)
        activity_name = {
            OCSFActivityID.FINDING_CREATE: "Create",
            OCSFActivityID.FINDING_UPDATE: "Update",
            OCSFActivityID.FINDING_CLOSE:  "Close",
        }.get(activity_id, "Other")

        uid = _stable_uid("wiz", event_id)
        envelope = self._base_envelope(
            class_uid=OCSFClassID.CONFIG_FINDING,
            category_uid=OCSFCategory.FINDINGS,
            activity_id=activity_id,
            activity_name=activity_name,
            time_ms=time_ms,
            uid=uid,
            raw=raw,
        )

        # ── Finding object ────────────────────────────────────────────
        rule = raw.get("rule", {})
        envelope["finding"] = {
            "uid":          event_id,
            "title":        raw.get("name"),
            "description":  raw.get("description"),
            "type":         _get(raw, "type", "name"),
            "remediation":  {"desc": raw.get("remediation")},
            "created_time": time_ms,
            "modified_time": _iso_to_epoch_ms(raw.get("updatedAt")),
            "first_seen_time": time_ms,
            "last_seen_time":  _iso_to_epoch_ms(raw.get("updatedAt")) or time_ms,
        }

        # ── Rule / Policy ─────────────────────────────────────────────
        envelope["rule"] = {
            "uid":     rule.get("id"),
            "name":    rule.get("name"),
            "short_id": rule.get("shortId"),
        }

        # ── Resource (affected cloud asset) ──────────────────────────
        res = raw.get("resource", {})
        sub = res.get("subscription", {})
        envelope["resource"] = {
            "uid":          res.get("id"),
            "name":         res.get("name"),
            "type":         res.get("type"),
            "cloud": {
                "provider":       res.get("cloudProvider"),
                "region":         res.get("region"),
                "account": {
                    "uid":   sub.get("externalId"),
                    "name":  sub.get("name"),
                    "type":  "Account",
                },
            },
        }

        # ── Compliance / Risk ─────────────────────────────────────────
        envelope["compliance"] = {
            "requirements":    raw.get("frameworks", []),
            "control":         rule.get("name"),
            "status":          status_str,
        }

        # ── Status & severity ─────────────────────────────────────────
        envelope["status"]      = status_str
        envelope["status_id"]   = status_id
        envelope["severity"]    = sev_str.capitalize()
        envelope["severity_id"] = severity_id

        # ── Analyst note ──────────────────────────────────────────────
        if raw.get("note"):
            envelope["comment"] = raw["note"]

        # ── Timestamps ───────────────────────────────────────────────
        if raw.get("resolvedAt"):
            envelope["end_time"] = _iso_to_epoch_ms(raw["resolvedAt"])

        # ── Unmapped remainder ────────────────────────────────────────
        mapped_keys = {
            "id", "createdAt", "updatedAt", "resolvedAt", "status",
            "severity", "name", "description", "remediation", "type",
            "resource", "rule", "note", "frameworks",
        }
        envelope["unmapped"] = {k: v for k, v in raw.items() if k not in mapped_keys}

        return envelope


# ---------------------------------------------------------------------------
# Palo Alto Networks PAN-OS → OCSF Network Activity (4001)
# ---------------------------------------------------------------------------

class PanOSAuthTransformer(BaseTransformer):
    """
    Transforms Palo Alto Networks PAN-OS Authentication log entries (JSON, PAN-OS 10.1+).

    PAN-OS Auth log shape (JSON, simplified):
    {
      "receive_time":       "2024/05/01 12:34:56",
      "serial":             "015351000012345",
      "type":               "AUTH",
      "subtype":            "authentication",
      "time_generated":     "2024/05/01 12:34:55",
      "vsys":               "vsys1",
      "ip":                 "10.0.0.5",
      "user":               "alice",
      "normalize_user":     "alice@contoso.com",
      "object":             "GlobalProtect",
      "authpolicy":         "gp-auth-policy",
      "authid":             "7890",
      "vendor":             "RADIUS",
      "clienttype":         "SSLVPN",
      "event":              "auth-success",
      "factorno":           1,
      "seqno":              "100001",
      "actionflags":        "0x0",
      "dg_hier_level_1":    10,
      "vsys_name":          "vsys1",
      "device_name":        "PA-VM-01",
      "vsys_id":            1,
      "authproto":          "RADIUS",
      "rule_uuid":          "...",
      "high_res_timestamp": "2024-05-01T12:34:55.123456+00:00"
    }

    OCSF target: Network Activity (class_uid 4001), category_uid 4.
    The 'connection' object carries the auth context; src_endpoint is the
    authenticating client; dst_endpoint is the firewall/gateway itself.
    """

    VENDOR_NAME = "Palo Alto Networks"

    # Map PAN-OS auth event strings → OCSF activity + status
    _EVENT_MAP: dict[str, tuple[int, int, str]] = {
        # event_str          → (activity_id,          status_id,              status_str)
        "auth-success":       (OCSFActivityID.NET_OPEN,   OCSFStatusID.SUCCESS, "Success"),
        "auth-fail":          (OCSFActivityID.NET_FAIL,   OCSFStatusID.FAILURE, "Failure"),
        "auth-challenge":     (OCSFActivityID.NET_OPEN,   OCSFStatusID.OTHER,   "Challenge"),
        "auth-timeout":       (OCSFActivityID.NET_FAIL,   OCSFStatusID.FAILURE, "Timeout"),
        "logout":             (OCSFActivityID.NET_CLOSE,  OCSFStatusID.SUCCESS, "Logout"),
        "sso-logon":          (OCSFActivityID.NET_OPEN,   OCSFStatusID.SUCCESS, "SSO Logon"),
        "sso-logoff":         (OCSFActivityID.NET_CLOSE,  OCSFStatusID.SUCCESS, "SSO Logoff"),
    }

    _ACTIVITY_NAME: dict[int, str] = {
        OCSFActivityID.NET_OPEN:  "Open",
        OCSFActivityID.NET_CLOSE: "Close",
        OCSFActivityID.NET_FAIL:  "Fail",
        OCSFActivityID.NET_OTHER: "Other",
    }

    # PAN-OS uses "factorno" to indicate MFA step (>1 == MFA factor)
    _MFA_FACTOR_THRESHOLD = 1

    def can_handle(self, raw: dict) -> bool:
        # PAN-OS JSON auth logs carry type=="AUTH" and a "device_name" field
        return (
            raw.get("type", "").upper() == "AUTH"
            and bool(raw.get("device_name"))
            and bool(raw.get("user") or raw.get("normalize_user"))
        )

    def transform(self, raw: dict) -> dict:
        # ── Timestamps ───────────────────────────────────────────────
        # Prefer high_res_timestamp (ISO-8601), fall back to time_generated
        ts_raw  = raw.get("high_res_timestamp") or raw.get("time_generated")
        time_ms = _iso_to_epoch_ms(ts_raw) or _now_epoch_ms()

        # ── Event classification ─────────────────────────────────────
        event_str    = (raw.get("event") or "").lower()
        activity_id, status_id, status_str = self._EVENT_MAP.get(
            event_str,
            (OCSFActivityID.NET_OTHER, OCSFStatusID.UNKNOWN, event_str.capitalize() or "Unknown"),
        )
        activity_name = self._ACTIVITY_NAME.get(activity_id, "Other")

        # ── Severity: failures → LOW; success → INFORMATIONAL ────────
        if status_id == OCSFStatusID.FAILURE:
            severity_id = OCSFSeverityID.LOW
            severity    = "Low"
        else:
            severity_id = OCSFSeverityID.INFORMATIONAL
            severity    = "Informational"

        # ── Stable UID ───────────────────────────────────────────────
        seq = raw.get("seqno") or str(uuid.uuid4())
        uid = _stable_uid("pan", raw.get("serial", ""), seq)

        envelope = self._base_envelope(
            class_uid=OCSFClassID.NETWORK_ACTIVITY,
            category_uid=OCSFCategory.NETWORK_ACTIVITY,
            activity_id=activity_id,
            activity_name=activity_name,
            time_ms=time_ms,
            uid=uid,
            raw=raw,
        )

        # ── User object ──────────────────────────────────────────────
        # normalize_user carries UPN form when available
        upn  = raw.get("normalize_user") or raw.get("user")
        name = raw.get("user")
        envelope["user"] = {
            "name":     upn,
            "uid":      name,
            "type":     "User",
            "type_id":  1,
        }

        # ── Source endpoint (authenticating client) ──────────────────
        envelope["src_endpoint"] = {
            "ip":   raw.get("ip"),
            "type": raw.get("clienttype"),
        }

        # ── Destination endpoint (firewall / gateway) ────────────────
        envelope["dst_endpoint"] = {
            "name":     raw.get("device_name"),
            "uid":      raw.get("serial"),
            "hostname": raw.get("device_name"),
        }

        # ── Connection / auth context ────────────────────────────────
        factor_no  = raw.get("factorno", 1)
        is_mfa     = isinstance(factor_no, int) and factor_no > self._MFA_FACTOR_THRESHOLD
        envelope["connection_info"] = {
            "auth_protocol":  raw.get("authproto") or raw.get("vendor"),
            "auth_policy":    raw.get("authpolicy"),
            "auth_object":    raw.get("object"),          # e.g. "GlobalProtect"
            "auth_id":        raw.get("authid"),
            "client_type":    raw.get("clienttype"),
            "factor_no":      factor_no,
            "is_mfa":         is_mfa,
            "mfa_factor":     factor_no if is_mfa else None,
        }

        # ── Device / firewall context ────────────────────────────────
        envelope["device"] = {
            "name":     raw.get("device_name"),
            "uid":      raw.get("serial"),
            "type":     "Firewall",
            "type_id":  9,              # OCSF device type 9 = Network Device
            "vsys":     raw.get("vsys") or raw.get("vsys_name"),
            "vsys_id":  raw.get("vsys_id"),
        }

        # ── Firewall policy metadata ─────────────────────────────────
        envelope["policy"] = {
            "name":     raw.get("authpolicy"),
            "uid":      raw.get("rule_uuid"),
        }

        # ── Status & severity ────────────────────────────────────────
        envelope["status"]      = status_str
        envelope["status_id"]   = status_id
        envelope["severity"]    = severity
        envelope["severity_id"] = severity_id
        envelope["message"]     = f"PAN-OS auth event: {event_str} for user {upn}"

        # ── Unmapped remainder ────────────────────────────────────────
        mapped_keys = {
            "receive_time", "serial", "type", "subtype", "time_generated",
            "vsys", "ip", "user", "normalize_user", "object", "authpolicy",
            "authid", "vendor", "clienttype", "event", "factorno", "seqno",
            "actionflags", "dg_hier_level_1", "vsys_name", "device_name",
            "vsys_id", "authproto", "rule_uuid", "high_res_timestamp",
        }
        envelope["unmapped"] = {k: v for k, v in raw.items() if k not in mapped_keys}

        return envelope


# ---------------------------------------------------------------------------
# Transformer registry & auto-detect
# ---------------------------------------------------------------------------

TRANSFORMERS: dict[str, BaseTransformer] = {
    "entra": EntraSignInTransformer(),
    "wiz":   WizFindingTransformer(),
    "pan":   PanOSAuthTransformer(),
}


def auto_detect(raw: dict) -> BaseTransformer | None:
    for transformer in TRANSFORMERS.values():
        if transformer.can_handle(raw):
            return transformer
    return None


# ---------------------------------------------------------------------------
# Ingestion pipeline
# ---------------------------------------------------------------------------

def ingest(
    raw_events: list[dict],
    vendor: str | None = None,
) -> tuple[list[dict], list[dict]]:
    """
    Transform a list of raw events.

    Returns
    -------
    (successes, failures)
      successes : list of OCSF-mapped dicts
      failures  : list of {"index": int, "error": str, "raw": dict}
    """
    successes: list[dict] = []
    failures:  list[dict] = []

    transformer: BaseTransformer | None = TRANSFORMERS.get(vendor) if vendor else None

    for i, raw in enumerate(raw_events):
        try:
            t = transformer or auto_detect(raw)
            if t is None:
                raise ValueError(
                    f"No transformer matched this event. "
                    f"Available vendors: {list(TRANSFORMERS)}"
                )
            ocsf_event = t.transform(raw)
            successes.append(ocsf_event)
            log.debug("Event %d → OCSF class %s", i, ocsf_event.get("class_uid"))
        except Exception as exc:  # noqa: BLE001
            log.warning("Event %d failed: %s", i, exc)
            failures.append({"index": i, "error": str(exc), "raw": raw})

    return successes, failures


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _load_json(path: Path | None, use_stdin: bool) -> list[dict]:
    if use_stdin:
        raw = json.load(sys.stdin)
    elif path:
        raw = json.loads(path.read_text(encoding="utf-8"))
    else:
        raise ValueError("Provide --input or --stdin")

    # Accept a single event dict or a list
    return raw if isinstance(raw, list) else [raw]


def _write_json(data: Any, path: Path | None, stdout: bool) -> None:
    text = json.dumps(data, indent=2, default=str)
    if stdout or path is None:
        print(text)
    else:
        path.write_text(text, encoding="utf-8")
        log.info("Output written → %s", path)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Vendor log → OCSF transformer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--vendor", choices=list(TRANSFORMERS),
                   help="Force a specific vendor parser (omit for auto-detect)")
    p.add_argument("--input",  type=Path, help="Path to raw JSON input file")
    p.add_argument("--output", type=Path, help="Path to write OCSF JSON output")
    p.add_argument("--stdin",  action="store_true", help="Read input from stdin")
    p.add_argument("--stdout", action="store_true", help="Write output to stdout")
    p.add_argument("--include-raw", action="store_true",
                   help="Preserve original event under _raw key (default: strip it)")
    p.add_argument("--include-failures", action="store_true",
                   help="Append a failures summary to the output")
    p.add_argument("--list-vendors", action="store_true",
                   help="List supported vendor parsers and exit")
    p.add_argument("--verbose", "-v", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args   = parser.parse_args(argv)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.list_vendors:
        print("Supported vendors:")
        for key, t in TRANSFORMERS.items():
            print(f"  {key:12s}  {t.VENDOR_NAME}")
        return 0

    raw_events = _load_json(args.input, args.stdin)
    log.info("Loaded %d raw event(s)", len(raw_events))

    successes, failures = ingest(raw_events, vendor=args.vendor)
    log.info("Transformed: %d success, %d failure", len(successes), len(failures))

    # Optionally strip _raw to reduce payload size
    if not args.include_raw:
        for e in successes:
            e.pop("_raw", None)

    output: Any
    if args.include_failures:
        output = {"events": successes, "failures": failures}
    else:
        output = successes if len(successes) != 1 else successes[0]

    _write_json(output, args.output, args.stdout)

    # Non-zero exit if any events failed
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
