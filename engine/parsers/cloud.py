import re
import json


class CloudParser:
    """Handles AWS/Azure/GCP CLI JSON, Prowler, ScoutSuite, Pacu output."""
    name = "cloud"

    def confidence(self, text: str) -> float:
        t = text.strip()
        # JSON-based cloud tool output
        if t.startswith("{") or t.startswith("["):
            try:
                data = json.loads(t)
                if self._is_cloud_json(data):
                    return 0.92
            except json.JSONDecodeError:
                pass
        # Text-based CLI / tool output
        if re.search(r"arn:aws:|AKID|aws_access_key|AssumeRole|sts:GetCallerIdentity", t):
            return 0.95
        if re.search(r"\"roleDefinitionName\":|\"principalType\":|\"assignmentScope\"", t):
            return 0.92
        if re.search(r"prowler|scoutsuite|pacu|cloudmapper", t, re.IGNORECASE):
            return 0.9
        if re.search(r"\bARN\b|AmazonS3|ec2\.amazonaws|iam\.amazonaws", t, re.IGNORECASE):
            return 0.88
        if re.search(r"serviceAccount:|\"kind\":\s*\"ClusterRoleBinding\"|gcloud.*iam", t):
            return 0.85
        return 0.0

    def _is_cloud_json(self, data) -> bool:
        if isinstance(data, dict):
            keys = set(data.keys())
            if keys & {"Users", "Roles", "Policies", "Groups", "Buckets", "Instances",
                        "services", "findings", "results", "Findings"}:
                return True
            if "Account" in data and "Services" in data:
                return True
        if isinstance(data, list) and data and isinstance(data[0], dict):
            sample = data[0]
            if any(k in sample for k in ("Arn", "RoleId", "PolicyArn", "BucketName",
                                          "InstanceId", "GroupId", "UserId")):
                return True
        return False

    def parse(self, text: str) -> dict:
        hosts, credentials, findings = [], [], []

        # --- AWS ---
        findings += self._parse_aws(text)
        credentials += self._parse_aws_creds(text)

        # --- Azure ---
        findings += self._parse_azure(text)

        # --- GCP ---
        findings += self._parse_gcp(text)

        # --- Prowler ---
        if re.search(r"prowler", text, re.IGNORECASE):
            findings += self._parse_prowler(text)

        # --- ScoutSuite ---
        if re.search(r"scoutsuite|scout_", text, re.IGNORECASE):
            findings += self._parse_scoutsuite(text)

        return {"hosts": hosts, "credentials": credentials, "findings": findings}

    def _parse_aws(self, text: str) -> list[dict]:
        findings = []

        # IAM users without MFA
        for m in re.finditer(r'"UserName":\s*"([^"]+)"', text):
            user = m.group(1)
            # Check surrounding context for MFA disabled
            snippet = text[m.start():m.start() + 500]
            if re.search(r'"mfa_active":\s*false|MFADevices.*\[\]|no MFA', snippet, re.IGNORECASE):
                findings.append({
                    "title": f"IAM user without MFA: {user}",
                    "description": "IAM user lacks MFA — credential compromise allows direct console access",
                    "evidence": f"User: {user}",
                    "severity": "high",
                    "type": "cloud-iam",
                    "host_ip": "",
                })

        # Admin/wildcard policies
        for m in re.finditer(
            r'"Effect":\s*"Allow"[^}]*"Action":\s*"\*"[^}]*"Resource":\s*"\*"', text, re.DOTALL,
        ):
            findings.append({
                "title": "IAM wildcard policy: Action:* Resource:*",
                "description": "Full admin IAM policy — complete account compromise if assumed",
                "evidence": m.group(0)[:200],
                "severity": "critical",
                "type": "cloud-iam",
                "host_ip": "",
            })

        # PassRole + privilege escalation patterns
        for m in re.finditer(r'"Action":\s*\[?[^"\]]*"iam:PassRole"', text, re.IGNORECASE):
            snippet = text[m.start():m.start() + 300]
            if '"iam:CreateRole"' in snippet or '"iam:AttachRolePolicy"' in snippet:
                findings.append({
                    "title": "IAM privilege escalation: PassRole + CreateRole/AttachRolePolicy",
                    "description": "Can create role and attach admin policy — full account takeover path",
                    "evidence": snippet[:200],
                    "severity": "critical",
                    "type": "cloud-iam",
                    "host_ip": "",
                })

        # Public S3 buckets
        for m in re.finditer(r'"BucketName":\s*"([^"]+)"', text):
            bucket = m.group(1)
            snippet = text[m.start():m.start() + 500]
            if re.search(r'"URI":\s*"http://acs\.amazonaws\.com/groups/global/AllUsers"|Public.*READ|AllUsers', snippet):
                findings.append({
                    "title": f"S3 bucket publicly accessible: {bucket}",
                    "description": "S3 bucket ACL grants access to AllUsers — data exposure risk",
                    "evidence": f"Bucket: {bucket}",
                    "severity": "critical",
                    "type": "cloud-storage",
                    "host_ip": "",
                })

        # EC2 security groups 0.0.0.0/0
        for m in re.finditer(r'"CidrIp":\s*"0\.0\.0\.0/0"', text):
            snippet = text[max(0, m.start() - 200):m.start()]
            port_m = re.search(r'"FromPort":\s*(\d+)', snippet)
            port = port_m.group(1) if port_m else "any"
            findings.append({
                "title": f"Security group open to internet: port {port}",
                "description": "EC2 security group allows 0.0.0.0/0 inbound — direct internet exposure",
                "evidence": f"Port {port} open to 0.0.0.0/0",
                "severity": "high" if port not in ("443", "80") else "medium",
                "type": "cloud-network",
                "host_ip": "",
            })

        # Instance metadata v1 (IMDSv1)
        if re.search(r"HttpTokens.*optional|imds.*v1|169\.254\.169\.254", text, re.IGNORECASE):
            findings.append({
                "title": "EC2 IMDSv1 enabled (metadata service)",
                "description": "IMDSv1 accessible without token — SSRF can steal instance profile credentials",
                "evidence": "HttpTokens: optional or IMDSv1 endpoint referenced",
                "severity": "high",
                "type": "cloud-metadata",
                "host_ip": "",
            })

        # Lambda with admin role
        for m in re.finditer(r'"FunctionName":\s*"([^"]+)"', text):
            fn = m.group(1)
            snippet = text[m.start():m.start() + 800]
            if re.search(r"AdministratorAccess|Action.*\*.*Resource.*\*", snippet, re.DOTALL):
                findings.append({
                    "title": f"Lambda with admin IAM role: {fn}",
                    "description": "Lambda function has admin permissions — code execution yields full account access",
                    "evidence": f"Function: {fn}",
                    "severity": "critical",
                    "type": "cloud-iam",
                    "host_ip": "",
                })

        # CloudTrail disabled
        if re.search(r'"IsLogging":\s*false|CloudTrail.*disabled|no.*trail', text, re.IGNORECASE):
            findings.append({
                "title": "CloudTrail logging disabled",
                "description": "API calls not logged — attacker actions invisible to blue team",
                "evidence": "CloudTrail IsLogging: false",
                "severity": "high",
                "type": "cloud-detection",
                "host_ip": "",
            })

        # Secrets in environment variables
        for m in re.finditer(
            r'"(AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|DATABASE_URL|SECRET_KEY|API_KEY|TOKEN)":\s*"([^"]{8,})"',
            text, re.IGNORECASE,
        ):
            findings.append({
                "title": f"Secret in environment: {m.group(1)}",
                "description": "Sensitive value hardcoded in Lambda/ECS environment variable",
                "evidence": f"Key: {m.group(1)}",
                "severity": "critical",
                "type": "secret-exposure",
                "host_ip": "",
            })

        # AssumeRole with external ID missing (confused deputy)
        for m in re.finditer(r'"sts:AssumeRole"', text):
            snippet = text[m.start():m.start() + 400]
            if "ExternalId" not in snippet and "Condition" not in snippet:
                findings.append({
                    "title": "AssumeRole without ExternalId condition",
                    "description": "Cross-account role trust without ExternalId — confused deputy attack possible",
                    "evidence": snippet[:200],
                    "severity": "medium",
                    "type": "cloud-iam",
                    "host_ip": "",
                })

        return findings

    def _parse_aws_creds(self, text: str) -> list[dict]:
        creds = []
        # Access key + secret
        key_m = re.search(r"(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})", text)
        secret_m = re.search(r"aws_secret_access_key[\"'\s:=]+([A-Za-z0-9+/]{40})", text, re.IGNORECASE)
        if key_m:
            creds.append({
                "username": key_m.group(1),
                "secret": secret_m.group(1) if secret_m else "",
                "secret_type": "aws-access-key",
                "domain": "aws",
                "source": "cloud-parser",
            })
        # Session token
        token_m = re.search(
            r"aws_session_token[\"'\s:=]+([A-Za-z0-9+/=]{100,})", text, re.IGNORECASE,
        )
        if token_m:
            creds.append({
                "username": "aws-session",
                "secret": token_m.group(1)[:64] + "...",
                "secret_type": "aws-session-token",
                "domain": "aws",
                "source": "cloud-parser",
            })
        return creds

    def _parse_azure(self, text: str) -> list[dict]:
        findings = []

        # Owner/Contributor on subscription
        for m in re.finditer(
            r'"roleDefinitionName":\s*"(Owner|Contributor)"[^}]*"principalType":\s*"([^"]+)"[^}]*"principalName":\s*"([^"]+)"',
            text, re.DOTALL,
        ):
            role, ptype, principal = m.group(1), m.group(2), m.group(3)
            if ptype in ("ServicePrincipal", "ForeignGroup"):
                findings.append({
                    "title": f"Azure {role} role on external principal: {principal}",
                    "description": f"External {ptype} has {role} role — validate if expected",
                    "evidence": m.group(0)[:200],
                    "severity": "high",
                    "type": "cloud-iam",
                    "host_ip": "",
                })

        # Storage account anonymous access
        if re.search(r'"allowBlobPublicAccess":\s*true|PublicAccessPolicy.*Container', text, re.IGNORECASE):
            findings.append({
                "title": "Azure storage blob public access enabled",
                "description": "Storage account allows anonymous blob access — data exposure",
                "evidence": "allowBlobPublicAccess: true",
                "severity": "high",
                "type": "cloud-storage",
                "host_ip": "",
            })

        # Key Vault no RBAC / soft delete disabled
        if re.search(r'"enableSoftDelete":\s*false', text, re.IGNORECASE):
            findings.append({
                "title": "Azure Key Vault soft delete disabled",
                "description": "Secrets/keys can be permanently deleted — potential data destruction",
                "evidence": "enableSoftDelete: false",
                "severity": "medium",
                "type": "cloud-config",
                "host_ip": "",
            })

        # Managed Identity with high privileges
        for m in re.finditer(r'"identity":\s*\{[^}]*"type":\s*"SystemAssigned"', text, re.DOTALL):
            snippet = text[m.start():m.start() + 600]
            if re.search(r"Owner|Contributor|Key Vault", snippet):
                findings.append({
                    "title": "Azure resource with privileged Managed Identity",
                    "description": "Resource has system-assigned identity with elevated permissions — compromise allows RBAC pivoting",
                    "evidence": snippet[:200],
                    "severity": "high",
                    "type": "cloud-iam",
                    "host_ip": "",
                })

        return findings

    def _parse_gcp(self, text: str) -> list[dict]:
        findings = []

        # Service account with owner/editor
        for m in re.finditer(
            r'"role":\s*"roles/(owner|editor)"[^}]*"member":\s*"serviceAccount:([^"]+)"',
            text, re.DOTALL | re.IGNORECASE,
        ):
            findings.append({
                "title": f"GCP service account with {m.group(1)} role: {m.group(2)}",
                "description": f"Service account has primitive {m.group(1)} role — if key exists, full project access",
                "evidence": m.group(0)[:200],
                "severity": "critical",
                "type": "cloud-iam",
                "host_ip": "",
            })

        # allUsers / allAuthenticatedUsers bindings
        for m in re.finditer(r'"member":\s*"(allUsers|allAuthenticatedUsers)"', text, re.IGNORECASE):
            snippet = text[max(0, m.start() - 200):m.start() + 100]
            role_m = re.search(r'"role":\s*"([^"]+)"', snippet)
            role = role_m.group(1) if role_m else "unknown"
            findings.append({
                "title": f"GCP public IAM binding: {m.group(1)} has {role}",
                "description": "IAM policy grants access to all/any users — unauthorized access possible",
                "evidence": m.group(0),
                "severity": "critical" if "admin" in role.lower() else "high",
                "type": "cloud-iam",
                "host_ip": "",
            })

        # GCS bucket public
        if re.search(r"allUsers.*READER|allAuthenticatedUsers.*READER|public.*bucket", text, re.IGNORECASE):
            findings.append({
                "title": "GCS bucket publicly readable",
                "description": "Cloud Storage bucket accessible to all users",
                "evidence": "Public bucket ACL found",
                "severity": "high",
                "type": "cloud-storage",
                "host_ip": "",
            })

        # Compute metadata server
        if re.search(r"metadata\.google\.internal|computeMetadata/v1", text, re.IGNORECASE):
            findings.append({
                "title": "GCP metadata service accessible",
                "description": "Compute metadata endpoint reachable — service account token and project info extractable",
                "evidence": "metadata.google.internal referenced",
                "severity": "high",
                "type": "cloud-metadata",
                "host_ip": "",
            })

        return findings

    def _parse_prowler(self, text: str) -> list[dict]:
        findings = []
        try:
            data = json.loads(text) if text.strip().startswith("[") else None
        except json.JSONDecodeError:
            data = None

        if data:
            for item in data:
                if not isinstance(item, dict):
                    continue
                status = item.get("Status", item.get("status", ""))
                if status.upper() in ("FAIL", "CRITICAL", "HIGH"):
                    sev = "critical" if status.upper() == "CRITICAL" else "high"
                    findings.append({
                        "title": item.get("CheckTitle", item.get("title", "Prowler finding")),
                        "description": item.get("Description", item.get("description", "")),
                        "evidence": item.get("ResourceId", item.get("resource_id", "")),
                        "severity": sev,
                        "type": "cloud-prowler",
                        "host_ip": "",
                    })
        else:
            # Text output
            for m in re.finditer(r"(FAIL|CRITICAL).*\[([^\]]+)\].*:(.*)", text):
                findings.append({
                    "title": m.group(2).strip(),
                    "description": m.group(3).strip(),
                    "evidence": m.group(0)[:200],
                    "severity": "critical" if m.group(1) == "CRITICAL" else "high",
                    "type": "cloud-prowler",
                    "host_ip": "",
                })

        return findings

    def _parse_scoutsuite(self, text: str) -> list[dict]:
        findings = []
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return findings

        def walk(obj, path=""):
            if isinstance(obj, dict):
                if obj.get("level") in ("danger", "warning") and obj.get("items"):
                    sev = "critical" if obj["level"] == "danger" else "high"
                    findings.append({
                        "title": obj.get("description", path),
                        "description": obj.get("rationale", ""),
                        "evidence": f"Affected items: {len(obj['items'])}",
                        "severity": sev,
                        "type": "cloud-scoutsuite",
                        "host_ip": "",
                    })
                for k, v in obj.items():
                    walk(v, f"{path}.{k}")
            elif isinstance(obj, list):
                for i in obj:
                    walk(i, path)

        walk(data)
        return findings[:50]
