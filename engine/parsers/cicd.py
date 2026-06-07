import re
import json


# Patterns that indicate secret exposure in CI/CD
_SECRET_PATTERNS = [
    (r"GITHUB_TOKEN|GH_TOKEN",          "GitHub token"),
    (r"GITLAB_TOKEN|CI_JOB_TOKEN",      "GitLab token"),
    (r"JENKINS_USER|JENKINS_API_TOKEN", "Jenkins credential"),
    (r"AWS_ACCESS_KEY_ID|AWS_SECRET",   "AWS credential"),
    (r"AZURE_CLIENT_SECRET|ARM_CLIENT", "Azure credential"),
    (r"GOOGLE_APPLICATION_CREDENTIALS|GCLOUD_SERVICE_KEY", "GCP credential"),
    (r"DOCKER_PASSWORD|REGISTRY_PASSWORD", "Container registry credential"),
    (r"NPM_TOKEN|NPMRC_AUTH",           "npm token"),
    (r"PYPI_TOKEN|TWINE_PASSWORD",      "PyPI token"),
    (r"SONAR_TOKEN|CODECOV_TOKEN",      "Code quality token"),
    (r"DATABASE_URL|DB_PASSWORD|POSTGRES_PASSWORD|MYSQL_PASSWORD", "Database credential"),
    (r"PRIVATE_KEY|RSA_PRIVATE|SSH_PRIVATE", "Private key"),
    (r"API_KEY|API_SECRET|SECRET_KEY|AUTH_TOKEN", "Generic API key"),
    (r"SLACK_WEBHOOK|SLACK_TOKEN",      "Slack token"),
    (r"STRIPE_SECRET|SENDGRID_API_KEY", "Payment/email API key"),
]


class CICDParser:
    """Handles GitHub Actions workflows, GitLab CI, Jenkins, and env var dumps."""
    name = "cicd"

    def confidence(self, text: str) -> float:
        if re.search(r"on:\s*\[?push|jobs:\s*\n\s+\w+:|uses:\s*actions/", text):
            return 0.95  # GitHub Actions
        if re.search(r"\.gitlab-ci\.yml|stages:\s*\n|script:\s*\n|gitlab-runner", text, re.IGNORECASE):
            return 0.93  # GitLab CI
        if re.search(r"Jenkinsfile|pipeline\s*\{|agent\s+(any|none|label)|stages\s*\{", text):
            return 0.93  # Jenkins
        if re.search(r"GITHUB_ACTIONS|GITLAB_CI|CIRCLECI|TRAVIS|JENKINS_URL", text):
            return 0.9   # CI env variable dump
        if re.search(r"\$\{\{.*secrets\.|env\..*TOKEN|env\..*SECRET|env\..*PASSWORD", text):
            return 0.88
        return 0.0

    def parse(self, text: str) -> dict:
        findings = []
        credentials = []

        platform = self._detect_platform(text)

        # Secret exposure in env vars / config
        for pattern, label in _SECRET_PATTERNS:
            for m in re.finditer(rf"({pattern})\s*[=:\"]+\s*([^\s\"'\n{{}}]+)", text, re.IGNORECASE):
                val = m.group(2).strip("\"'${}").strip()
                if len(val) > 6 and val not in ("true", "false", "null", "none", "${{", "secrets."):
                    credentials.append({
                        "username": m.group(1),
                        "secret": val[:64] + ("..." if len(val) > 64 else ""),
                        "secret_type": "ci-secret",
                        "domain": platform,
                        "source": "cicd",
                    })
                    findings.append({
                        "title": f"CI/CD secret in plaintext: {m.group(1)} ({label})",
                        "description": f"{label} exposed as plain environment variable instead of secret reference",
                        "evidence": m.group(0)[:150],
                        "severity": "critical",
                        "type": "secret-exposure",
                        "host_ip": "",
                    })

        # GitHub Actions specific
        if platform == "github-actions":
            findings += self._analyze_github_actions(text)

        # GitLab CI specific
        elif platform == "gitlab-ci":
            findings += self._analyze_gitlab_ci(text)

        # Jenkins specific
        elif platform == "jenkins":
            findings += self._analyze_jenkins(text)

        # Generic CI/CD misconfigurations
        findings += self._analyze_generic(text, platform)

        return {"hosts": [], "credentials": credentials, "findings": findings}

    def _detect_platform(self, text: str) -> str:
        if re.search(r"on:\s*\[?push|github\.com|GITHUB_", text):
            return "github-actions"
        if re.search(r"\.gitlab|GITLAB_|gitlab-runner", text, re.IGNORECASE):
            return "gitlab-ci"
        if re.search(r"Jenkinsfile|JENKINS_|jenkins\.io", text, re.IGNORECASE):
            return "jenkins"
        if re.search(r"CIRCLECI|circle\.yml", text, re.IGNORECASE):
            return "circleci"
        return "ci-cd"

    def _analyze_github_actions(self, text: str) -> list:
        findings = []

        # Workflow: pull_request_target with code checkout — script injection risk
        if re.search(r"pull_request_target", text) and re.search(r"actions/checkout", text):
            findings.append({
                "title": "GitHub Actions: pull_request_target with checkout",
                "description": "pull_request_target runs with write permissions + secrets — PR from fork can inject malicious code",
                "evidence": "on: pull_request_target + actions/checkout",
                "severity": "critical",
                "type": "cicd-injection",
                "host_ip": "",
            })

        # Workflow: script injection via github.event inputs
        for m in re.finditer(r"run:.*\$\{\{\s*github\.event\.(issue|pr|pull_request|comment|review)", text):
            findings.append({
                "title": "GitHub Actions: script injection via event data",
                "description": "Workflow injects untrusted github.event data directly into run: — attacker controls input",
                "evidence": m.group(0)[:200],
                "severity": "critical",
                "type": "cicd-injection",
                "host_ip": "",
            })

        # Overly permissive permissions
        if re.search(r"permissions:\s*write-all|permissions:\s*\n\s+.*:\s*write", text):
            findings.append({
                "title": "GitHub Actions: broad write permissions",
                "description": "Workflow grants write-all or multiple write permissions — compromised step can modify repo, create releases",
                "evidence": "permissions: write-all",
                "severity": "high",
                "type": "cicd-permissions",
                "host_ip": "",
            })

        # Self-hosted runner
        if re.search(r"runs-on:\s*self-hosted", text):
            findings.append({
                "title": "GitHub Actions: self-hosted runner",
                "description": "Self-hosted runners execute on internal infrastructure — compromised workflow reaches internal network",
                "evidence": "runs-on: self-hosted",
                "severity": "high",
                "type": "cicd-runner",
                "host_ip": "",
            })

        # Secrets printed in run commands
        for m in re.finditer(r"run:.*echo.*\$\{\{\s*secrets\.", text, re.IGNORECASE):
            findings.append({
                "title": "GitHub Actions: secret echoed to logs",
                "description": "secrets.* value printed via echo — visible in public/private action logs",
                "evidence": m.group(0)[:200],
                "severity": "high",
                "type": "secret-exposure",
                "host_ip": "",
            })

        # OIDC: broad audience or missing conditions
        if re.search(r"id-token.*write|aws-actions/configure-aws-credentials|azure/login", text):
            if not re.search(r"condition:|subject:|audience:", text, re.IGNORECASE):
                findings.append({
                    "title": "GitHub Actions OIDC: missing trust conditions",
                    "description": "OIDC cloud auth without strict subject/audience conditions — any workflow in repo can assume the role",
                    "evidence": "OIDC token write permission without conditions",
                    "severity": "high",
                    "type": "cicd-oidc",
                    "host_ip": "",
                })

        return findings

    def _analyze_gitlab_ci(self, text: str) -> list:
        findings = []

        # Shared runners with sensitive variables
        if re.search(r"tags:\s*\n\s+-\s*shared", text) and re.search(r"variables:", text):
            findings.append({
                "title": "GitLab CI: sensitive variables on shared runner",
                "description": "Protected variables may be exposed on shared runners — use protected branches or specific runner tags",
                "evidence": "Shared runner tag with variables block",
                "severity": "medium",
                "type": "cicd-permissions",
                "host_ip": "",
            })

        # CI_JOB_TOKEN scope
        if re.search(r"CI_JOB_TOKEN", text) and re.search(r"curl|wget|git clone", text, re.IGNORECASE):
            findings.append({
                "title": "GitLab CI_JOB_TOKEN used in script",
                "description": "CI_JOB_TOKEN grants access to other project APIs — scope not limited by default in older GitLab versions",
                "evidence": "CI_JOB_TOKEN in curl/wget/git clone context",
                "severity": "medium",
                "type": "cicd-permissions",
                "host_ip": "",
            })

        # Script injection via variable
        for m in re.finditer(r"script:\s*\n\s+-\s*.*\$(?!\{)[A-Z_]+.*\n", text):
            findings.append({
                "title": "GitLab CI: potential script injection via unquoted variable",
                "description": "Unquoted variable in script block — attacker-controlled variable could inject commands",
                "evidence": m.group(0).strip()[:200],
                "severity": "medium",
                "type": "cicd-injection",
                "host_ip": "",
            })

        return findings

    def _analyze_jenkins(self, text: str) -> list:
        findings = []

        # Credentials printed in build log
        if re.search(r"withCredentials|credentialsId", text) and re.search(r"\becho\b|\bprint\b|\bcat\b", text):
            findings.append({
                "title": "Jenkins: credentials potentially printed to build log",
                "description": "withCredentials block contains echo/print — masked values may leak in certain log contexts",
                "evidence": "withCredentials + echo/print",
                "severity": "high",
                "type": "secret-exposure",
                "host_ip": "",
            })

        # Unauthenticated build trigger
        if re.search(r"properties.*pipelineTriggers|triggers.*pollSCM|remoteTrigger", text, re.IGNORECASE):
            findings.append({
                "title": "Jenkins: remote trigger potentially unauthenticated",
                "description": "Pipeline has remote/SCM trigger — validate authentication token is required",
                "evidence": "Remote trigger or pollSCM configured",
                "severity": "medium",
                "type": "cicd-permissions",
                "host_ip": "",
            })

        # sh/bat with credential interpolation
        for m in re.finditer(r"sh\s*['\"].*\$\{([A-Z_]+)\}.*['\"]", text):
            var = m.group(1)
            if re.search(r"PASS|SECRET|TOKEN|KEY|CRED", var):
                findings.append({
                    "title": f"Jenkins: secret interpolated in sh command: {var}",
                    "description": "Secret variable interpolated into shell string — may appear in process list or logs",
                    "evidence": m.group(0)[:200],
                    "severity": "high",
                    "type": "secret-exposure",
                    "host_ip": "",
                })

        return findings

    def _analyze_generic(self, text: str, platform: str) -> list:
        findings = []

        # Hardcoded IPs or internal hostnames
        for m in re.finditer(r"\b(10\.\d+\.\d+\.\d+|172\.1[6-9]\.\d+\.\d+|172\.2\d\.\d+\.\d+|192\.168\.\d+\.\d+)\b", text):
            ip = m.group(1)
            snippet = text[max(0, m.start()-50):m.start()+80]
            if not re.search(r"#|example|test|sample", snippet, re.IGNORECASE):
                findings.append({
                    "title": f"Internal IP hardcoded in CI/CD config: {ip}",
                    "description": "Internal network address in pipeline — reveals internal topology",
                    "evidence": snippet.strip()[:200],
                    "severity": "info",
                    "type": "info-disclosure",
                    "host_ip": ip,
                })

        # Docker images pinned to :latest
        for m in re.finditer(r"(image|FROM|uses):\s*[\w/\-\.]+:latest", text):
            findings.append({
                "title": "Unpinned :latest image in pipeline",
                "description": "Using :latest tag — supply chain attack possible if registry is compromised",
                "evidence": m.group(0)[:100],
                "severity": "medium",
                "type": "supply-chain",
                "host_ip": "",
            })

        return findings
