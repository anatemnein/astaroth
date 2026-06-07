import re
import json


class ContainerParser:
    """Handles kubectl JSON, docker inspect, trivy, and k8s RBAC output."""
    name = "container"

    def confidence(self, text: str) -> float:
        t = text.strip()
        if re.search(r'"apiVersion":|"kind":\s*"(Pod|Role|ClusterRole|RoleBinding|Secret|ServiceAccount|Namespace)"', t):
            return 0.97
        if re.search(r"kubectl|kubelet|kube-apiserver|kube-system", t, re.IGNORECASE):
            return 0.9
        if t.startswith("{") or t.startswith("["):
            try:
                data = json.loads(t)
                if self._is_k8s_json(data):
                    return 0.95
                if self._is_docker_json(data):
                    return 0.92
            except (json.JSONDecodeError, ValueError):
                pass
        if re.search(r"trivy|CVE-\d{4}-\d+.*CRITICAL|image.*vulnerabilit", t, re.IGNORECASE):
            return 0.9
        if re.search(r'"HostConfig":|"NetworkMode":|"Binds":|Privileged.*true', t, re.IGNORECASE):
            return 0.88
        return 0.0

    def _is_k8s_json(self, data) -> bool:
        if isinstance(data, dict):
            return bool(data.get("apiVersion") or data.get("kind") or
                        (isinstance(data.get("items"), list) and data.get("metadata")))
        return False

    def _is_docker_json(self, data) -> bool:
        if isinstance(data, list) and data and isinstance(data[0], dict):
            return bool(data[0].get("HostConfig") or data[0].get("Config"))
        if isinstance(data, dict):
            return bool(data.get("HostConfig") or data.get("NetworkSettings"))
        return False

    def parse(self, text: str) -> dict:
        hosts, credentials, findings = [], [], []

        try:
            data = json.loads(text.strip()) if text.strip().startswith(("{", "[")) else None
        except (json.JSONDecodeError, ValueError):
            data = None

        if data:
            if self._is_k8s_json(data):
                h, c, f = self._parse_k8s(data)
                hosts += h; credentials += c; findings += f
            elif self._is_docker_json(data):
                h, c, f = self._parse_docker(data)
                hosts += h; credentials += c; findings += f

        # Trivy (can be JSON or text)
        if re.search(r"trivy|CVE-\d{4}-\d+", text, re.IGNORECASE):
            findings += self._parse_trivy(text, data)

        # Text-based kubectl output
        if not data and re.search(r"kubectl|NAME\s+READY\s+STATUS|NAMESPACE\s+NAME", text):
            findings += self._parse_kubectl_text(text)

        return {"hosts": hosts, "credentials": credentials, "findings": findings}

    def _parse_k8s(self, data) -> tuple:
        hosts, credentials, findings = [], [], []
        items = []

        if isinstance(data, dict) and data.get("items"):
            items = data["items"]
        elif isinstance(data, dict):
            items = [data]
        elif isinstance(data, list):
            items = data

        for obj in items:
            if not isinstance(obj, dict):
                continue
            kind = obj.get("kind", "")
            meta = obj.get("metadata", {})
            name = meta.get("name", "")
            namespace = meta.get("namespace", "default")
            spec = obj.get("spec", {})

            if kind == "Pod":
                h, f = self._analyze_pod(obj, name, namespace)
                hosts += h; findings += f

            elif kind in ("Role", "ClusterRole"):
                findings += self._analyze_rbac_role(obj, kind, name, namespace)

            elif kind in ("RoleBinding", "ClusterRoleBinding"):
                findings += self._analyze_rbac_binding(obj, kind, name, namespace)

            elif kind == "Secret":
                secret_type = obj.get("type", "")
                d = obj.get("data", {})
                for key, val in d.items():
                    if key in ("token", "password", "secret", ".dockerconfigjson"):
                        credentials.append({
                            "username": f"{namespace}/{name}",
                            "secret": val[:64] + ("..." if len(val) > 64 else ""),
                            "secret_type": f"k8s-secret-{secret_type or key}",
                            "domain": namespace,
                            "source": "kubectl",
                        })
                        findings.append({
                            "title": f"K8s secret readable: {namespace}/{name} ({key})",
                            "description": "Kubernetes secret data accessible — extract service account tokens, TLS certs, or app secrets",
                            "evidence": f"Secret: {namespace}/{name}, key: {key}",
                            "severity": "high",
                            "type": "k8s-secret",
                            "host_ip": "",
                        })

            elif kind == "ServiceAccount":
                automount = spec.get("automountServiceAccountToken", True)
                if automount is not False:
                    findings.append({
                        "title": f"ServiceAccount with automounted token: {namespace}/{name}",
                        "description": "Token automatically mounted into pods — compromise any pod using this SA grants its permissions",
                        "evidence": f"ServiceAccount: {namespace}/{name}",
                        "severity": "medium",
                        "type": "k8s-rbac",
                        "host_ip": "",
                    })

        return hosts, credentials, findings

    def _analyze_pod(self, obj, name, namespace) -> tuple:
        hosts, findings = [], []
        spec = obj.get("spec", {})
        containers = spec.get("containers", []) + spec.get("initContainers", [])
        node = spec.get("nodeName", "")

        for c in containers:
            sc = c.get("securityContext", {})
            pod_sc = spec.get("securityContext", {})

            if sc.get("privileged") or pod_sc.get("privileged"):
                findings.append({
                    "title": f"Privileged container: {namespace}/{name}/{c['name']}",
                    "description": "Privileged pod — full node access, host namespace abuse, cgroup escape",
                    "evidence": f"securityContext.privileged: true",
                    "severity": "critical",
                    "type": "container-escape",
                    "host_ip": node or "",
                })

            if sc.get("runAsUser") == 0 or sc.get("runAsNonRoot") is False:
                findings.append({
                    "title": f"Container running as root: {namespace}/{name}/{c['name']}",
                    "description": "Root container — escape to host if combined with other misconfigurations",
                    "evidence": "runAsUser: 0",
                    "severity": "high",
                    "type": "container-escape",
                    "host_ip": node or "",
                })

            caps = sc.get("capabilities", {})
            dangerous_caps = {"SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "SYS_MODULE", "DAC_READ_SEARCH"}
            added = set(caps.get("add", []))
            for cap in dangerous_caps & added:
                findings.append({
                    "title": f"Dangerous capability in {namespace}/{name}: {cap}",
                    "description": f"CAP_{cap} enables privilege escalation or container escape",
                    "evidence": f"capabilities.add: {cap}",
                    "severity": "critical" if cap in ("SYS_ADMIN", "SYS_MODULE") else "high",
                    "type": "container-escape",
                    "host_ip": node or "",
                })

        # Volume mounts
        for vol in spec.get("volumes", []):
            hp = vol.get("hostPath", {}).get("path", "")
            if hp in ("/", "/etc", "/var/run/docker.sock", "/proc", "/sys"):
                findings.append({
                    "title": f"Sensitive hostPath mount in {namespace}/{name}: {hp}",
                    "description": f"Host path '{hp}' mounted into pod — read/write host filesystem or escape container",
                    "evidence": f"hostPath: {hp}",
                    "severity": "critical",
                    "type": "container-escape",
                    "host_ip": node or "",
                })
            elif hp == "/var/run/docker.sock":
                findings.append({
                    "title": f"Docker socket mounted: {namespace}/{name}",
                    "description": "Docker socket in pod — spawn privileged containers, escape to host",
                    "evidence": "hostPath: /var/run/docker.sock",
                    "severity": "critical",
                    "type": "container-escape",
                    "host_ip": node or "",
                })

        if spec.get("hostNetwork"):
            findings.append({
                "title": f"Host network in pod: {namespace}/{name}",
                "description": "Pod shares host network namespace — sniff traffic, bind host ports",
                "evidence": "hostNetwork: true",
                "severity": "high",
                "type": "container-escape",
                "host_ip": node or "",
            })
        if spec.get("hostPID"):
            findings.append({
                "title": f"Host PID namespace in pod: {namespace}/{name}",
                "description": "Pod can see all host processes — signal injection, ptrace attacks",
                "evidence": "hostPID: true",
                "severity": "high",
                "type": "container-escape",
                "host_ip": node or "",
            })

        if node:
            hosts.append({"ip": node, "hostname": node, "os": "Linux (k8s node)", "services": []})

        return hosts, findings

    def _analyze_rbac_role(self, obj, kind, name, namespace) -> list:
        findings = []
        for rule in obj.get("rules", []):
            verbs = set(rule.get("verbs", []))
            resources = set(rule.get("resources", []))
            api_groups = set(rule.get("apiGroups", []))

            if "*" in verbs and "*" in resources:
                findings.append({
                    "title": f"Wildcard RBAC {kind}: {namespace}/{name}",
                    "description": "Role grants all verbs on all resources — equivalent to cluster-admin if bound to user/SA",
                    "evidence": f"verbs: *, resources: *",
                    "severity": "critical",
                    "type": "k8s-rbac",
                    "host_ip": "",
                })
            elif "secrets" in resources and ("get" in verbs or "*" in verbs):
                findings.append({
                    "title": f"RBAC allows secrets read: {kind} {namespace}/{name}",
                    "description": "Role can read secrets — access service account tokens and application credentials",
                    "evidence": f"resources: secrets, verbs: {list(verbs)}",
                    "severity": "high",
                    "type": "k8s-rbac",
                    "host_ip": "",
                })
            if "pods/exec" in resources or ("exec" in verbs and "pods" in resources):
                findings.append({
                    "title": f"RBAC allows pod exec: {kind} {namespace}/{name}",
                    "description": "Role allows kubectl exec — arbitrary code execution in any matching pod",
                    "evidence": f"resources: pods/exec",
                    "severity": "high",
                    "type": "k8s-rbac",
                    "host_ip": "",
                })

        return findings

    def _analyze_rbac_binding(self, obj, kind, name, namespace) -> list:
        findings = []
        role_ref = obj.get("roleRef", {})
        role_name = role_ref.get("name", "")
        subjects = obj.get("subjects", [])

        if role_name in ("cluster-admin", "admin", "edit"):
            for subj in subjects:
                subj_name = subj.get("name", "")
                subj_type = subj.get("kind", "")
                if subj_name in ("default", "system:anonymous", "system:unauthenticated"):
                    findings.append({
                        "title": f"Dangerous {kind}: {role_name} bound to {subj_name}",
                        "description": f"{subj_type} '{subj_name}' has {role_name} — immediate cluster compromise",
                        "evidence": f"{kind}: {name}, subject: {subj_name}",
                        "severity": "critical",
                        "type": "k8s-rbac",
                        "host_ip": "",
                    })
                elif subj_type == "ServiceAccount":
                    findings.append({
                        "title": f"ServiceAccount with {role_name}: {subj.get('namespace','')}/{subj_name}",
                        "description": f"ServiceAccount bound to {role_name} — any pod using this SA is high-value target",
                        "evidence": f"{kind}: {name}",
                        "severity": "high" if role_name != "cluster-admin" else "critical",
                        "type": "k8s-rbac",
                        "host_ip": "",
                    })

        return findings

    def _parse_docker(self, data) -> tuple:
        findings = []
        items = data if isinstance(data, list) else [data]

        for container in items:
            if not isinstance(container, dict):
                continue
            cname = container.get("Name", container.get("Id", "unknown"))
            hc = container.get("HostConfig", {})

            if hc.get("Privileged"):
                findings.append({
                    "title": f"Privileged container: {cname}",
                    "description": "Docker --privileged — full access to host devices, cgroup escape",
                    "evidence": "Privileged: true",
                    "severity": "critical",
                    "type": "container-escape",
                    "host_ip": "",
                })

            for bind in hc.get("Binds", []) or []:
                host_path = bind.split(":")[0]
                if host_path in ("/var/run/docker.sock", "/", "/etc", "/proc"):
                    findings.append({
                        "title": f"Sensitive bind mount in {cname}: {host_path}",
                        "description": f"Host path {host_path} mounted — container escape possible",
                        "evidence": f"Bind: {bind}",
                        "severity": "critical",
                        "type": "container-escape",
                        "host_ip": "",
                    })

            caps = hc.get("CapAdd", []) or []
            dangerous = {"SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "SYS_MODULE"}
            for cap in set(caps) & dangerous:
                findings.append({
                    "title": f"Dangerous capability {cap} in {cname}",
                    "description": f"CAP_{cap} present — container escape or privilege escalation vector",
                    "evidence": f"CapAdd: {cap}",
                    "severity": "critical" if cap == "SYS_ADMIN" else "high",
                    "type": "container-escape",
                    "host_ip": "",
                })

            if hc.get("NetworkMode") == "host":
                findings.append({
                    "title": f"Host network mode: {cname}",
                    "description": "Container on host network — bypass network policies, sniff host traffic",
                    "evidence": "NetworkMode: host",
                    "severity": "high",
                    "type": "container-escape",
                    "host_ip": "",
                })

        return [], [], findings

    def _parse_trivy(self, text: str, data) -> list:
        findings = []
        if data and isinstance(data, dict) and data.get("Results"):
            for result in data["Results"]:
                for vuln in result.get("Vulnerabilities", []):
                    if vuln.get("Severity") in ("CRITICAL", "HIGH"):
                        findings.append({
                            "title": f"{vuln['VulnerabilityID']}: {vuln.get('PkgName','')} {vuln.get('InstalledVersion','')}",
                            "description": vuln.get("Description", vuln.get("Title", ""))[:300],
                            "evidence": f"Fixed in: {vuln.get('FixedVersion', 'no fix')}",
                            "severity": "critical" if vuln["Severity"] == "CRITICAL" else "high",
                            "type": "cve",
                            "host_ip": "",
                        })
        else:
            for m in re.finditer(r"(CVE-\d{4}-\d+)\s+.*(CRITICAL|HIGH)\s+.*\n?.*\n?.*", text):
                findings.append({
                    "title": m.group(1),
                    "description": m.group(0)[:200],
                    "evidence": m.group(0)[:100],
                    "severity": "critical" if m.group(2) == "CRITICAL" else "high",
                    "type": "cve",
                    "host_ip": "",
                })
        return findings

    def _parse_kubectl_text(self, text: str) -> list:
        findings = []
        if re.search(r"system:anonymous|system:unauthenticated", text):
            findings.append({
                "title": "Anonymous access to Kubernetes API",
                "description": "Unauthenticated requests allowed — enumerate cluster resources without credentials",
                "evidence": "system:anonymous in RBAC subjects",
                "severity": "critical",
                "type": "k8s-rbac",
                "host_ip": "",
            })
        return findings
