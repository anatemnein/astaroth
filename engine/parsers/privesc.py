import re

# (pattern, title, description, severity, type)
_WINPEAS_CHECKS = [
    (r"SeImpersonatePrivilege\s+\w+\s+Enabled",
     "SeImpersonatePrivilege Enabled",
     "Token impersonation available — JuicyPotato/PrintSpoofer/GodPotato applicable if service/IIS context",
     "critical", "windows-privesc"),
    (r"SeDebugPrivilege\s+\w+\s+Enabled",
     "SeDebugPrivilege Enabled",
     "Debug privilege — dump LSASS, inject into privileged processes",
     "critical", "windows-privesc"),
    (r"SeBackupPrivilege\s+\w+\s+Enabled",
     "SeBackupPrivilege Enabled",
     "Backup privilege — read SAM/SYSTEM, extract hashes offline",
     "high", "windows-privesc"),
    (r"AlwaysInstallElevated.*1|AlwaysInstallElevated.*Enabled",
     "AlwaysInstallElevated",
     "MSI installs run as SYSTEM — craft malicious .msi for privilege escalation",
     "critical", "windows-privesc"),
    (r"Unquoted Service Path.*[A-Z]:\\",
     "Unquoted Service Path",
     "Service binary path unquoted with spaces — plant DLL or binary in earlier path component",
     "high", "windows-privesc"),
    (r"NT AUTHORITY\\SYSTEM.*icacls|Everyone.*FullControl.*\.exe",
     "Writable Service Binary",
     "Service binary writable by current user — replace binary for SYSTEM execution",
     "critical", "windows-privesc"),
    (r"AutoLogon.*Password|DefaultPassword",
     "AutoLogon Credentials in Registry",
     "Cleartext credentials in registry AutoLogon keys",
     "high", "credentials"),
    (r"SAM.*Backup|SYSTEM.*Backup|RegSaveKey.*SAM",
     "SAM/SYSTEM Backup Accessible",
     "SAM or SYSTEM hive accessible — extract local hashes",
     "critical", "credentials"),
    (r"Credential Manager|Windows Vault|CredEnumerateW",
     "Windows Credential Manager",
     "Credentials stored in Windows Credential Manager — enumerate with cmdkey",
     "medium", "credentials"),
    (r"Modifiable.*Scheduled Task|WriteDACL.*Task",
     "Writable Scheduled Task",
     "Scheduled task writable — modify to execute arbitrary code",
     "high", "windows-privesc"),
    (r"DLL Hijacking|Missing DLL|LoadDll",
     "DLL Hijacking Opportunity",
     "Service or application loads missing DLL from user-writable path",
     "high", "windows-privesc"),
]

_LINPEAS_CHECKS = [
    (r"SUID.*root|SUID files",
     "SUID Binaries (root-owned)",
     "SUID binaries run as owner — check GTFOBins for privilege escalation",
     "high", "linux-privesc"),
    (r"sudo.*NOPASSWD|NOPASSWD.*sudo",
     "Sudo NOPASSWD",
     "User can run commands as root without password — check for GTFOBins escape",
     "critical", "linux-privesc"),
    (r"(ALL.*NOPASSWD|sudo -l.*NOPASSWD)",
     "Full sudo without password",
     "User has unrestricted root sudo — trivial privilege escalation",
     "critical", "linux-privesc"),
    (r"crontab|/etc/cron\.",
     "Cron Job Found",
     "Cron job running as privileged user — check for writable scripts or PATH abuse",
     "medium", "linux-privesc"),
    (r"cap_setuid|cap_sys_admin|cap_dac_read_search",
     "Dangerous Linux Capability",
     "Capability allows privilege escalation — check GTFOBins for the binary",
     "critical", "linux-privesc"),
    (r"readable.*shadow|shadow.*readable",
     "/etc/shadow Readable",
     "Shadow file readable — extract and crack hashes",
     "critical", "credentials"),
    (r"Writable.*passwd|/etc/passwd.*writable",
     "/etc/passwd Writable",
     "/etc/passwd writable — add root user directly",
     "critical", "linux-privesc"),
    (r"NFS.*no_root_squash|no_root_squash",
     "NFS no_root_squash",
     "NFS share without root squash — mount and write SUID binary as local root",
     "critical", "linux-privesc"),
    (r"Docker group|lxd group|disk group",
     "Privileged Group Membership",
     "User in docker/lxd/disk group — trivial privilege escalation to root",
     "critical", "linux-privesc"),
    (r"password.*=.*['\"]|PASSWORD.*=|passwd.*=",
     "Hardcoded Credentials in Config",
     "Plaintext credentials found in configuration files",
     "high", "credentials"),
    (r"\.ssh/id_rsa|\.ssh/id_ecdsa|\.ssh/id_ed25519",
     "SSH Private Key Found",
     "SSH private key accessible — attempt lateral movement with key",
     "high", "credentials"),
]


class PrivescParser:
    name = "privesc"

    def confidence(self, text: str) -> float:
        if re.search(r"WINPEAS|winPEAS|WinPEAS", text):
            return 0.95
        if re.search(r"LINPEAS|linPEAS|LinPEAS", text):
            return 0.95
        if re.search(r"SeImpersonatePrivilege|SeDebugPrivilege|AlwaysInstallElevated", text):
            return 0.85
        if re.search(r"SUID.*root|sudo -l|cap_setuid|/etc/shadow", text):
            return 0.85
        return 0.0

    def parse(self, text: str) -> dict:
        findings = []
        is_windows = bool(re.search(r"WINPEAS|SeImpersonatePrivilege|AlwaysInstallElevated|Windows|NTLM", text, re.IGNORECASE))
        checks = _WINPEAS_CHECKS if is_windows else _LINPEAS_CHECKS

        for pattern, title, desc, sev, ftype in checks:
            if re.search(pattern, text, re.IGNORECASE):
                # Capture a line of evidence
                m = re.search(r".{0,60}" + pattern + r".{0,60}", text, re.IGNORECASE)
                evidence = m.group(0).strip() if m else ""
                findings.append({
                    "title": title,
                    "description": desc,
                    "evidence": evidence,
                    "severity": sev,
                    "type": ftype,
                    "host_ip": "",
                })

        return {"hosts": [], "credentials": [], "findings": findings}
