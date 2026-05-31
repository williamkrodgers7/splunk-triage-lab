# 16GB High-Efficiency Splunk Detection Lab
An optimized, resource-constrained home lab built to simulate enterprise threat detection, log analysis, and incident triage using a minimal hardware footprint.

## 🛠️ Environment Architecture & Specs
*   **Host Machine:** Windows 10 Pro / Windows 11 Pro (16 GB RAM baseline)
*   **SIEM Platform:** Splunk Enterprise (Single-Instance Node)
*   **Endpoints Monitored:** Windows 10 & Windows 11 Workstations
*   **Telemetry Agents:** Splunk Universal Forwarder + Microsoft Sysmon (System Monitor)

> **Note on Resource Optimization:** To run an enterprise-grade SIEM alongside concurrent Windows endpoints on a 16GB RAM baseline, I engineered strict data-filtering rules. By modifying `inputs.conf` and dropping noisy, low-value Event IDs at the forwarder layer, I minimized CPU/RAM serialization overhead while maintaining 100% visibility into high-fidelity security alerts.

---

## 🔍 Implemented Detection Use Cases & SPL Queries

### 1. Anti-Proxy Brute Force Detection (MITRE ATT&CK T1110)
*   **Data Source:** `WinEventLog:Security`
*   **Target Telemetry:** Event ID 4625 (An account failed to log on)
*   **Logic:** Tracks unique source IPs generating failed login attempts within a rolling window while filtering out empty properties.

```splunk
index=windows sourcetype="WinEventLog:Security" EventCode=4625 IpAddress!="-" 

| stats count, dc(IpAddress) as Unique_Proxies, values(IpAddress) as Attacking_IPs by Computer, TargetUserName 
| where Unique_Proxies > 5 OR count > 20
| sort - count
```

### 2. Active Session Token Tracker & Lateral Movement Hunter (MITRE ATT&CK T1021)
*   **Data Source:** `WinEventLog:Security`
*   **Target Telemetry:** Event ID 4624 (A successful account logon)
*   **Logic:** Isolates network logons (LogonType 3) and Remote Desktop connections (LogonType 10) while stripping out noisy automated machine accounts.

```splunk
index=windows sourcetype="WinEventLog:Security" EventCode=4624 (LogonType=3 OR LogonType=10) TargetUserName!="*\$" 

| table _time, Computer, TargetUserName, TargetLogonId, IpAddress, LogonType 
| sort - _time
```

### 3. Malicious Process Parent-Child Relationship Mapping (MITRE ATT&CK T1059)
*   **Data Source:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
*   **Target Telemetry:** Sysmon Event ID 1 (Process Creation)
*   **Logic:** Uses case-insensitive string parsing to flag command shells explicitly spawned by high-risk parent applications like Office binaries or web servers.

```splunk
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 

| eval ParentProcess=lower(mvindex(split(ParentImage, "\\"), -1)), ChildProcess=lower(mvindex(split(Image, "\\"), -1)) 
| where ParentProcess IN ("w3wp.exe", "sqlservr.exe", "winword.exe", "excel.exe") 
| table _time, Computer, ParentProcess, ChildProcess, CommandLine
```

---

## 📈 Key Technical Skills Demonstrated
*   **SIEM Administration:** Installing Splunk, managing indexes, and configuring data inputs.
*   **Endpoint Hardening:** Deploying Microsoft Sysmon and configuring Group Policies for Command-Line Process Auditing (Event ID 4688).
*   **Log Normalization:** Analyzing raw Windows event schemas and building memory-efficient Search Processing Language (SPL) queries.
*   **Resource Management:** Tuning configurations to run security monitoring pipelines under strict 16GB RAM hardware constraints.
