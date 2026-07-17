# 🛡️ Trinetra

<p align="center">
  <b>Professional GUI dashboard for Nessus credentialed-scan validation, authentication coverage, failed credential evidence, and client-ready reporting.</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Nessus-Credential%20Validation-00A676?style=for-the-badge" />
  <img src="https://img.shields.io/badge/GUI-Tkinter%20Dashboard-2563EB?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Reports-Excel%20%7C%20CSV%20%7C%20PDF-F97316?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Author-Sleeping%20Bhudda-8B5CF6?style=for-the-badge" />
</p>

---

**Search keywords:** Nessus credentialed scan, Nessus CA scan, credential assurance, authentication validation, failed credentials, partial authentication, vulnerability assessment, VAPT reporting, Nessus Excel report, Nessus PDF report, security dashboard.

---

## 📌 About the Application

**Trinetra** is a Python-based desktop GUI application that helps security engineers and VAPT teams quickly validate whether Nessus credentialed scans were successful or not.

The tool connects to Nessus using API keys, loads available scan folders and scans, exports the selected scan result as a temporary CSV, parses authentication-related plugins, and shows a clean dashboard before exporting final evidence reports.

It is useful when you need to answer questions like:

- Which hosts were scanned with valid credentials?
- Which hosts failed authentication?
- Which hosts had partial authentication or insufficient privilege?
- Which targets were configured but not reachable in the scan result?
- What is the exact Nessus plugin evidence behind the authentication status?
- What remediation action should be taken for failed or partial authentication?

---

## ✨ Key Features

| Feature | Description |
|---|---|
| 🔐 Local Login | First launch creates a local admin login. Password is stored as a salted hash in the user profile, not inside the repository. |
| 🌐 Nessus API Connection | Connects to Nessus using Access Key and Secret Key. |
| 📁 Folder & Scan Browser | Loads Nessus folders and scans in a GUI table. |
| 🕒 Scan History Selection | Allows selection of latest/default or historical scan result. |
| 📊 Dashboard View | Shows total IPs, passed auth, failed auth, partial auth, no credentials, not reachable, unknown, coverage %, and success %. |
| 🔎 Host-Level Drilldown | Displays host status with plugin IDs, evidence reason, protocol status, and recommendation. |
| 🧩 Protocol Breakdown | Groups authentication status by protocol such as SSH, SMB, WMI, WinRM, SNMP, DB, vCenter/ESXi, and more. |
| 📄 Offline CSV Mode | Can load an already exported Nessus CSV without connecting to API. |
| 📤 Export Options | Exports Excel dashboard, PDF summary, and CSV bundle. |
| 🌙 Dark Mode | Modern dark/light GUI theme support. |

---

## 🧠 How It Works

```text
User Login
   ↓
Enter Nessus URL + API Keys
   ↓
Load Nessus Folders and Scans
   ↓
Select Folder → Select Scan → Select Scan History
   ↓
Tool fetches scan details from Nessus API
   ↓
Tool exports temporary Nessus CSV
   ↓
CSV is parsed for authentication-related plugin IDs
   ↓
Authentication status is calculated per protocol
   ↓
Final host status is calculated
   ↓
Dashboard, charts, tables, and reports are generated
```

---

## 🧪 Authentication Status Logic

The tool uses Nessus plugin evidence to classify each host into mutually exclusive states.

| Status | Meaning | Common Evidence |
|---|---|---|
| ✅ `PASS` | Authentication was successful | Valid credential plugins or `Credentialed checks: yes` |
| ❌ `FAIL` | Authentication failed | Wrong password, failed login, database auth failure |
| ⚠️ `PARTIAL` | Login worked but with issue | Insufficient privilege, intermittent failure, incomplete Windows checks |
| 🔑 `NOCREDS` | No credentials were provided | Scan policy did not include credentials |
| 🚫 `NOT_REACHABLE` | Target was configured but did not appear in result | Target missing from scan inventory / CSV |
| ❔ `UNKNOWN` | No clear auth evidence found | Missing, ambiguous, or unsupported plugin evidence |

---

## 🔍 Supported Evidence Plugins

| Category | Plugin IDs |
|---|---|
| PASS | `141118`, `110095`, `122502`, `117887`, `19506` with `Credentialed checks: yes` |
| FAIL | `104410`, `122503`, `91822` |
| PARTIAL | `110385`, `117885`, `24786` |
| NOCREDS | `110723` |
| UNKNOWN / Ambiguous | `117886`, `21745`, `110695` |

---

## 📊 Dashboard Metrics

The dashboard displays:

- **Total IPs**
- **Auth Passed**
- **Auth Failed**
- **Partial Auth**
- **No Credentials**
- **Not Reachable**
- **Unknown**
- **Credential Coverage %**
- **Auth Success %**
- **Raw Rows Parsed**
- **Total Auth Findings**

---

## 📁 Report Outputs

### Excel Report

The Excel report contains:

- Dashboard summary
- Authentication status chart
- Top authentication issue chart
- Host status sheet
- Protocol status sheet
- Raw authentication findings sheet
- Status-wise sheets for pass/fail/partial/no-credentials/not-reachable/unknown hosts
- Notes sheet

### CSV Bundle

The CSV bundle includes:

```text
host_status.csv
protocol_status.csv
auth_findings.csv
pass_hosts.csv
fail_hosts.csv
partial_hosts.csv
nocreds_hosts.csv
not_reachable_hosts.csv
unknown_hosts.csv
summary.json
```

### PDF Report

The PDF report includes:

- Summary metrics
- Notes
- Authentication status pie chart
- Top authentication issues chart
- First set of non-pass hosts with reasons

---

## 🖥️ GUI Options

The application provides the following main options:

| Option | Purpose |
|---|---|
| Base URL | Nessus URL, for example `https://127.0.0.1:8834` |
| Access Key | Nessus API access key |
| Secret Key | Nessus API secret key |
| Verify TLS | Enable this for valid certificates; disable for self-signed Nessus certificates |
| Test / Load Folders | Connect to Nessus and load folders/scans |
| Offline: Load CSV | Analyze an existing Nessus CSV export without API connection |
| Build Dashboard | Export selected scan temporarily and build dashboard |
| Export Excel | Save Excel evidence report |
| Export PDF | Save PDF summary report |
| Export CSV Bundle | Save all CSV evidence files |
| Copy Failed IPs | Copy failed hosts for quick retesting or remediation |

---

## ⚙️ Installation

### Kali / Ubuntu

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-tk
python3 -m pip install requests openpyxl matplotlib
```

### Windows

Install Python 3, then run:

```powershell
pip install requests openpyxl matplotlib
```

---

## 🚀 How to Run

### Linux / Kali

```bash
git clone https://github.com/ArupSEK/Nessus_tool.git
cd Nessus_tool
python3 trinetra_gui.py
```

### Windows

```powershell
git clone https://github.com/ArupSEK/Nessus_tool.git
cd Nessus_tool
python trinetra_gui.py
```

---

## 🔐 First Launch Login

On first launch, the application asks you to create a local admin login.

The login is used only for local access control.

```text
Password storage: salted hash
Location: user profile
Repository storage: no password stored in repo
```

---

## 🌐 Nessus API Requirements

You need a Nessus API Access Key and Secret Key with permission to:

- View scans
- View scan folders
- View scan history
- Export scan result CSV

For standalone Nessus, the base URL usually looks like:

```text
https://<nessus-ip>:8834
```

Example:

```text
https://127.0.0.1:8834
```

If your Nessus uses a self-signed certificate, uncheck **Verify TLS** in the GUI.

---

## 🧾 Final Use Case

This tool is best for VAPT and vulnerability management teams who need a professional answer for:

```text
How many assets were scanned with valid credentials?
How many failed authentication?
Why did authentication fail?
Which hosts need credential correction or privilege review?
Which assets were not reachable during scan?
Can we export client-ready evidence?
```

---

## 🛠️ Troubleshooting

| Issue | Solution |
|---|---|
| Tkinter error | Install `python3-tk` on Linux/Kali. |
| SSL certificate error | Uncheck **Verify TLS** for self-signed Nessus certificate. |
| API 401 error | Check Access Key and Secret Key. |
| API 403 error | API user does not have required scan permission. |
| CSV export timeout | Check scan size, Nessus load, and network connectivity. |
| Empty dashboard | Confirm selected scan has completed results and exportable data. |
| Unknown status count is high | Use plugin evidence / raw findings tab to confirm whether auth plugins are missing. |

---

## ⚠️ Security Notes

- Do not commit Nessus API keys to GitHub.
- Do not share exported reports publicly.
- Treat scan data as sensitive internal security evidence.
- Use least-privilege API keys where possible.
- Review failed/partial authentication before marking a scan as complete.

---

## 👤 Author

**Sleeping Bhudda**

Built for Trinetra-powered Nessus authentication validation, VAPT evidence reporting, and professional credential scan assurance.
