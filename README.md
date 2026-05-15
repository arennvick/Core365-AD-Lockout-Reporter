# Core365-AD-Lockout-Reporter
Core365 tool for Active Directory lockout troubleshooting. Pulls Event ID 4740 from the PDC emulator, identifies caller computers, and outputs a clean HTML report or email via Microsoft Graph (app-only auth).

# AD Lockout Caller Report (Event ID 4740) — HTML + Optional Email via Microsoft Graph

A PowerShell automation that helps IT teams quickly **identify the source (caller computer)** of repeated Active Directory account lockouts by parsing **Security Event ID 4740** and producing a **readable report**. [2](https://techpress.net/connect-to-microsoft-graph-powershell-using-certificate/)

✅ Generates a **modern, light-themed HTML report**  
✅ Optionally sends the report **inline in the email body** (no attachments) via **Microsoft Graph** using **certificate-based app-only authentication** [3](https://learn.microsoft.com/en-us/answers/questions/1461353/eventid-4740-events-issue)[4](https://windowstechno.com/primary-domain-controllerpdc-emulator/)  
✅ Optimized to query the **PDC Emulator** for efficient lockout processing visibility [1](https://blog.mindcore.dk/2026/02/microsoft-graph-remembered-to-restict-mail-send-application-permission-app-access-policies/)  

---

## Why this exists (real-world problem)

When users (or service accounts) keep getting locked out, the fastest path to resolution is to find **what device or system is repeatedly sending the wrong password**. Event Viewer can show this, but manually searching DC Security logs is slow and doesn’t scale when many accounts lock out.

This script automates the workflow by extracting lockout details from **Event ID 4740** and identifying the **caller computer** so you can fix the actual source (cached creds, scheduled task, service, device mail client, etc.). [2](https://techpress.net/connect-to-microsoft-graph-powershell-using-certificate/)

---

## Why we query the PDC Emulator (instead of all DCs)

Microsoft’s Active Directory specification for the **PDC Emulator FSMO role** states:

- When a logon fails at a DC due to a bad password, the DC can forward validation to the **PDC Emulator** to check the most current password.  
- **Account lockout is processed on the PDC Emulator.** [1](https://blog.mindcore.dk/2026/02/microsoft-graph-remembered-to-restict-mail-send-application-permission-app-access-policies/)  

This makes the PDC Emulator a practical starting point for lockout investigations and centralized reporting. [1](https://blog.mindcore.dk/2026/02/microsoft-graph-remembered-to-restict-mail-send-application-permission-app-access-policies/)  

> Note: In some environments, related lockout activity can also appear on other DCs depending on where authentication occurs, but the PDC Emulator remains the central lockout processing role. [1](https://blog.mindcore.dk/2026/02/microsoft-graph-remembered-to-restict-mail-send-application-permission-app-access-policies/)[6](https://graphpermissions.merill.net/permission/Mail.Send)  

---

## Features

- **Collects lockout events (4740)** from the PDC Emulator Security log. [2](https://techpress.net/connect-to-microsoft-graph-powershell-using-certificate/)  
- Extracts:
  - TimeCreated  
  - SamAccountName  
  - Domain – Caller Computer (deduplicated when both values match)  
  - DomainController  
  - EventRecordId  
- Produces:
  - **HTML report** saved alongside the script  
  - Optional **email delivery** via Microsoft Graph `/users/{id}/sendMail` [3](https://learn.microsoft.com/en-us/answers/questions/1461353/eventid-4740-events-issue)  
- Uses **email-safe inline HTML/CSS** for consistent formatting in Outlook clients.

---

## Requirements

### PowerShell / Modules
- Windows PowerShell 5.1+ or PowerShell 7+  
- **ActiveDirectory** module (RSAT) for locating the PDC Emulator (`Get-ADDomain`).  
- **Microsoft.Graph** module (only required if using `-SendEmail`). [4](https://windowstechno.com/primary-domain-controllerpdc-emulator/)  

Install Graph module (if needed):

```powershell
Install-Module Microsoft.Graph -Scope AllUsers
``
