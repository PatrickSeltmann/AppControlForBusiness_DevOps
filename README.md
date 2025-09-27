# AppControlForBusiness_DevOps

# App Control for Business (ACfB) – Build & Publish via Azure DevOps Pipeline or interactively

Detailed information on my blog: **[ctrlshiftenter.cloud](https://www.ctrlshiftenter.cloud/)**

This repository helps you **sign** **App Control for Business (ACfB)** policy XML files and **publish** them to **Microsoft Intune** using **Microsoft Graph**.

It works in two ways:

1. **Manual run** on your machine (interactive login).
2. **Azure DevOps pipeline** (non-interactive, uses an access token).

---

## What this does

* Finds policy XML files in `Policies/unsigned_original` (files named like `Base_*.xml` or `Supplemental_*.xml`).
* Copies them into `Policies/signed`.
* **Signs** the XML with a certificate from `Certs/`.
* Restores the **VersionEx** field (some sign tools reset it).
* Creates/updates the matching **Intune** policy through **Graph API**.

---

## Repository layout

```text
repo-root/
├─ Publish-ACFBPolicy.ps1          # Main script: sign + upload
├─ ACFB-Build-Pipeline.yml         # Azure DevOps pipeline
├─ README.md                       # This file
├─ Certs/                          # Public certs (.cer/.crt) for signing
│  ├─ org-code-sign.cer
├─ Policies/
│  ├─ unsigned_original/           # Source: unsigned XML policies
│  │  ├─ Base_MyPolicy.xml
│  │  └─ Supplemental_Allow_X.xml
│  └─ signed/                      # Output: signed XML (what gets uploaded)
```

---

## Requirements

* **PowerShell 7+** (`pwsh`).
  Check with:

  ```powershell
  $PSVersionTable.PSVersion
  ```
* **Microsoft.Graph** PowerShell (the script installs `Microsoft.Graph.Authentication` if missing).
* **Add-SignerRule** command available on the machine/agent (on `PATH` or dot-sourced).
* A **certificate** file in `Certs/` (`.cer` or `.crt`) used for signing.

  > Do **not** store private keys in the repo.

**Permissions (for Intune/Graph)**

* Scope `DeviceManagementConfiguration.ReadWrite.All`.
* In CI, the service connection must have consent to call Microsoft Graph.

---

## How to run – Manual (local)

1. Open **PowerShell 7** (type `pwsh`).
2. Run:

   ```powershell
   pwsh ./Publish-ACFBPolicy.ps1 `
     -PolicyRootDir .\Policies\unsigned_original `
     -OutputPolicyDir .\Policies\signed `
     -CertFolder .\Certs
   ```
3. You will be asked to sign in (Graph). The script will sign policies, restore `VersionEx`, and upload to Intune.

**Optional**

```powershell
# Target a specific tenant during interactive login
pwsh ./Publish-ACFBPolicy.ps1 -TenantId "00000000-0000-0000-0000-000000000000"

# Dry run (no upload and signing; shows what would happen)
pwsh ./Publish-ACFBPolicy.ps1 -DryRun
```

---

## How to run – Azure DevOps Pipeline

* Pipeline file: **`ACFB-Build-Pipeline.yml`**
* Triggers on changes under `Policies/unsigned_original/**` on branch `main`.
* Steps:

  1. Get a Microsoft Graph access token via **OIDC** (`AzureCLI@2`)
  2. Run **`Publish-ACFBPolicy.ps1`** with `-AccessToken "$(secret)"`
  3. Commit new/changed files in `Policies/signed` back to the repo (skip on PRs)

**Service connection**: must be set up with **workload identity federation (OIDC)** and allowed to get a **Microsoft Graph** token.

---

## Policy versioning (important)

* Some signing tools reset `<VersionEx>` to `10.0.0.0`. The script **restores** the original `VersionEx` from the **unsigned** source.
* Update logic:

  * **Update** if local `VersionEx` is **higher** than remote, or
  * If versions are **equal** but the **XML content** is different,
  * Otherwise **skip**.

Tip: bump `<VersionEx>` in your unsigned file when you intend to ship an update.

---

## Troubleshooting

**Script runs in pipeline but fails locally**

* Use **PowerShell 7** (`pwsh`), not Windows PowerShell 5.1.

**Graph auth errors**

* Manual: sign in with an account that has Intune/Graph rights.
* Pipeline: check the **service connection** and the **scopes/consent** for Microsoft Graph.

**Signed file shows wrong VersionEx**

* The script resets it after signing. Look for log lines:

  * `SOURCE VersionEx = 'x.y.z.w'`
  * `LOCAL  VersionEx = 'x.y.z.w'`

**No changes pushed back**

* The commit step only runs when the build **succeeds** and **not** on pull requests.
* Make sure `persistCredentials: true` is set and the build has permission to push.

---

## Security notes

* Do **not** commit private keys. Only place **public** certs (`.cer`, `.crt`) in `Certs/`.
* Keep your pipeline’s service connection scoped to what it needs.
* The access token is stored in a **masked** pipeline variable and passed only as a parameter.

---

---

## License

This project is licensed under the **GNU General Public License v3.0**.

You are free to use, modify, and distribute this software. Commercial use is allowed.
All modifications and derivative works must also be distributed under the GPLv3 license.
See `LICENSE` for details.

---

### What went wrong before?

* You opened a code fence with ```markdown at the very top and later closed with **four** backticks ```` — Markdown treated almost everything as code.
* In this fixed version, each code snippet opens and closes with **exactly three** backticks, and there are no stray fences.
