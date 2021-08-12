---
layout: single
author_profile: true
title: CVE Collection
header:
  overlay_image: blog-cover.jpg
permalink: /cves.html
---

This page centralizes my personal collection of obtained CVE's. Proof-of-concepts may be found on my Github, exploit-db, or packetstorm pages.

You can find my personal disclosure policy on the bottom of this page.

----

### 2020  - CVE Discoveries ###

| Id | CVE ID | Category  |
|:---|:--------|--------:|
| 11 | [CVE-2020-12122](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CCVE-2020-12122) | DLL hijacking
| 10 | [CVE-2020-12121](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-12121) | Max Secure Max Spyware Detector DOS|
| 9 | [CVE-2020-10234](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10234) | Undisclosed [error]|
| 8 | [CVE-2020-9453](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-9014) | Epson EMPNSA.sys IOCTL corruption(DOS)|
| 7 | [CVE-2020-9014](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-9014) | Epson EMPMAU.sys IOCTL corruption (DOS)|
| 6 | [CVE-2020-5511](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-5511) | PHPGurukul Small CRM v2.0  SQL Injection |
| 5 | [CVE-2020-5510](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-5510) | PHPGurukul Hostel Management System v2.0 SQL Injection |
| 4 | [CVE-2020-5509](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-5509) | PHPGurukul Car Rental Project v1.0 Remote Code Execution|
| 3 | [CVE-2020-5193](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-5193) | PHPGurukul Hospital Management System Reflected XSS |
| 2 | [CVE-2020-5192](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-5192) | PHPGurukul Hospital Management System Multiple SQL Injection's |
| 1 | [CVE-2020-5183](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-5183) | FTPGetter Professional 5.97.0.223 memory corruption |

### 2019 - CVE Discoveries ###

| Id | CVE ID | Info  |
|:---|:--------|--------:|
| 6 | [CVE-2019-19978](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-19978) | Reflected XSS |
| 5 | [CVE-2019-17181](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17181) | IntraSrv 1.0 Remote SEH Buffer Overflow |
| 4 | [CVE-2019-16724](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16724) | File Sharing Wizard 1.5.0 Remote SEH Buffer Overflow |
| 3 | [CVE-2019-13066](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-13066) | Sahi Pro 8.0.0 Multiple Reflected XSS |
| 2 | [CVE-2019-13065](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-13065) | Reflected XSS |
| 1 | [CVE-2019-13064](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-13064) | Reflected XSS |


----

### Vendor Vulnerability Reporting and Disclosure Policy

This policy sets for the reporting and disclosure policy that FullPwn Operations follows when handling a disclosure case with a vendor. If a vulnerability is discovered within a vendor product, the vendor will be contacted via email with details and a security report about the details of the vulnerability and the proper mitigation strategy that the vendor may take to patch the application.

This vulnerability disclosure policy is similar to the [CERT](https://vuls.cert.org/confluence/display/Wiki/Vulnerability+Disclosure+Policy) disclosure policy of 45 days.

The following steps will be taken if a vulnerability is disclosed to a vendor.

|  | Actions to be Taken by FullPwn Operations |
|:---|:--------|
| Day 0 | - Intial vendor contact |
| Day 7 | - Second vendor contact if no original response |
| Day 14 | - If the vendor has not responded or has stopped responding, within 10 days full disclosure notice |
| Day 45 | - Full public disclosure if the vendor hasn't responded | 

If a vendor is interested in extending or working with FullPwn Operations on a specific aspect of vulnerability disclosure, feel free to include that in any contact emails.
