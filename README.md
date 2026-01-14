# 🛡️ Whoami-Command-Detected-in-Request-Body
SOC Analyst Investigation Report


> Platform: LetsDefend.io  
> Role: SOC Analyst  
> Focus: Detection, Analysis, and Response  


## 📌 Alert Overview

- Alert Name: SOC168 - Whoami Command Detected in Request Body
- Alert Source: LetsDefend.io  
- Alert / Case ID: 118
- Severity: High  
- Date & Time Detected: Feb, 28, 2022, 04:12 AM
- Analyst: Jose Sanchez

Hostname: WebServer1004  
Destination IP Address: 172.16.17.16  
Source IP Address: 61.177.172.87  
HTTP Request Method: POST  
Requested URL: https://172.16.17.16/video/  
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)  
Alert Trigger Reason: Request Body contains `whoami` string  
Device Action: Permitted  

---


## 📝 Initial Alert Summary

This alert was triggered because the HTTP request body contained the string `whoami`, which is a common command used by attackers to identify user permissions and system information on the server.  

I filtered the logs in the Log Management section for the destination IP `172.16.17.16` and observed that this request came from `61.177.172.87`.  


Feb 28, 2022 4:13 AM 

<img width="1562" height="816" alt="image" src="https://github.com/user-attachments/assets/9ac99770-cd30-42d3-9de3-b1eafbcc4ad1" />

A follow-up POST request containing the parameter c=ls was observed, indicating the attacker's progression from command execution testing to filesystem enumeration. The request was permitted and returned an HTTP 200 response, significantly increasing the likelihood of successful command injection. This activity represents active exploitation and poses a high risk of remote code execution.

Feb 28, 2022 4:14 AM 

<img width="1542" height="690" alt="image" src="https://github.com/user-attachments/assets/b96719de-8e30-4abf-9cfc-5bb21a1bcbc1" />

The "?c=cat /etc/passwd" query string indicates the attacker attempted to read the system's password file. The request succeeded and returned an HTTP 200 response. 



Feb 28, 2022 4:15 AM 

<img width="1520" height="648" alt="image" src="https://github.com/user-attachments/assets/13030355-7cca-4812-942b-f04c9bfbd54f" />



A POST request containing c=cat /etc/shadow was observed, indicating an attempt to access sensitive credential storage on the OS system. This activity represents a critical escalation in the attack lifecycle and suggests potential root‑level command execution. The request was permitted and returned an HTTP 200 response. 


I went to VirusTotal and searched for the source IP Address `61.177.172.87.`

<img width="1684" height="596" alt="image" src="https://github.com/user-attachments/assets/6195a9ad-bfbb-429a-bae3-875dffc76a43" />


I then went to AlienVault and found that it had a history of Honeypot and brute force.

<img width="1848" height="884" alt="image" src="https://github.com/user-attachments/assets/843c0d76-44e1-4822-9ff3-d3f3a17897cb" />

---

## 🚩 Indicators of Compromise (IOCs)

### 🌐 Network Indicators
- **Source IP(s):**  
  - `61.177.172.87`
- **Destination IP(s):**  
  - `172.16.17.16`
- **Ports / Protocols:**  
  - HTTP / HTTPS default port (`80`/`443` if known)

In the Endpoint Security section, I looked at the command line history via "Terminal History". I found the same commands used in the Processes Parameters in the CMD History, and they were commanded by 'USER: root.'

<img width="1818" height="868" alt="image" src="https://github.com/user-attachments/assets/518f271c-67a3-4dcf-ba8f-b7ef9a9f66ba" />


This indicates that the commands and the attack were successful. 
We must contain this endpoint to prevent further damage to our servers. 

<img width="1322" height="456" alt="image" src="https://github.com/user-attachments/assets/4d1e83c2-add3-40a4-accd-f57882a8d1b8" />

<img width="1514" height="310" alt="image" src="https://github.com/user-attachments/assets/7b181595-eb94-4a3f-8a62-9aa424bdea19" />


Now I can start the playbook. 

<img width="1106" height="306" alt="image" src="https://github.com/user-attachments/assets/b40aae82-d337-47a7-90f7-3468bbd2101f" />


I then input my artifacts. 
<img width="610" height="446" alt="image" src="https://github.com/user-attachments/assets/acdae435-b0f9-4612-a5da-ee9d5d7e50f2" />

Then I added my notes. 

<img width="760" height="578" alt="image" src="https://github.com/user-attachments/assets/f0bd3f88-f2a9-4162-9223-93cad1c38a84" />

I then closed the alert indicates the commands used in the attack were sucessful and we must contain this endpoint to prevent further damage to our servers. 

<img width="1620" height="448" alt="image" src="https://github.com/user-attachments/assets/69a142ac-d05d-4a3e-827c-fe75f0ce2c3d" />



Since the reason for triggering the alert is the word "whoami" in the Request Body, we must first determine whether it is triggered correctly.
We enter the Log Management page and filter by the source IP address from the search field, and reach the relevant request.
When the Request Body is examined, it is seen that the attacker actually sent the whoami command.
When other requests are examined, we see that the attacker is running more than one command.
We can understand whether the attack was successful by looking at the Command History of the device named WebServer1004 on the Endpoint Security page.
Command History shows all commands executed by the attacker. This indicates that the commands were executed successfully.
The device must be contained. It is a True Positive alert.


### Recommended Remediation Steps

1) Immediate Application Hardening

Sanitize and validate all user input

Ensure all request parameters (including POST bodies) are properly validated using allowlists.


2) Eliminate Direct OS Command Execution in Web Applications

Refactor application logic to avoid calling system commands (exec, system, shell_exec, etc.).

If OS interaction is unavoidable, use secure APIs or libraries that do not invoke a shell.

3) Deploy and Tune a Web Application Firewall (WAF)

Enable WAF rules to block:

Command keywords (whoami, ls, cat, uname)

Suspicious POST parameters (e.g., c=)

Enable rate-limiting and bot detection.
