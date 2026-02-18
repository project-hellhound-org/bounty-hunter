#  Hellhound – Modular Red Team Framework

Hellhound is a correlation-based offensive security platform designed to streamline the Red Team kill chain. It moves beyond simple scanning by providing an intelligent, context-aware engine that orchestrates reconnaissance, vulnerability assessment, and exploitation workflows through a unified command interface. 

Built for operators who require structure, visibility, and actionable intelligence, Hellhound transforms raw data into correlated attack paths. 

![Hellhound Banner](Images/hellhound.png)

---

## Overview 

Modern red teaming and penetration testing often involve managing a fragmented toolset—Nmap for discovery, web scanners for fuzzing, and manual scripts for exploitation. Hellhound solves this fragmentation by acting as an Orchestration Layer. 

It provides: 
   - Unified Intelligence Correlation: Aggregating data across reconnaissance, enumeration, and exploitation phases into a single "Loot" database.
   - Context-Aware Execution: Dynamically adapting available modules based on target classification (Host vs. Web Application).
   -  Risk-Based Scoring: Automatically quantifying threat severity based on confirmed exploitation and heuristic analysis.
   -  Extensible Modularity: A plugin architecture that allows for rapid development and integration of custom capabilities.

## Design Philosophy 

Hellhound is built on the principle of Human-in-the-Loop Automation. Unlike fully automated scanners that generate noise, Hellhound empowers the operator to guide the engagement while automating the tedious aspects of data correlation and evidence collection. 
Core Architecture 
     The Engine: A Python-based core that manages state, session persistence, and inter-module communication.
     The Arsenal: A modular repository of capabilities categorized by operational phase (Recon, Web, Vuln, Exploit, Intel).
     The Loot: A structured JSON-based intelligence store that correlates findings across modules to build a comprehensive attack narrative.
     

## Operational Workflow 

Hellhound structures engagements into a logical progression: 

  - Discovery: Identifying the attack surface (Infrastructure & Web). 
  - Enumeration: Gathering deep intelligence on services and parameters. 
  - Assessment: Identifying vulnerabilities and logical flaws. 
  - Exploitation: Validating risks and gaining access. 
  - Reporting: Aggregating proof and risk scores for final delivery. 

## Capabilities 
### 1. Target-Aware Reconnaissance 

Hellhound classifies targets to optimize the attack path. 

  - Host Mode: Engages network-layer reconnaissance, service enumeration, and vulnerability mapping.
  - Web Mode: Prioritizes HTTP surface mapping, parameter discovery, and application logic analysis.
     

### 2. Automated Intelligence Correlation 

Unlike standard scanners that output linear lists, Hellhound's loot command synthesizes data. 

  - Cross-Module Linking: Findings from the Spider (e.g., a comment mentioning SQLi) are automatically flagged for analysis by the Parax module.
  - Risk Aggregation: The framework calculates a dynamic "Risk Score" based on the severity of confirmed exploits (e.g., RCE) versus potential risks (e.g., IDOR).
     

### 3. Unified Command & Control (C2) 

The interactive console provides a Metasploit-inspired interface designed for operational efficiency. 

  - Session Management: Persistent storage of engagement data and results.
  - Alias System: Rapid command execution for veteran operators.
  - Suggestion Engine: "Howl" analyzes gathered intelligence to recommend the next logical step in the kill chain.
     

##  Installation

```
# Clone the repository
git clone https://github.com/l4zz3rj0d/Hellhound-Pentest.git
cd Hellhound-Pentest

# Install Python dependencies
pip install .
pip install -r requirements.txt

# Install Go-based tools
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

## Usage
Launch Console Mode
```
hellhound console
```
Launch Hunting MOde
````
hellhound hunt <target>
````

## Hellhound Console Commands
| Command          | Description                    |                    
| ---------------- | ------------------------------ | 
| `prey <ip or domain>`        | Lock onto a target |
| `nmap`           | Run reconnaissance             |                    
| `arsenal`        | List available modules         |                    
| `equip <module>` | Select a module                |                    
| `run / strike`   | Execute module                 |                    
| `howl`           | Suggest next actions           |                    
| `loot`           | View results                   |                    
| `release`        | Exit module mode               |                    
| `auto`           | Intelligent attack chain (WIP) |                    
| `status`         | Show framework state           |                    
| `sessions`       | List previous hunts            |                    
| `clear`          | Clear screen                   |                    
| `exit`           | Exit console                   |                   


## Aliases
````
hunt → prey
use  → equip
run  → strike
ls   → arsenal
q    → exit
cls  → clear
````
## Example Workflow
````
hellhound > prey example.com
[Select target type: WEB]

hellhound > asset_recon
hellhound > dns_recon
hellhound > nmap
hellhound > stalk
hellhound > howl

hellhound > equip vhost
hellhound(vhost) > strike

hellhound > loot

````


## Sessions & Results

Each hunt creates a session:
```
hellhound/storage/<target>_<timestamp>/
```
View inside console:
```
sessions
```

## Roadmap

- Rule-based Hunting Mode

- Service-aware attack chains

- CVE correlation from Nmap output

- Automated exploit suggestions

- Report generation

- AI-assisted attack planning

## Disclaimer

This project is intended only for:

- Education

- Security research

- Authorized penetration testing

⚠️ Do NOT use against systems without explicit permission.

## Developed By

Team Hellhound
