🛡️ Wazuh SOC SIEM Lab

Suricata | YARA | ClamAV | Osquery | Cowrie | MITRE CALDERA

A complete blue-team SOC & SIEM home lab for threat detection, malware analysis, host monitoring, and attack simulation using open-source tools.

🏗️ Architecture Overview
[ Attacker / Internet ]
          |
      [ Suricata ]
      Network IDS
          |
      [ Cowrie ]
      SSH Honeypot
          |
 [ YARA / ClamAV ]
   Malware Scan
          |
     [ Osquery ]
  Host Behavior
          |
   [ Wazuh Manager ]
   SIEM + Correlation
          |
     [ Dashboard ]
   Detection & Alerts


📂 Repository Structure
.
├── install_all.sh                 # One-command full installation
├── install_wazuh_suricata.sh      # Wazuh 4.14 + Suricata integration
├── install_cowrie.sh              # Cowrie SSH honeypot
├── install_yara_clamav.sh         # Malware detection
├── install_osquery.sh             # Host telemetry
│
├── wazuh/
│   ├── config/ossec.conf          # Example Wazuh config
│   ├── rules/local_rules.xml      # Custom rules
│   └── decoders/.gitkeep
│
├── suricata/
│   ├── config/suricata.yaml       # Example config
│   └── rules/.gitkeep             # Rules generated at runtime
│
└── .gitignore                     # Ignore logs, secrets, runtime files


🚀 One-Command Installation
✅ Supported OS

Ubuntu Server 22.04 / 24.04

🔹 Install everything


git clone https://github.com/83uzzal/wazuh-soc-siem-suricata-yara-osquery-caldera-honeypot.git
cd wazuh-soc-siem-suricata-yara-osquery-caldera-honeypot
sudo chmod +x install_all.sh
sudo ./install_all.sh

⚙️ What install_all.sh Does

✔ Installs Wazuh 4.14 (All-in-One)
✔ Installs & configures Suricata IDS
✔ Integrates Suricata → Wazuh (EVE JSON)
✔ Installs YARA + ClamAV
✔ Installs Osquery
✔ Deploys Cowrie SSH Honeypot
✔ Enables services & logging
✔ Prints Dashboard URL & credentials


🔎 Important Log Locations
Wazuh

/var/ossec/logs/alerts/alerts.json
/var/ossec/logs/ossec.log

Suricata

/var/log/suricata/eve.json
/var/log/suricata/fast.log

Cowrie

/opt/cowrie/var/log/cowrie/


Osquery

/var/log/osquery/osqueryd.results.log


🧪 Use Cases

🔐 SSH brute-force detection (Cowrie + Wazuh)

🌐 Network attack detection (Suricata)

🦠 Malware detection (YARA + ClamAV)

🖥️ Host behavior monitoring (Osquery)

📊 SOC alert correlation & dashboards

🎯 MITRE ATT&CK attack simulation (CALDERA ready)


🔄 Suricata Rules Handling (Security-Safe)

Suricata rules are NOT stored in GitHub (to avoid secrets).

Rules are updated automatically during install:
sudo suricata-update

Runtime rules location:
/var/lib/suricata/rules/


⭐ Star the Repo

If this project helps you, please ⭐ star the repository!

📌 Disclaimer

This lab is for education & defensive security research only.
Do NOT deploy on production systems.



👨‍💻 Author

Md. Alamgir Hasan
Cyber Security | SOC | SIEM | Blue Team
🇧🇩 Bangladesh

🔗 GitHub: https://github.com/83uzzal
🔗 LinkedIn: https://www.linkedin.com/in/md-alamgir-hasan











