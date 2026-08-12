 # SIEM-Alert-Triage-with-ELK-Stack
 # Objective
 Centralize logs from a victim host into a SIEM (Elasticsearch + Kibana + Filebeat), simulate an attack, detect it through log analysis, build an automated alert rule, and triage the resulting alert — replicating a real SOC analyst workflow from log ingestion to incident write-up.
 # Environment
 | Role    | Host name     |   Tool stack
 | :---:      | :---:      | :---:
 | Attacker  | Paull-attacker-kali | Kali linux, Hydra.
 | Victim | paull-analyst | Ubuntu servver, OpenSSH, Filebeat
 | Siem | paull - sensor | Ubuntu server, ElasticSearch, kibana 
  * Note - All three VMs run in VMware Workstation on an isolated internal network. Private IP ranges shown in screenshots are lab-only and safe to publish.

    # Architecture
    [Kali - Attacker] --SSH brute force--> [Ubuntu-Victim] --Filebeat--> [Elasticsearch/Kibana - SIEM]

    # Setup Summary
  1. Elasticsearch + Kibana installed on the SIEM host, configured for single-node operation with xpack.security enabled (username/password auth) and server.host: 0.0.0.0 to allow remote access.

2. Filebeat installed on the victim host, configured with a filestream input (Filebeat 9.x deprecated the legacy log input type) shipping /var/log/auth.log and /var/log/syslog to Elasticsearch
Note: logs land in Elasticsearch as unparsed text in the message field (the Filebeat system module, which extracts structured fields like source.ip, was not yet enabled at this stage — however as i continue to use ELK i will keep improving my SIEM so as to replicate a standard SOC SIEM setup).   
 
# Attack Simulation 
Tool: Hydra: Command  - ```hydra -l hrstaff1 -P <wordlist>.txt ssh://192.168.142.138```
This generated a burst of authentication attempts against the victim's SSH service, visible in Kibana Discover within seconds of execution. 
![Hydra brute-force successful](hydra-ssh-attack.png)
# Detection - Kibana Discover 
Query used to isolate brute-force activity: ```message: "failed password"```.

 sample raw log entry:
paull-analyst sshd[6464]: Failed password for hrstaff1 from 192.168.142.139 port 40438 ssh2.

Both Failed password  and a single Accepted password entry were visible, confirming the tool eventually succeeded once it reached the correct credential in the wordlist — mirroring what a real brute-force compromise looks like in logs.
![failed & accepted password detected in ELK log stash](ELK-log-failed-password.png)
![failed & accepted password detected in ELK log stash](ELK-log-accepted-password.png)


# Alert Rule
Built as a native Kibana Elasticsearch query rule (Stack Management → Rules and Connectors):

| Setting   |  Value |
| :---: | :---: |
Rule type	 | Elasticsearch query
Data view | 	filebeat-*
Query |	message: "Failed password"
Threshold | 	count() IS ABOVE 5
Time window	 | 1 minute
Check frequency	 | Every 1 minute

Actions	None configured (no notification connector in lab environment)

Conceptual logic:
IF count(Failed password) > 5 WITHIN 60 seconds
THEN raise alert "Possible SSH Brute Force"
SEVERITY = Medium
![Alert rule setup page](Alert-rule-setup.png)

The rule was validated by re-running Hydra and confirming the rule's test query returned a non-zero match count, then confirming an alert instance appeared under Alerts and Insights → Alerts.
![Alert detected in ELK](Alert-detected.png)
