#1# Changed applied en sheet:
https://docs.google.com/spreadsheets/d/12LM8qsuKH31jNMHAoNIGHQhFTfcSCXYy/edit?gid=848248435#gid=848248435


#2# deleted firewalls and security controls (will be covered by Sentinel)

18.10.43.10.1 (L1) Ensure 'Configure real-time protection and Security Intelligence Updates during OOBE' is set to 'Enabled'
18.10.43.10.2 (L1) Ensure 'Scan all downloaded files and attachments' is set to 'Enabled'
18.10.43.10.3 (L1) Ensure 'Turn off real-time protection' is set to 'Disabled'
18.10.43.10.4 (L1) Ensure 'Turn on behavior monitoring' is set to 'Enabled'
18.10.43.10.5 (L1) Ensure 'Turn on script scanning' is set to 'Enabled'
18.10.43.11.1.1.2 (L1) Ensure 'Configure Remote Encryption Protection Mode' is set to 'Enabled: Audit' or higher
18.10.43.13.1 (L1) Ensure 'Scan excluded files and directories during quick scans' is set to 'Enabled: 1'
18.10.43.13.2 (L1) Ensure 'Scan packed executables' is set to 'Enabled'
18.10.43.13.3 (L1) Ensure 'Scan removable drives' is set to 'Enabled'
18.10.43.13.4 (L1) Ensure 'Trigger a quick scan after X days without any scans' is set to 'Enabled: 7'
18.10.43.13.5 (L1) Ensure 'Turn on e-mail scanning' is set to 'Enabled'
18.10.43.16 (L1) Ensure 'Configure detection for potentially unwanted applications' is set to 'Enabled: Block'
18.10.43.17 (L1) Ensure 'Control whether exclusions are visible to local users' is set to 'Enabled'
18.10.43.4.1 (L1) Ensure 'Enable EDR in block mode' is set to 'Enabled'
18.10.43.5.1 (L1) Ensure 'Configure local setting override for reporting to Microsoft MAPS' is set to 'Disabled'
18.10.43.6.1.1 (L1) Ensure 'Configure Attack Surface Reduction rules' is set to 'Enabled'
18.10.43.6.1.2 (L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured
18.10.43.6.3.1 (L1) Ensure 'Prevent users and apps from accessing dangerous websites' is set to 'Enabled: Block'
18.10.43.7.1 (L1) Ensure 'Enable file hash computation feature' is set to 'Enabled'
9.1.1 (L1) Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'
9.1.2 (L1) Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'
9.1.3 (L1) Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'
9.1.4 (L1) Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\domainfw.log'
9.1.5 (L1) Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater'
9.1.6 (L1) Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'
9.1.7 (L1) Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'
9.2.1 (L1) Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'
9.2.2 (L1) Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'
9.2.3 (L1) Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'
9.2.4 (L1) Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\privatefw.log'
9.2.5 (L1) Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'
9.2.6 (L1) Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'
9.2.7 (L1) Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'
9.3.1 (L1) Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'
9.3.2 (L1) Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'
9.3.3 (L1) Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No'
9.3.4 (L1) Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'
9.3.5 (L1) Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'
9.3.6 (L1) Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\publicfw.log'
9.3.7 (L1) Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'
9.3.8 (L1) Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'
9.3.9 (L1) Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'



#3# Modification of controls:

2.2.11 (L1) Ensure 'Back up files and directories' is set to 'Administrators'
2.2.46 (L1) Ensure 'Restore files and directories' is set to 'Administrators'

Include Backup Operators in the groups to check


#4# Added maintenance for Active Directory users and groups based on variables to handled multiple languages, currently covered:
english, spanish, french, german