# AV-ePo
This will give a baseline as SecMon to monitor alert that may crucial on your asset once AV agent installed on your asset or HVA. This entry used ePo logs that forwarded to your SIEM.

*** File infected. undetermined clean error delete failed [EID 1284] ***
** Multiple malicious files foundmon the single machine. But AV failed to delete and need on-demand scan as paer of remediations process ** 
sourcetype=epo* event_description="File infected.  Undetermined clean error, delete failed" 
| bucket _time span=1d
| stats  values(detected_timestamp) as TimeStamp, values(event_description) as Event_Desc, values(category) as Category, values(severity) as Severity, values(signature) as Signature, values(threat_type) as ThreatType, values(file_name) as InfectedFile, values(logon_user) as UserName, count(file_name) as Total_files by dest_nt_host  
| where  Total_files >=3  | sort  - TimeStamp
