1) Count Aggregation

title: AWS EC2 Download Userdata
id: 26ff4080-194e-47e7-9889-ef7602efed0c
status: test
description: Detects bulk downloading of User Data associated with AWS EC2 instances. Instance User Data may include installation scripts and hard-coded secrets for deployment.
references:
    - https://github.com/RhinoSecurityLabs/pacu/blob/866376cd711666c775bbfcde0524c817f2c5b181/pacu/modules/ec2__download_userdata/main.py
author: faloker
date: 2020/02/11
modified: 2022/10/09
tags:
    - attack.exfiltration
    - attack.t1020
logsource:
    product: aws
    service: cloudtrail
detection:
    selection_source:
        eventSource: ec2.amazonaws.com
        requestParameters.attribute: userData
        eventName: DescribeInstanceAttribute
    timeframe: 30m
    condition: selection_source | count() > 10
falsepositives:
    - Assets management software like device42
level: medium
----------------------------------------
title: Potential Backup Enumeration on AWS
id: 76255e09-755e-4675-8b6b-dbce9842cd2a
status: experimental
description: Detects potential enumeration activity targeting an AWS instance backups
references:
    - https://unit42.paloaltonetworks.com/compromised-cloud-compute-credentials/
author: Janantha Marasinghe
date: 2022/12/13
modified: 2022/12/28
tags:
    - attack.discovery
    - attack.t1580
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: 'ec2.amazonaws.com'
        eventName:
            - 'GetPasswordData'
            - 'GetEbsEncryptionByDefault'
            - 'GetEbsDefaultKmsKeyId'
            - 'GetBucketReplication'
            - 'DescribeVolumes'
            - 'DescribeVolumesModifications'
            - 'DescribeSnapshotAttribute'
            - 'DescribeSnapshotTierStatus'
            - 'DescribeImages'
    timeframe: 10m
    condition: selection | count() > 5
falsepositives:
    - Unknown
level: medium
---------------------
title: Account Enumeration on AWS
id: e9c14b23-47e2-4a8b-8a63-d36618e33d70
status: test
description: Detects enumeration of accounts configuration via api call to list different instances and services within a short period of time.
author: toffeebr33k
date: 2020/11/21
modified: 2022/10/09
tags:
    - attack.discovery
    - attack.t1592
logsource:
    product: aws
    service: cloudtrail
detection:
    selection_eventname:
        eventName: list*
    timeframe: 10m
    condition: selection_eventname | count() > 50
fields:
    - userIdentity.arn
falsepositives:
    - AWS Config or other configuration scanning activities
level: low
-------------------
title: Potential Network Enumeration on AWS
id: c3d53999-4b14-4ddd-9d9b-e618c366b54d
status: experimental
description: Detects network enumeration performed on AWS.
references:
    - https://unit42.paloaltonetworks.com/compromised-cloud-compute-credentials/
author: Janantha Marasinghe
date: 2022/12/13
modified: 2022/12/28
tags:
    - attack.discovery
    - attack.t1016
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: 'ec2.amazonaws.com'
        eventName:
            - 'DescribeCarrierGateways'
            - 'DescribeVpcEndpointConnectionNotifications'
            - 'DescribeTransitGatewayMulticastDomains'
            - 'DescribeClientVpnRoutes'
            - 'DescribeDhcpOptions'
            - 'GetTransitGatewayRouteTableAssociations'
    timeframe: 10m
    condition: selection | count() > 5
falsepositives:
    - Unknown
level: low
------------------------
title: Potential Storage Enumeration on AWS
id: 4723218f-2048-41f6-bcb0-417f2d784f61
related:
    - id: f305fd62-beca-47da-ad95-7690a0620084
      type: similar
status: experimental
description: Detects potential enumeration activity targeting AWS storage
references:
    - https://unit42.paloaltonetworks.com/compromised-cloud-compute-credentials/
author: Janantha Marasinghe
date: 2022/12/13
modified: 2022/12/28
tags:
    - attack.discovery
    - attack.t1619
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: 's3.amazonaws.com'
        eventName:
            - 'ListBuckets'
            - 'GetBucketCors'
            - 'GetBucketInventoryConfiguration'
            - 'GetBucketPublicAccessBlock'
            - 'GetBucketMetricsConfiguration'
            - 'GetBucketPolicy'
            - 'GetBucketTagging'
    timeframe: 10m
    condition: selection | count() > 5
falsepositives:
    - Unknown
level: medium
------------------------
title: AWS Macie Evasion
id: 91f6a16c-ef71-437a-99ac-0b070e3ad221
status: test
description: Detects evade to Macie detection.
references:
    - https://docs.aws.amazon.com/cli/latest/reference/macie/
author: Sittikorn S
date: 2021/07/06
modified: 2022/10/09
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventName:
            - 'ArchiveFindings'
            - 'CreateFindingsFilter'
            - 'DeleteMember'
            - 'DisassociateFromMasterAccount'
            - 'DisassociateMember'
            - 'DisableMacie'
            - 'DisableOrganizationAdminAccount'
            - 'UpdateFindingsFilter'
            - 'UpdateMacieSession'
            - 'UpdateMemberSession'
            - 'UpdateClassificationJob'
    timeframe: 10m
    condition: selection | count() by sourceIPAddress > 5
fields:
    - sourceIPAddress
    - userIdentity.arn
falsepositives:
    - System or Network administrator behaviors
level: medium
------------------
title: CVE-2021-3156 Exploitation Attempt Bruteforcing
id: b9748c98-9ea7-4fdb-80b6-29bed6ba71d2
related:
    - id: 5ee37487-4eb8-4ac2-9be1-d7d14cdc559f
      type: derived
status: test
description: |
  Detects exploitation attempt of vulnerability described in CVE-2021-3156.
  Alternative approach might be to look for flooding of auditd logs due to bruteforcing.
  required to trigger the heap-based buffer overflow.
references:
    - https://blog.qualys.com/vulnerabilities-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit
author: Bhabesh Raj
date: 2021/02/01
modified: 2022/11/26
tags:
    - attack.privilege_escalation
    - attack.t1068
    - cve.2021.3156
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: 'SYSCALL'
        exe: '/usr/bin/sudoedit'
    condition: selection | count() by host > 50
falsepositives:
    - Unknown
level: high
-------------------
title: CVE-2021-3156 Exploitation Attempt
id: 5ee37487-4eb8-4ac2-9be1-d7d14cdc559f
status: test
description: |
  Detects exploitation attempt of vulnerability described in CVE-2021-3156.
  Alternative approach might be to look for flooding of auditd logs due to bruteforcing
  required to trigger the heap-based buffer overflow.
references:
    - https://blog.qualys.com/vulnerabilities-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit
author: Bhabesh Raj
date: 2021/02/01
modified: 2022/12/18
tags:
    - attack.privilege_escalation
    - attack.t1068
    - cve.2021.3156
logsource:
    product: linux
    service: auditd
detection:
    cmd_base:
        type: 'EXECVE'
        a0: '/usr/bin/sudoedit'
    cmd_s:
        - a1: '-s'
        - a2: '-s'
        - a3: '-s'
        - a4: '-s'
    cmd_backslash:
        - a1: '\'
        - a2: '\'
        - a3: '\'
        - a4: '\'
    condition: all of cmd_* | count() by host > 50
falsepositives:
    - Unknown
level: high
CSIEM Samples:
Select host, count(*) 
where type="TRAFFIC" group having count(*) > 500000
------------------
title: Failed Logins with Different Accounts from Single Source - Linux
id: fc947f8e-ea81-4b14-9a7b-13f888f94e18
status: test
description: Detects suspicious failed logins with different user accounts from a single source system
author: Florian Roth (Nextron Systems)
date: 2017/02/16
modified: 2022/11/26
tags:
    - attack.credential_access
    - attack.t1110
logsource:
    product: linux
    service: auth
detection:
    selection:
        pam_message: authentication failure
        pam_user: '*'
        pam_rhost: '*'
    timeframe: 24h
    condition: selection | count(pam_user) by pam_rhost > 3
falsepositives:
    - Terminal servers
    - Jump servers
    - Workstations with frequently changing users
level: medium

CSIEM Samples:
Select pam_rhost, pam_user, count(*) 
where type="TRAFFIC" group having count(*) > 500000
---------------
title: Possible DNS Tunneling
id: 1ec4b281-aa65-46a2-bdae-5fd830ed914e
status: test
description: Normally, DNS logs contain a limited amount of different dns queries for a single domain. This rule detects a high amount of queries for a single domain, which can be an indicator that DNS is used to transfer data.
references:
    - https://zeltser.com/c2-dns-tunneling/
    - https://patrick-bareiss.com/detect-c2-traffic-over-dns-using-sigma/
author: Patrick Bareiss
date: 2019/04/07
modified: 2021/11/27
tags:
    - attack.command_and_control
    - attack.t1071.004
    - attack.exfiltration
    - attack.t1048.003
logsource:
    category: dns
detection:
    selection:
        parent_domain: '*'
    condition: selection | count(dns_query) by parent_domain > 1000
falsepositives:
    - Valid software, which uses dns for transferring data
level: high
----------------
title: Network Scans Count By Destination Port
id: fab0ddf0-b8a9-4d70-91ce-a20547209afb
status: test
description: Detects many failed connection attempts to different ports or hosts
author: Thomas Patzke
date: 2017/02/19
modified: 2022/10/09
tags:
    - attack.discovery
    - attack.t1046
logsource:
    category: firewall
detection:
    selection:
        action: denied
    timeframe: 24h
    condition: selection | count(dst_port) by src_ip > 10
fields:
    - src_ip
    - dst_ip
    - dst_port
falsepositives:
    - Inventarization systems
    - Vulnerability scans
level: medium
-------------------
title: Multiple Modsecurity Blocks
id: a06eea10-d932-4aa6-8ba9-186df72c8d23
status: stable
description: Detects multiple blocks by the mod_security module (Web Application Firewall)
author: Florian Roth (Nextron Systems)
date: 2017/02/28
modified: 2023/01/07
tags:
    - attack.impact
    - attack.t1499
logsource:
    product: modsecurity
detection:
    selection:
        - 'mod_security: Access denied'
        - 'ModSecurity: Access denied'
        - 'mod_security-message: Access denied'
    timeframe: 120m
    condition: selection | count() > 6
falsepositives:
    - Vulnerability scanners
    - Frequent attacks if system faces Internet
level: medium
--------------
title: Multiple Suspicious Resp Codes Caused by Single Client
id: 6fdfc796-06b3-46e8-af08-58f3505318af
status: test
description: Detects possible exploitation activity or bugs in a web application
author: Thomas Patzke
date: 2017/02/19
modified: 2021/11/27
tags:
    - attack.initial_access
    - attack.t1190
logsource:
    category: webserver
detection:
    selection:
        sc-status:
            - 400
            - 401
            - 403
            - 500
    timeframe: 10m
    condition: selection | count() by clientip > 10
fields:
    - client_ip
    - vhost
    - url
    - response
falsepositives:
    - Unstable application
    - Application that misuses the response codes
level: medium



2) Near Aggregation

title: AWS Lambda Function Created or Invoked
id: d914951b-52c8-485f-875e-86abab710c0b
status: test
description: Detects when an user creates or invokes a lambda function.
references:
    - https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
author: Austin Songer @austinsonger
date: 2021/10/03
modified: 2022/12/25
tags:
    - attack.privilege_escalation
    - attack.t1078
logsource:
    product: aws
    service: cloudtrail
detection:
    selection1:
        eventSource: lambda.amazonaws.com
        eventName: CreateFunction
    selection2:
        eventSource: lambda.amazonaws.com
        eventName: Invoke
    condition: selection1 | near selection2
falsepositives:
    - Lambda Function created or invoked may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
    - If known behavior is causing false positives, it can be exempted from the rule.
level: low



3) 1 of filter

title: AWS EC2 VM Export Failure
id: 54b9a76a-3c71-4673-b4b3-2edb4566ea7b
status: experimental
description: An attempt to export an AWS EC2 instance has been detected. A VM Export might indicate an attempt to extract information from an instance.
references:
    - https://docs.aws.amazon.com/vm-import/latest/userguide/vmexport.html#export-instance
author: Diogo Braz
date: 2020/04/16
modified: 2022/10/05
tags:
    - attack.collection
    - attack.t1005
    - attack.exfiltration
    - attack.t1537
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventName: 'CreateInstanceExportTask'
        eventSource: 'ec2.amazonaws.com'
    filter1:
        errorMessage|contains: '*'
    filter2:
        errorCode|contains: '*'
    filter3:
        responseElements|contains: 'Failure'
    condition: selection and not 1 of filter*
level: low


4) all of section*

title: Google Workspace MFA Disabled
id: 780601d1-6376-4f2a-884e-b8d45599f78c
status: test
description: Detects when multi-factor authentication (MFA) is disabled.
references:
    - https://cloud.google.com/logging/docs/audit/gsuite-audit-logging#3
    - https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-security-settings#ENFORCE_STRONG_AUTHENTICATION
    - https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-security-settings?hl=en#ALLOW_STRONG_AUTHENTICATION
author: Austin Songer
date: 2021/08/26
modified: 2022/12/25
tags:
    - attack.impact
logsource:
    product: google_workspace
    service: google_workspace.admin
detection:
    selection_base:
        eventService: admin.googleapis.com
        eventName:
            - ENFORCE_STRONG_AUTHENTICATION
            - ALLOW_STRONG_AUTHENTICATION
    selection_eventValue:
        new_value: 'false'
    condition: all of selection*
falsepositives:
    - MFA may be disabled and performed by a system administrator.
level: medium

5) all of strange
title: Binary Padding - Linux
id: c52a914f-3d8b-4b2a-bb75-b3991e75f8ba
status: test
description: |
    Adversaries may use binary padding to add junk data and change the on-disk representation of malware.
    This rule detect using dd and truncate to add a junk data to file.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1027.001/T1027.001.md
author: 'Igor Fits, oscd.community'
date: 2020/10/13
modified: 2023/01/06
tags:
    - attack.defense_evasion
    - attack.t1027.001
logsource:
    product: linux
    service: auditd
detection:
    selection_execve:
        type: 'EXECVE'
    keywords_truncate:
        - 'truncate'
        - '-s'
    keywords_dd:
        - 'dd'
        - 'if='
    keywords_filter:
        - 'of='
    condition: selection_execve and (all of keywords_truncate or (all of keywords_dd and not keywords_filter))
falsepositives:
    - Unknown
level: high

5) Sum Aggregation

title: High DNS Bytes Out
id: 0f6c1bf5-70a5-4963-aef9-aab1eefb50bd
status: test
description: High DNS queries bytes amount from host per short period of time
author: Daniil Yugoslavskiy, oscd.community
date: 2019/10/24
modified: 2022/10/09
tags:
    - attack.exfiltration
    - attack.t1048.003
logsource:
    category: dns
detection:
    selection:
        query: '*'
    timeframe: 1m
    condition: selection | sum(question_length) by src_ip > 300000
falsepositives:
    - Legitimate high DNS bytes out rate to domain name which should be added to whitelist
level: medium
--------------------
title: High DNS Bytes Out - Firewall
id: 3b6e327d-8649-4102-993f-d25786481589
status: test
description: High DNS queries bytes amount from host per short period of time
author: Daniil Yugoslavskiy, oscd.community
date: 2019/10/24
modified: 2022/11/27
tags:
    - attack.exfiltration
    - attack.t1048.003
logsource:
    category: firewall
detection:
    selection:
        dst_port: 53
    timeframe: 1m
    condition: selection | sum(message_size) by src_ip > 300000
falsepositives:
    - Legitimate high DNS bytes out rate to domain name which should be added to whitelist
level: medium


6) Select and 1 of selection
title: Cleartext Protocol Usage
id: d7fb8f0e-bd5f-45c2-b467-19571c490d7e
status: stable
description: |
  Ensure that all account usernames and authentication credentials are transmitted across networks using encrypted channels.
  Ensure that an encryption is used for all sensitive information in transit. Ensure that an encrypted channels is used for all administrative account access.
references:
    - https://www.cisecurity.org/controls/cis-controls-list/
    - https://www.pcisecuritystandards.org/documents/PCI_DSS_v3-2-1.pdf
    - https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.04162018.pdf
author: Alexandr Yampolskyi, SOC Prime, Tim Shelton
date: 2019/03/26
modified: 2022/10/10
# tags:
    # - CSC4
    # - CSC4.5
    # - CSC14
    # - CSC14.4
    # - CSC16
    # - CSC16.5
    # - NIST CSF 1.1 PR.AT-2
    # - NIST CSF 1.1 PR.MA-2
    # - NIST CSF 1.1 PR.PT-3
    # - NIST CSF 1.1 PR.AC-1
    # - NIST CSF 1.1 PR.AC-4
    # - NIST CSF 1.1 PR.AC-5
    # - NIST CSF 1.1 PR.AC-6
    # - NIST CSF 1.1 PR.AC-7
    # - NIST CSF 1.1 PR.DS-1
    # - NIST CSF 1.1 PR.DS-2
    # - ISO 27002-2013 A.9.2.1
    # - ISO 27002-2013 A.9.2.2
    # - ISO 27002-2013 A.9.2.3
    # - ISO 27002-2013 A.9.2.4
    # - ISO 27002-2013 A.9.2.5
    # - ISO 27002-2013 A.9.2.6
    # - ISO 27002-2013 A.9.3.1
    # - ISO 27002-2013 A.9.4.1
    # - ISO 27002-2013 A.9.4.2
    # - ISO 27002-2013 A.9.4.3
    # - ISO 27002-2013 A.9.4.4
    # - ISO 27002-2013 A.8.3.1
    # - ISO 27002-2013 A.9.1.1
    # - ISO 27002-2013 A.10.1.1
    # - PCI DSS 3.2 2.1
    # - PCI DSS 3.2 8.1
    # - PCI DSS 3.2 8.2
    # - PCI DSS 3.2 8.3
    # - PCI DSS 3.2 8.7
    # - PCI DSS 3.2 8.8
    # - PCI DSS 3.2 1.3
    # - PCI DSS 3.2 1.4
    # - PCI DSS 3.2 4.3
    # - PCI DSS 3.2 7.1
    # - PCI DSS 3.2 7.2
    # - PCI DSS 3.2 7.3
logsource:
    category: firewall
detection:
    selection:
        dst_port:
            - 8080
            - 21
            - 80
            - 23
            - 50000
            - 1521
            - 27017
            - 3306
            - 1433
            - 11211
            - 15672
            - 5900
            - 5901
            - 5902
            - 5903
            - 5904
    selection_allow1:
        action:
            - forward
            - accept
            - 2
    selection_allow2:
        blocked: "false" # not all fws set action value, but are set to mark as blocked or allowed or not
    condition: selection and 1 of selection_allow*
falsepositives:
    - Unknown
level: low

7) all of selection and 1 of selection together
title: CVE-2020-10148 SolarWinds Orion API Auth Bypass
id: 5a35116f-43bc-4901-b62d-ef131f42a9af
status: test
description: Detects CVE-2020-10148 SolarWinds Orion API authentication bypass attempts
references:
    - https://kb.cert.org/vuls/id/843464
author: Bhabesh Raj, Tim Shelton
date: 2020/12/27
modified: 2023/01/02
tags:
    - attack.initial_access
    - attack.t1190
logsource:
    category: webserver
detection:
    selection:
        cs-uri-query|contains:
            - '/WebResource.axd'
            - '/ScriptResource.axd'
            - '/i18n.ashx'
            - '/Skipi18n'
    selection2:
        cs-uri-query|contains:
            - '/SolarWinds/'
            - '/api/'
    valid_request_1:
        cs-uri-query|contains: 'Orion/Skipi18n/Profiler/'
    valid_request_2:
        cs-uri-query|contains:
            - 'css.i18n.ashx'
            - 'js.i18n.ashx'
    condition: all of selection* and not 1 of valid_request_*
falsepositives:
    - Unknown
level: critical