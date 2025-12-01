# COMP 3010 CW2 Report
## Introduction
A Security Operations Centre (SOC) is a collection of personnel, procedures, and tools that can offer a comprehensive solution for identifying and mitigating an attack before any harm is done. As the number and sophistication of cyberattacks increase, SOCs have become essential for gathering security telemetry, triaging alerts, evaluating incidents using threat intelligence, and organizing a successful response (Vielberth et al 2020).
In this report, the SOC context is explored through the Boss of the SOC v3 (BOTSv3) dataset, a simulated enterprise environment for the fictitious company “Frothly” that provides realistic AWS, endpoint, and network activity that mirrors enterprise operations. Using Splunk to analyze BOTSv3, this investigation models real SOC workflows such as querying CloudTrail logs, identifying misconfigurations and analyzing attacker behavior.

The objectives of this investigation are:

•	Answering one set of 200-level questions.

•	Reconstructing the incident from a SOC perspective.

•	Reflecting on SOC processes / improvement.

The report's scope is restricted to Splunk log analysis of the chosen BOTSv3 scenario and the 200-level questions that go along with it. The focus is on getting information from available logs, developing search filters and relating the findings to SOC processes. A thorough threat-hunting activity, host-based forensics and detailed malware reverse engineering outside of the dataset supplied are all outside the scope. 

This investigation assumes the following: The BOTSv3 logs are complete, accurately time-synchronized, and representative of Frothly's environment, Splunk is the main SIEM platform within the SOC, and a typical tiered SOC structure is in place. Instead of focusing on compatibility or data quality issues, these assumptions enable the analysis to focus on how a SOC team would understand and act upon the available information.

## SOC Roles & Incident Handling Reflection
The BOTSv3 dataset is related to and accurately represents the different SOC tiers, their roles and incident handling methods. The typical SOC is divided into three main tiers:

• **Tier 1 (Triage Specialist):** Tier 1 analysts focus on monitoring alarms and alerts, removing false positives, and obtaining basic context to promptly escalate critical incidents (Vielberth et al 2020). In the BOTSv3 dataset, identifying the IAM users accessing AWS services and finding the processor number used on the web servers mirrors this role. For example, a Tier 1 analyst could run a straightforward CloudTrail search to list IAM users involved in suspicious activity and check host hardware details to understand which assets are affected during triage. These Tier 1 activities mostly fall within the detection phase, with some contribution to response, as they provide the first validated view of what is happening before escalation.

• **Tier 2 (Incident Responder):**  At Tier 2, analysts review higher-severity incidents escalated by triage specialists, perform deeper investigation, and are responsible for developing and implementing strategies to contain and recover from an incident (Vielberth et al 2020). In the BOTSv3 exercise, this is reflected in tasks such as identifying the field used to alert on AWS API activity without MFA, tracing the event ID of the PutBucketAcl call, and attributing it to Bud’s username. Tier 2 analysts interpret and correlate the raw data collected at Tier 1, turning it into functional threat intelligence (for example, using “AWS API activity without MFA” as an indicator of compromise and tying it to a specific user and bucket). These activities sit across the detection and response phases, as Tier 2 both refines what the incident actually is and drives containment actions. If the incident responder encounters significant complexity, the case is escalated to Tier 3.

• **Tier 3 (Threat Hunter):** Tier 3 analysts are the most experienced personnel in a SOC. They mainly proactively look for unknown threats and review security data provided by tiers 1 and 2 for any vulnerabilities or gaps. In relation to the BOTSv3 exercise, an incident responder might escalate the PutBucketAcl event and Bud’s username to a threat hunter, who then pivots into S3 access logs to determine which file was uploaded while the bucket was public and assess the impact. Likewise, using winhostmon data to spot a single host running a different Windows edition reflects hunting for outliers that may indicate misconfiguration or attacker activity. These Tier 3 activities span the response and recovery phases, and also support prevention by informing improved detections and hardening measures.

Overall, the BOTSv3 exercise shows an effective escalation from Tier 1 to Tier 3, but it relies heavily on manual searches rather than automated alerts or playbooks. In a real SOC, I would strengthen alerting around S3 ACL changes and MFA, implement stricter access controls and use standardized dashboards to speed investigations.

## Installation & Data Preparation 


## Guided Questions
### Q1 – IAM users that accessed AWS services

**a) Question Description**

This question uses AWS CloudTrail logs to identify which IAM users are calling AWS APIs in the environment. For a SOC, this is basic identity monitoring: knowing which accounts are active is key to spotting compromised users and misuse of privileges. It sits in the Detection and Investigation stages of the incident lifecycle. 

The AWS documentation shows that the IAM user who performed an action is stored in the userIdentity.userName field when userIdentity.type="IAMUser" (docs.aws.amazon.com. n.d.). 
<img width="975" height="379" alt="image" src="https://github.com/user-attachments/assets/22fc0b4f-7081-4f26-bd6b-eeadd4212920" />

**b) SPL query used**

With the BOTSv3 data, I used stats values() to get the distinct IAM user names

```spl
index=botsv3 sourcetype="aws:cloudtrail"
| stats values(userIdentity.userName) AS iam_users
```

---

**c) Output**

```text
bstoll
btun
splunk_access
web_admin
```

<img width="975" height="376" alt="image" src="https://github.com/user-attachments/assets/1ea03715-7cd8-4c46-911e-1271704392c6" />

---



## References
1. Vielberth, M., Böhm, F., Fichtinger, I. and Pernul, G., 2020. Security operations center: A systematic study and open challenges. Ieee Access, 8, pp.227756-227779.
2. docs.aws.amazon.com. (n.d.). CloudTrail log file examples - AWS CloudTrail. [online] Available at: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html.
