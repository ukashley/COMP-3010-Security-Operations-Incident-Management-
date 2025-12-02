# COMP 3010 CW2 Report
## 1. Introduction
A Security Operations Centre (SOC) is a collection of personnel, procedures, and tools that can offer a comprehensive solution for identifying and mitigating an attack before any harm is done. As the number and sophistication of cyberattacks increase, SOCs have become essential for gathering security telemetry, triaging alerts, evaluating incidents using threat intelligence, and organizing a successful response (Vielberth et al 2020).
In this report, the SOC context is explored through the Boss of the SOC v3 (BOTSv3) dataset, a simulated enterprise environment for the fictitious company “Frothly” that provides realistic AWS, endpoint, and network activity that mirrors enterprise operations. Using Splunk to analyze BOTSv3, this investigation models real SOC workflows such as querying CloudTrail logs, identifying misconfigurations and analyzing attacker behavior.

The objectives of this investigation are:

•	Answering one set of 200-level questions.

•	Reconstructing the incident from a SOC perspective.

•	Reflecting on SOC processes / improvement.

The report's scope is restricted to Splunk log analysis of the chosen BOTSv3 scenario and the 200-level questions that go along with it. The focus is on getting information from available logs, developing search filters and relating the findings to SOC processes. A thorough threat-hunting activity, host-based forensics and detailed malware reverse engineering outside of the dataset supplied are all outside the scope. 

This investigation assumes the following: The BOTSv3 logs are complete, accurately time-synchronized, and representative of Frothly's environment, Splunk is the main SIEM platform within the SOC, and a typical tiered SOC structure is in place. Instead of focusing on compatibility or data quality issues, these assumptions enable the analysis to focus on how a SOC team would understand and act upon the available information.

## 2. SOC Roles & Incident Handling Reflection
The BOTSv3 dataset is related to and accurately represents the different SOC tiers, their roles and incident handling methods. The typical SOC is divided into three main tiers:

• **Tier 1 (Triage Specialist):** Tier 1 analysts focus on monitoring alarms and alerts, removing false positives, and obtaining basic context to promptly escalate critical incidents (Vielberth et al 2020). In the BOTSv3 dataset, identifying the IAM users accessing AWS services and finding the processor number used on the web servers mirrors this role. For example, a Tier 1 analyst could run a straightforward CloudTrail search to list IAM users involved in suspicious activity and check host hardware details to understand which assets are affected during triage. These Tier 1 activities mostly fall within the detection phase, with some contribution to response, as they provide the first validated view of what is happening before escalation.

• **Tier 2 (Incident Responder):**  At Tier 2, analysts review higher-severity incidents escalated by triage specialists, perform deeper investigation, and are responsible for developing and implementing strategies to contain and recover from an incident (Vielberth et al 2020). In the BOTSv3 exercise, this is reflected in tasks such as identifying the field used to alert on AWS API activity without MFA, tracing the event ID of the PutBucketAcl call, and attributing it to Bud’s username. Tier 2 analysts interpret and correlate the raw data collected at Tier 1, turning it into functional threat intelligence (for example, using “AWS API activity without MFA” as an indicator of compromise and tying it to a specific user and bucket). These activities sit across the detection and response phases, as Tier 2 both refines what the incident actually is and drives containment actions. If the incident responder encounters significant complexity, the case is escalated to Tier 3.

• **Tier 3 (Threat Hunter):** Tier 3 analysts are the most experienced personnel in a SOC. They mainly proactively look for unknown threats and review security data provided by tiers 1 and 2 for any vulnerabilities or gaps. In relation to the BOTSv3 exercise, an incident responder might escalate the PutBucketAcl event and Bud’s username to a threat hunter, who then pivots into S3 access logs to determine which file was uploaded while the bucket was public and assess the impact. Likewise, using winhostmon data to spot a single host running a different Windows edition reflects hunting for outliers that may indicate misconfiguration or attacker activity. These Tier 3 activities span the response and recovery phases, and also support prevention by informing improved detections and hardening measures.

## 3. Installation & Data Preparation 


## 4. Guided Questions
### Q1 – IAM users that accessed AWS services

**a) Answer**

bstoll,btun,splunk_access,web_admin

**b) Description**

This question uses AWS CloudTrail logs to identify which IAM users are calling AWS APIs in the environment. For a SOC, this is basic identity monitoring: knowing which accounts are active is key to spotting compromised users and misuse of privileges. It sits in the detection stages of the incident lifecycle and aligns with research showing that SOCs need to correlate identity and activity data over time to spot sophisticated multi-stage attacks, rather than looking at isolated events alone (Akinrolabu et al. 2018). 

The AWS documentation shows that the IAM user who performed an action is stored in the userIdentity.userName field when userIdentity.type="IAMUser" (docs.aws.amazon.com. n.d.). 
<img width="975" height="379" alt="image" src="https://github.com/user-attachments/assets/22fc0b4f-7081-4f26-bd6b-eeadd4212920" />

**c) Method used**

With the BOTSv3 data, I used stats values() to get the distinct IAM usernames

```spl
index=botsv3 sourcetype="aws:cloudtrail"
| stats values(userIdentity.userName) AS iam_users
```

---

**d) Output**

```text
bstoll
btun
splunk_access
web_admin
```

<img width="975" height="376" alt="image" src="https://github.com/user-attachments/assets/1ea03715-7cd8-4c46-911e-1271704392c6" />

---

**e) Interpretation**

The dataset shows four IAM users generating CloudTrail events, the first two (`bstoll`,`btun`) look like human users, `splunk_access` is likely a service account, and `web_admin` suggests a privileged/shared admin account. A SOC analyst often relies on user-profiling and behavioural features to distinguish normal from suspicious activity, so these four IAM users would each get their own behavioural baseline before deciding whether their actions look risky (Akinrolabu et al. 2018). These four users become pivots for later questions, such as S3 bucket ACL changes or object uploads. A SOC would restrict searches to these identities to reduce noise and spot malicious actions faster. 

### Q2 – Field to alert that AWS API activity occured without MFA

**a) Answer**

userIdentity.sessionContext.attributes.mfaAuthenticated

**b) Description**

This question uses AWS CloudTrail logs to identify the full JSON path of the field that indicates AWS API activity occurred without MFA. For a SOC, this falls within the detection and analysis part of the security incident handling lifecycle, where data monitoring decides if an event is a security incident. An API call made without MFA can be treated as a potential indicator of compromise and would typically be handled by an incident responder in line with the organization’s security incident handling and response process (Agbede 2023). 

**c) Method used**

I searched the BOTSv3 CloudTrail data for MFA-related API calls, excluding console logins 

```spl
index=botsv3 sourcetype="aws:cloudtrail" *mfa* NOT "ConsoleLogin"
```
<img width="975" height="513" alt="image" src="https://github.com/user-attachments/assets/d72a6bfd-f6ef-400a-84e0-1fd54dea240a" />

---

Then, in the Events view, I expanded userIdentity > sessionContext > attributes and saw the field mfaAuthenticated, which shows whether MFA was used with true/false.
<img width="975" height="405" alt="image" src="https://github.com/user-attachments/assets/6343ef83-1253-40ee-b106-99c1c7ffe941" />


**d) Output**

```spl
index=botsv3 sourcetype="aws:cloudtrail" *mfa* NOT "ConsoleLogin"
| table userIdentity.sessionContext.attributes.mfaAuthenticated, eventName, userIdentity.userName
```

<img width="975" height="524" alt="image" src="https://github.com/user-attachments/assets/64ed8342-ba9f-49d0-9c8a-aeeb97d9d9f3" />

---

**e) Interpretation**

For a SOC, this is important because identifying userIdentity.sessionContext.attributes.mfaAuthenticated lets them utilise the MFA policy in CloudTrail by clearly differentiating strongly authenticated activity (true) from higher-risk sessions (false). Analysts can alert on sensitive API calls made without MFA and, during investigations, quickly pivot to those calls to spot possible account compromise and check whether MFA controls are actually being followed.

### Q3 – The processor number used on the web servers

**a) Answer**

E5-2676

**b) Description**

This question uses available hardware information in the dataset to identify the processor number used on the web servers. For a SOC, this falls at the first part of security incident handling, where a triage specialist can easily check hosts' hardware details to locate the processor number and assets that were affected if any.

**c) Method used**

Used the botsV3 data and “hardware” as the source type to begin the search

```spl
index=botsv3 sourcetype="hardware" 
```
<img width="975" height="516" alt="image" src="https://github.com/user-attachments/assets/91465de6-1b07-4698-aef0-ef8bef2950e9" />

---

A closer look at the first displayed event showed the processor number used on the web servers. 
<img width="975" height="256" alt="image" src="https://github.com/user-attachments/assets/28fb537d-8879-43b5-bcef-9570a76ed090" />

---

To confirm that the host hosts web servers, I used the search filter below and the results (Using  stream:http and has the server: Apache/2.2.34 (Amazon)) confirmed it does:
```spl
index=botsv3 host="gacrux.i-09cbc261e84259b54"
```
<img width="975" height="759" alt="image" src="https://github.com/user-attachments/assets/7371bec0-bb6e-4dd9-b2b8-9afc91f7d542" />

---

**d) Interpretation**

For a SOC, this is important because device identification and tracking in security incidents and forensic investigations can be gotten from identifying the processor number. This unique, factory-assigned identifier aids in distinguishing a specific physical CPU from all others in the same series. Tier 1 analysts can alert on suspicious devices and trace back odd logs during investigations with the knowledge of this number. 

### Q4 – The event ID of the API call that enabled public access

**a) Answer**

ab45689d-69cd-41e7-8705-5350402cf7ac

**b) Description**

This question uses AWS CloudTrail logs to identify the event ID of the accidental API call made by Bud that enabled public access to an S3 bucket. CloudTrail records each change with an eventID, user, time, and request parameters (Amazon.com, 2025). For a SOC, identifying this event is key to understanding who made the change, when it happened, and what level of access was granted.

**c) Method used**

To find the event ID, I searched for events with the name “PutBucketAcl” and this returned two events

```spl
index=botsv3 sourcetype="aws:cloudtrail" eventName="PutBucketAcl"
```
<img width="975" height="517" alt="image" src="https://github.com/user-attachments/assets/0644775c-9e5a-48be-809f-ff451482cd43" />

---

To narrow it down to the event ID of the API call that gave access to all users. I used this search filter:

```spl
index=botsv3 sourcetype="aws:cloudtrail" eventName="PutBucketAcl" AllUsers
```

---

**d) Output**

From this filtered result, I inspected the event fields and identified the specific eventID associated with Bud’s public ACL change:
<img width="975" height="849" alt="image" src="https://github.com/user-attachments/assets/dd8c1e31-f090-49d6-bc84-0d4dfce14a8e" />

**e) Interpretation**

This eventID records the precise moment Bud’s IAM user made the S3 bucket public to AllUsers. For a SOC analyst, it's a crucial point because it indicates when exposure started, who caused it, and allows you to look for any external access in follow-up logs (Farris, 2022). It also emphasizes the need for alerts and safeguards against dangerous ACL modifications.

## References
1. Vielberth, M., Böhm, F., Fichtinger, I. and Pernul, G., 2020. Security operations center: A systematic study and open challenges. Ieee Access, 8, pp.227756-227779.
2. docs.aws.amazon.com. (n.d.). CloudTrail log file examples - AWS CloudTrail. [online] Available at: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html.
3. Akinrolabu, O., Agrafiotis, I. and Erola, A. (2018) 'The challenge of detecting sophisticated attacks: Insights from SOC Analysts'. In Proceedings of the 13th international conference on availability, reliability and security (pp. 1-9).
4. Agbede, O.M. (2023) Incident Handling and Response Process in Security Operations.
5. Amazon.com. (2025). CloudTrail record contents for management, data, and network activity events - AWS CloudTrail. [online] Available at: http://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html.
6. Farris, C. (2022). Incident Response in AWS. [online] Available at: https://www.chrisfarris.com/post/aws-ir/ [Accessed 2 Dec. 2025].
