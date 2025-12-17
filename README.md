# Coursework 2: BOTSv3 Incident Analysis and Presentation
## Table of Contents
<img width="875" height="623" alt="image" src="https://github.com/user-attachments/assets/297430c0-0a21-4450-9c60-b3baa9050997" />

## 1. Introduction
A misconfiguration in Frothly’s AWS environment leads to a public S3 bucket, an external upload of a warning file, and one endpoint running a different Windows edition from the rest of the estate. Using Splunk and the Boss of the SOC v3 (BOTSv3) dataset, this report, intended for a security management audience, reconstructs the sequence of events from a Security Operations Centre (SOC) point of view and shows how a SOC team could detect, investigate, and learn from the incident.

A SOC brings together people, processes, and tools to detect, investigate, and respond to attacks before significant harm occurs [1]. By treating BOTSv3 as a timeline reconstruction exercise, the research explains what a SOC would do at each stage by correlating CloudTrail, S3 access logs, and endpoint telemetry to connect identity activity to a bucket ACL modification and connect an external upload to an endpoint configuration anomaly.

The objectives are to answer one set of BOTSv3 200-level questions, reconstruct the incident from a SOC perspective and reflect on SOC processes and potential improvements. The scope is limited to Splunk log analysis of the chosen BOTSv3 scenario and its associated 200-level questions. Broader threat hunting, host-based forensics and malware analysis beyond the supplied dataset are out of scope. The analysis assumes BOTSv3 logs are complete and time-synchronized, that Splunk is the main SIEM, and that a typical tiered SOC structure is in place, so the focus stays on how analysts interpret and act on the available information.

## 2. SOC Roles & Incident Handling Reflection
BOTSv3 reflects how a SOC operates day-to-day. Tier 1 monitors and triages alerts by validating signal fast, removing obvious false positives, capturing initial context and affected assets etc. [1]. Tier 2 investigates and contains by correlating logs, building a timeline, attributing activity to assets, and driving immediate fixes [1]. Tier 3 hunts and improves detection/prevention by turning lessons learned into stronger alert logic, baselines, and guardrails. In BOTSv3, this escalation is mirrored by moving from quick searches to proof and scope, then to hardening and detection tuning.

This aligns with the incident handling lifecycle:
**Prevention:** enforce MFA for sensitive AWS actions, apply least privilege, and use S3 guardrails (e.g. Block Public Access / prevent public ACLs). 

**Detection:** alert on high-risk CloudTrail/S3 patterns like sensitive actions without MFA, public access/ACL changes, unusual uploads/access and flag endpoint build drift via baselining.

**Reaction:** confirm the key change event, attribute it, scope affected data/assets, and contain by removing risky access [12].

**Recovery:** verify secure configuration is restored, tighten/repair IAM permissions and remediate non-standard endpoints, updating SOC runbooks and escalation criteria [12].

BOTSv3 highlights a practical limitation of real SOC operations because analysts often work with incomplete context and noisy data. Effective escalation therefore depends on clear handovers between tiers and well-defined alert thresholds. While BOTSv3 provides rich telemetry, real environments frequently suffer from logging gaps, reinforcing that SOC effectiveness relies as much on logging strategy and detection engineering as on analyst capability [13].

## 3. Installation & Data Preparation 
To replicate a standard SOC deployment where analysts operate their own SIEM stack, Splunk Enterprise was installed on an Ubuntu virtual machine. A local Splunk Enterprise instance was chosen over Splunk Cloud so that indexes, configuration files and system resources could be fully controlled, reflecting how many SOCs run Splunk within their own infrastructure for security and compliance reasons [8]. This also allowed full administrative access for experimenting with BOTSv3 without affecting a shared environment.

The Linux installer version was selected from Splunk and installed via the terminal.
<img width="975" height="511" alt="image" src="https://github.com/user-attachments/assets/a1432ed6-4d54-43cd-a970-58da52141d44" />
<img width="975" height="733" alt="image" src="https://github.com/user-attachments/assets/d6e89051-be15-482d-95fc-e921046ac7f1" />

After installation, the service was started from /opt/splunk/bin using sudo ./splunk start --accept-license and created a dedicated local admin account. 
<img width="975" height="401" alt="image" src="https://github.com/user-attachments/assets/e358db85-4d8f-4960-af2b-9a31df4e8eb6" />
 
This aligns with SOC practice, where SIEM administration is restricted to a small number of privileged identities to reduce the risk of unauthorized access [9].

After startup, I validated the deployment the way a SOC would validate a new log onboarding by checking if Splunk service is healthy, that the botsv3 app loaded, and data is present in the intended index/sourcetypes
<img width="975" height="380" alt="image" src="https://github.com/user-attachments/assets/5ff10371-c2d6-4632-bfc7-ebf5e651b1ee" />

This matters because any missing sourcetype would invalidate later detection and incident reconstruction.

I downloaded botsv3_data_set.tgz from GitHub into ~/Downloads, extracted it, and copied the botsv3_data_set directory into /opt/splunk/etc/apps with cp -r. 
<img width="975" height="671" alt="image" src="https://github.com/user-attachments/assets/7c6272f2-6de8-45c7-a6a7-0517ce17c6b5" />
<img width="975" height="722" alt="image" src="https://github.com/user-attachments/assets/93dad4be-52ee-4ee8-8ba3-936cf436156a" />
 
After confirming the app files, I started Splunk from /opt/splunk/bin so it could load the new content.
<img width="975" height="684" alt="image" src="https://github.com/user-attachments/assets/c4272590-d1d8-425a-aeca-ecd9a56e8024" />

The app provisions a dedicated botsv3 index and sourcetypes, aligning with SOC practice of isolating datasets for tuning and access control. I verified ingestion by confirming events exist in index=botsv3, expected sourcetypes populate, and timestamps span the scenario window, so later queries aren’t answering from partial data.
<img width="975" height="518" alt="image" src="https://github.com/user-attachments/assets/9651c10a-e824-480e-a151-57b460222f8b" />
<img width="975" height="490" alt="image" src="https://github.com/user-attachments/assets/f8f81163-13da-473c-8f6b-928478312933" />

These checks reflect how a SOC would onboard new log sources and confirm they are reliable for investigations and detections [10].

## 4. Guided Questions
### 4.1 Q1 – IAM users that accessed AWS services

**a) Answer**

bstoll,btun,splunk_access,web_admin

**b) Explanation**

The AWS documentation shows that the IAM user who performed an action is stored in the userIdentity.userName field when userIdentity.type="IAMUser" [2]. 
<img width="975" height="379" alt="image" src="https://github.com/user-attachments/assets/22fc0b4f-7081-4f26-bd6b-eeadd4212920" />

I filtered to IAMUser events and extracted unique values of userIdentity.userName to list every IAM identity that generated AWS API activity in the dataset.

```spl
index=botsv3 sourcetype="aws:cloudtrail"
| stats values(userIdentity.userName) AS iam_users
```

This provides a baseline of active identities for later pivots and ensures searches can be focused (e.g. reviewing S3 ACL changes or object uploads), reducing noise and making it easier to spot compromised accounts or misuse of privileges [3].

```text
bstoll
btun
splunk_access
web_admin
```

<img width="975" height="376" alt="image" src="https://github.com/user-attachments/assets/1ea03715-7cd8-4c46-911e-1271704392c6" />

---

### 4.2 Q2 – Field to alert that AWS API activity occured without MFA

**a) Answer**

userIdentity.sessionContext.attributes.mfaAuthenticated

**b) Explanation**

The aim here is to find the CloudTrail field that indicates whether MFA was used for an API call. I filtered CloudTrail events for MFA-related data while excluding console logins so that sign-in noise did not hide the relevant field:

```spl
index=botsv3 sourcetype="aws:cloudtrail" *mfa* NOT "ConsoleLogin"
```
<img width="975" height="513" alt="image" src="https://github.com/user-attachments/assets/d72a6bfd-f6ef-400a-84e0-1fd54dea240a" />

---

In the Events view, expanding userIdentity > sessionContext > attributes reveal the Boolean field mfaAuthenticated, which records whether MFA was present for that session [2]:
<img width="975" height="405" alt="image" src="https://github.com/user-attachments/assets/6343ef83-1253-40ee-b106-99c1c7ffe941" />

---

In a SOC, this field is critical for detection and response. It lets analysts distinguish strongly authenticated sessions (true) from higher-risk ones (false). Detection rules can alert on sensitive API calls made without MFA, and incident responders can pivot to non-MFA sessions when investigating suspected account compromise or testing whether MFA policies are actually being followed [4].

### 4.3 Q3 – The processor number used on the web servers

**a) Answer**

E5-2676

**b) Explanation**

This question uses hardware information in the dataset to identify the processor number used on the web servers. I started by searching the botsv3 index for events containing CPU details:

```spl
index=botsv3 sourcetype="hardware" 
```
<img width="975" height="516" alt="image" src="https://github.com/user-attachments/assets/91465de6-1b07-4698-aef0-ef8bef2950e9" />

---

They all included the same processor number, so I selected the first one:
<img width="975" height="256" alt="image" src="https://github.com/user-attachments/assets/28fb537d-8879-43b5-bcef-9570a76ed090" />

---

To confirm that this host was actually running web services, I pivoted on its host value:
 ```spl
index=botsv3 host="gacrux.i-09cbc261e84259b54"
```
and saw HTTP traffic with a server header such as Apache/2.2.34 (Amazon), confirming it is a web server.
<img width="975" height="759" alt="image" src="https://github.com/user-attachments/assets/7371bec0-bb6e-4dd9-b2b8-9afc91f7d542" />

---

For a SOC, this is important because device identification and tracking in security incidents and forensic investigations can be gotten from identifying the processor number. This unique, factory-assigned identifier aids in distinguishing a specific physical CPU from all others in the same series. Tier 1/2 analysts can pivot on this hardware profile when correlating logs, so investigations stay aligned with the correct physical infrastructure rather than just abstract hostnames.

### 4.4 Q4 – The event ID of the API call that enabled public access

**a) Answer**

ab45689d-69cd-41e7-8705-5350402cf7ac

**b) Explanation**

To find the event that made an S3 bucket public, I searched for S3 ACL changes in CloudTrail [5]:

```spl
index=botsv3 sourcetype="aws:cloudtrail" eventName="PutBucketAcl"
```
<img width="975" height="517" alt="image" src="https://github.com/user-attachments/assets/0644775c-9e5a-48be-809f-ff451482cd43" />

---

To narrow it down to the event ID of the API call that gave access to all users. I used this search filter:

```spl
index=botsv3 sourcetype="aws:cloudtrail" eventName="PutBucketAcl" AllUsers
```
Inspecting the event fields showed the specific eventID associated with Bud’s public ACL change:
<img width="975" height="849" alt="image" src="https://github.com/user-attachments/assets/dd8c1e31-f090-49d6-bc84-0d4dfce14a8e" />

---

This eventID records the precise change that opened the S3 bucket to the public. For a SOC analyst, it's a crucial point because it indicates when exposure started, who caused it, and allows you to look for any external access in follow-up logs [6]. It also emphasizes the need for alerts and safeguards against dangerous ACL modifications.

### 4.5 Q5 – Bud's Username

**a) Answer**

bstoll

**b) Explanation**

Using the same PutBucketAcl event, I expanded the userIdentity field:

```spl
index=botsv3 sourcetype="aws:cloudtrail" eventName="PutBucketAcl"
```
The userIdentity.userName field shows that Bud’s IAM username is bstoll:
<img width="802" height="827" alt="image" src="https://github.com/user-attachments/assets/0d421d5b-a23a-456d-a4f5-95ee02003d50" />

---

For incident handling, this ties the risky configuration change directly to an individual account. The SOC can then review bstoll’s recent activity (for example, all CloudTrail events for that user), check whether his access rights are appropriate, and, if needed, adjust permissions. This can also be mitigated by enforcing additional controls such as including him in targeted security awareness training [6].

### 4.6 Q6 – Name of the public S3 bucket

**a) Answer**

frothlywebcode

**b) Explanation**

Still within the PutBucketAcl event, I expanded requestParameters and located the bucket name in the bucketName field:

```spl
index=botsv3 sourcetype="aws:cloudtrail" eventName="PutBucketAcl"
```

The expansion clearly shows the S3 bucket name:
<img width="875" height="597" alt="image" src="https://github.com/user-attachments/assets/a0d254bd-31fd-4e62-8c0b-868540b75484" />

---

The SOC can scope the impact of the misconfiguration by knowing the precise bucket name, including what data might be stored there, which services or applications rely on it, and whether sensitive content could have been accessed by outside parties [6]. It also provides focused searches in S3 access logs and configuration baselines so that follow-up inspections and improvements are applied to the correct asset. 

### 4.7 Q7 – The text file uploaded to the S3 bucket

**a) Answer**

OPEN_BUCKET_PLEASE_FIX.txt 

**b) Explanation**

After identifying the exposed bucket in CloudTrail, I pivoted to sourcetype=aws:s3:accesslogs 

```spl
index=botsv3 sourcetype=" aws:s3:accesslogs" frothlywebcode
```
<img width="975" height="492" alt="image" src="https://github.com/user-attachments/assets/d0168360-7e59-43a7-9dc7-26830d1dce00" />

---

I saw a mix of HTTP operations, so I filtered to successful uploads by looking for REST.PUT.OBJECT with a 200 HTTP status code, scoped to the affected bucket:

```spl
index="botsv3" sourcetype="aws:s3:accesslogs" frothlywebcode "REST.PUT.OBJECT"
```
<img width="975" height="511" alt="image" src="https://github.com/user-attachments/assets/c4f4f9bd-5bb9-4dfb-b1c2-6362540af950" />

---

This narrowed the results to four events. I then restricted results to objects ending in .txt to find the exact text file:
```spl
index="botsv3" sourcetype="aws:s3:accesslogs" frothlywebcode "REST.PUT.OBJECT" .txt
```

This shows the text file successfully uploaded during the public exposure window was OPEN_BUCKET_PLEASE_FIX.txt.
<img width="975" height="412" alt="image" src="https://github.com/user-attachments/assets/e4338c58-d8d5-47a2-a2e4-434c5d225f65" />

---

For a SOC, identifying OPEN_BUCKET_PLEASE_FIX.txt shows the direct impact of Bud’s risky S3 ACL change. S3 server access logs' request and object information are correlated with the PutBucketAcl event with REST.PUT.OBJECT entries in aws:s3:accesslogs to verify what was uploaded, when it occurred, and to identify malicious or warning files during the exposure window [7].

### 4.8 Q8 – FQDN of the endpoint with a different Windows edition

**a) Answer**

BSTOLL-L.froth.ly

**b) Explanation**

This question identifies a host running a different Windows edition compared to the rest of the estate. I started with:
```spl
index="botsv3" sourcetype="winhostmon" "windows 10"
```
<img width="975" height="825" alt="image" src="https://github.com/user-attachments/assets/fe373b17-6b4c-4c49-963d-fe18eb8ba282" />

---

This returned 204 events, with two editions present: Windows 10 Pro and Windows 10 Enterprise. To isolate the outlier, I searched for the Enterprise edition:
```spl
index="botsv3" sourcetype="winhostmon" "windows 10 Enterprise"
```
<img width="975" height="1131" alt="image" src="https://github.com/user-attachments/assets/b1e7c424-b0c5-4cc2-82bd-90e8e4dfc02a" />

---

Looking through the 30 returned events, I confirmed that there was only one host name consistently appearing which was BSTOLL-L. To get final confirmation, I used the filter below to see the number of events it would return, and it returned 174 (174+30 = 204):
```spl
index="botsv3" sourcetype="winhostmon" "windows 10 Pro"
```
<img width="975" height="826" alt="image" src="https://github.com/user-attachments/assets/4da450a9-4923-44b4-8c00-5e541ed591d6" />

---

Finally, I pivoted on BSTOLL-L across all data to retrieve richer system metadata:
```spl
index="botsv3" BSTOLL-L | stats count by sourcetype source
```
<img width="975" height="582" alt="image" src="https://github.com/user-attachments/assets/a187788c-524c-4e57-823b-b778d64b902d" />

---

From the cisconvmsysdata source, expanding the event showed the full FQDN: BSTOLL-L.froth.ly.
<img width="975" height="464" alt="image" src="https://github.com/user-attachments/assets/57e612d1-ecfe-4aae-bf03-f837b0a8f587" />

---

This kind of baseline comparison is used to spot non-standard builds that may be missing controls. In a SOC context, this endpoint should be treated as an exception, investigated, and brought into alignment or given additional monitoring.

## 5. Conclusion
This investigation traced a realistic cloud misconfiguration incident from initial IAM activity to S3 exposure and endpoint anomalies using Splunk and the BOTSv3 dataset. It showed how IAM usage patterns, risky changes such as Bud’s public S3 ACL on frothlywebcode, the upload of OPEN_BUCKET_PLEASE_FIX.txt, and outlier hosts like BSTOLL-L.froth.ly collectively provide the context needed for scoping impact, attributing actions and prioritizing response.

The SOC takeaways are to treat non-MFA API activity as high signal for identity compromise, alert immediately on public S3 ACL changes and object uploads during exposure windows, and use endpoint baselining to flag non-standard builds for rapid triage [11]. Strategically, this means adding proactive threat hunting over CloudTrail and host telemetry, enhancing correlation searches using fields like userIdentity.sessionContext.attributes.mfaAuthenticated, and strengthening cloud guardrails for automated prevention of public buckets. Together, these improvements would shorten detection and response times and enhance the SOC’s resilience.

## 6. References
[1] 	V. M, B. F, F. I and P. G, "Security operations center: A systematic study and open challenges," IEEE, vol. VIII, pp. 227756-227779, 2020. 

[2] 	docs.aws.amazon.com, "CloudTrail log file examples - AWS CloudTrail," Amazon, n.d.. [Online]. Available: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html. [Accessed November 2025].

[3] 	A. O, A. I and E. A, "The challenge of detecting sophisticated attacks: Insights from SOC Analysts," In Proceedings of the 13th International Conference on availability, reliability and security, pp. 1-9, 2018. 

[4] 	A. O.M, "Incident Handling and Response Process in Security Operations," 2023. 

[5] 	Amazon.com, "CloudTrail record contents for management, data, and network activity events - AWS CloudTrail," Amazon, 2025. [Online]. Available: http://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html. [Accessed November 2025].

[6] 	F. C, "Incident Response in AWS," 2022. [Online]. Available: https://www.chrisfarris.com/post/aws-ir/. [Accessed 2 December 2025].

[7] 	A. W. Services, "Logging requests using server access logging - Amazon Simple Storage Service," Amazon, 2023. [Online]. Available: https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html. [Accessed 2 December 2025].

[8] M.Mohankumar and R. Ranjithkumar, "Security Information and Event Management (SIEM) Performance in On-Premises and Cloud Based SIEM: A Survey," In Proc. 1st Int. Conf. Artificial Intelligence for Internet of Things (AI4IoT), pp. 628-630, 2023. 

[9] Y. S. A. S. Z. Z. G. J. A. T. B. A. D. F.B. Kokulu, "Matched and Mismatched SOCs: A Qualitative Study on Security Operations Center Issues," in Proc. 2019 ACM SIGSAC Conf. Computer and Communications Security (CCS), pp. 1955-1970, 2019. 

[10] A. Madani, S. Rezayi and H. Gharaee, "Log management comprehensive architecture in Security Operation Center (SOC)," In 2011 International Conference on Computational Aspects of Social Networks (CASoN), pp. 284-289, 2011. 

[11] 	T. K.A, S. M.I.H, C. F and M. C, "Continuous auditing and threat detection in multi-cloud infrastructure," Computers & Security, vol. 102, pp. 1-26, 2021. 

[12]  M. Saraiva and M.M.V, "CyberSoc Incident Response Management Framework," Masters thesis, 2024.
