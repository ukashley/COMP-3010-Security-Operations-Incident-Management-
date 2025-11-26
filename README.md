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

• **Tier 1 (Triage Specialist):** Tier 1 analysts focus on monitoring alarms and alerts, removing false positives, and obtaining basic context to promptly escalate critical incidents. In the BOTSv3 dataset, identifying the IAM users accessing AWS services and finding the processor number used on the web servers mirrors this role. For example, a Tier 1 analyst could run a straightforward CloudTrail search to list IAM users involved in suspicious activity and check host hardware details to understand which assets are affected during triage. These Tier 1 activities mostly fall within the detection phase, with some contribution to response, as they provide the first validated view of what is happening before escalation (Vielberth et al 2020).

• **Tier 2 (Incident Responder):**  At tier 2, analysts review more critical incidents escalated by triage specialists, perform deeper detection, and are responsible for developing and implementing strategies to contain and recover from an incident.

## References
Vielberth, M., Böhm, F., Fichtinger, I. and Pernul, G. (2020) Security operations center: A systematic study and open challenges. Ieee Access, 8, pp.227756-227779.
