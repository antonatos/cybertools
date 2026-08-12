1. **Instrument removable media mount events to identify newly attached drives that may host malicious executables**
  1. Enable and collect Windows event logs related to device/volume arrival and mounting, such as Microsoft-Windows-DriverFrameworks-UserMode/Operational (Event ID 2003/2101) and Microsoft-Windows-Partition/Diagnostic logs where applicable
  2. Collect Windows Security and System logs capturing plug-and-play device installation and volume mount events, including events like 6416 ("A new external device was recognized by the system") on newer Windows versions
  3. Normalize removable media mount events into a field set that includes device identifier, volume name, drive letter, user context, host, and timestamp
  4. Tag mounted volumes as "removable" based on device type, bus type (e.g., USB) or policy information from endpoint management tools
  5. Maintain a short-lived state of recently mounted removable drives per host (e.g., last 24 hours) to support correlation with subsequent file write and execution events
2. **Collect and correlate file write activity to removable media volumes immediately after mount**
  1. Enable detailed file creation and write telemetry via Windows Event Logging (e.g., Security 4663 with object auditing), Sysmon (Event ID 11 FileCreate), or EDR file activity sensors
  2. Ensure file path fields allow distinguishing drive letters and UNC paths so that files written to removable media (e.g., E:\\, F:\\) can be positively identified
  3. Correlate file creation/write events occurring on the removable drive within a defined time window following mount (e.g., first 60–120 minutes) to build a list of newly staged tools or scripts
  4. Capture metadata such as file hash, publisher, digital signature status, original file name, PE characteristics, and file size for each file created on removable media
  5. Flag files written to removable drives from high-risk directories (e.g., C:\\Windows\\System32, user profile temp folders) or by processes associated with known malware or administrative tooling
  6. Persist associations between each removable drive mount and the set of files created on that drive for use in later execution and lateral movement correlation
3. **Monitor execution of binaries, scripts, and other executable content originating from the removable media**
  1. Enable process creation logging with full command line and image path details via Windows Security (Event ID 4688), Sysmon (Event ID 1), or EDR process telemetry
  2. Identify executions where the process image path or script interpreter arguments reference a removable drive letter (e.g., E:\\tool.exe, F:\\script.ps1) or mounted volume path
  3. Track child processes spawned by executables residing on removable media to detect multi-stage execution chains originating from the drive
  4. Record user context, parent process, working directory, and integrity level for any process executed from removable media to support behavioral analytics
  5. Apply simple allow/block lists or reputation checks to files executed from removable media, including verification of signatures and prevalence across the environment
  6. Correlate execution events with prior file write activity to determine whether the executed file was recently staged to the removable drive from another system
4. **Detect autorun usage and abuse associated with removable media**
  1. Monitor for the presence and modification of autorun configuration files such as autorun.inf on removable drives using file create and change telemetry
  2. Collect registry modifications related to AutoPlay and AutoRun settings under HKCU and HKLM paths (e.g., Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer) to identify attempts to enable or modify default behavior
  3. Log process executions of ShellExecute, explorer.exe, and other Windows shell components that automatically start programs from newly inserted media based on autorun configurations
  4. Correlate the creation or modification of autorun.inf and associated binaries on removable media with subsequent execution events triggered upon mount or user access
  5. Identify suspicious autorun entries that reference hidden files, uncommon extensions, or paths on removable drives that do not match typical installation media patterns
  6. Alert on removable media autorun sequences where the same tool or payload is executed across multiple hosts following drive insertion
5. **Identify lateral spread via staged tools on removable media across multiple hosts**
  1. Track removable drive identifiers (e.g., serial numbers, volume GUIDs) to recognize when the same physical media is mounted on different hosts within a defined time period
  2. Correlate file hashes and names of tools or payloads found on removable media across hosts to detect reuse of the same staged artifacts for lateral movement
  3. Detect patterns where a tool is first written to a removable drive on one host, then subsequently executed from that drive on another host, indicating potential lateral spread
  4. Monitor for repeated execution of administrative tools, remote access software, or known offensive security frameworks from removable media across different user accounts and systems
  5. Use timelines combining mount events, file writes, and process executions to reconstruct cross-host propagation chains driven by removable media usage
  6. Prioritize lateral spread detections that involve privileged accounts, domain-joined systems, or hosts in sensitive network segments
6. **Apply behavioral rules and analytics to detect suspicious patterns of execution from removable media**
  1. Define baseline profiles of legitimate removable media usage (e.g., corporate-approved installation media, backup drives) to distinguish them from anomalous activity
  2. Create detection rules that trigger when executables on removable media are launched immediately or shortly after mount, especially by non-administrative users
  3. Develop analytics that score behaviors such as unsigned binaries running from removable drives, rare or newly observed hashes, uncommon file paths, or unusual parent processes
  4. Combine signals from autorun activity, rapid multi-host execution, and rare tools staged on removable media to elevate risk scores for potential T1091 events
  5. Use frequency analysis to identify users or hosts with abnormally high levels of removable media-based execution compared to their historical behavior
  6. Continuously tune behavioral thresholds based on false positive analysis while preserving sensitivity to rare but high-impact removable media attacks
7. **Integrate detections into alerting, triage, and response processes for T1091 on Windows**
  1. Map detection rules and analytics explicitly to MITRE ATT&CK technique T1091 for consistency in reporting and threat hunting
  2. Configure SIEM or EDR alerting to generate incidents when correlations between removable drive mount, file staging, and execution are observed within suspicious time windows
  3. Include context such as drive identifier, involved hosts, user accounts, file hashes, and autorun artifacts in alerts to support rapid triage
  4. Define playbook actions for responders, such as isolating affected hosts, collecting volatile data, and preserving copies of suspect removable media for analysis
  5. Ensure that detection outputs feed back into threat hunting and intelligence processes to refine future rules and improve coverage for removable media-based lateral movement
  6. Regularly review detection efficacy against known T1091 case studies and lab simulations to validate that alerts capture execution of files originating from removable media after drive mount with correlation to file write activity, autorun usage, and lateral spread via staged tools