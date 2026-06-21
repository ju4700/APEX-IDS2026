Literature Review: The Evolution and Methodological Critique of Network Intrusion Detection (NIDS) Datasets


1. Introduction to the NIDS Evaluation Landscape
The efficacy of machine-learning-based Network Intrusion Detection Systems (NIDS) is inextricably linked to the quality and representativeness of the underlying training datasets. Within the current research paradigm, there exists a pronounced divergence—often termed the "Expectations Versus Reality" gap—where high-performance metrics reported in academic literature (frequently exceeding 0.99 F1 scores) fail to translate into operational effectiveness during practical deployment.The primary catalyst for this failure is a systemic lack of standardisation across the evaluation landscape. Comparative analysis is frequently stymied by the absence of universal benchmarks for network environments, attack vectors, and protocol technologies. This inconsistency forces researchers to evaluate architectures on disparate datasets, each with unique labelling methodologies and traffic characteristics. Consequently, a system may demonstrate exceptional performance in a controlled, synthetic environment while lacking the necessary robustness to navigate the "concept drift" and nuanced traffic patterns found in live production networks. To bridge this gap, the community must shift from reporting inflated results on static benchmarks to prioritising real-world generalisability.
2. The Legacy of Synthetic Benchmarks: From KDD99 to CICIDS2017
Early NIDS research was underpinned by a handful of foundational synthetic benchmarks. While these provided the necessary sandbox for the nascent development of machine-learning classifiers, they are now widely regarded as insufficient for modern security requirements.
Limitations of Legacy Datasets
Dataset
	Historical Significance
	Modern Exclusion Reason
	KDD-Cup '99
	Foundational benchmark for early multiclass classification research.
	Non-representative legacy benchmark; outdated attack profiles; lacks raw pcap files for modern feature extraction.
	NSL-KDD
	Designed to mitigate specific statistical biases (e.g., redundant records) in KDD-Cup '99.
	Lacks pcap files; features are insufficient for evaluating modern flow-based or deep-learning architectures.
	CAIDA
	A critical resource for early DDoS and internet trace study.
	Heavily anonymised and unlabelled; inability to provide ground truth for training supervised or autoencoder-based systems.
	ISCX2012
	One of the first systematic attempts to generate reproducible benchmarks.
	Outdated; lacks the comprehensive feature sets provided by second-generation datasets.
	The evolution from these foundational sets led to "first-generation" modern benchmarks, most notably  UNSW-NB15  and  CICIDS2017 . UNSW-NB15 provided a significant leap in complexity, offering 49 features and 9 distinct attack types captured over a 48-hour duration. CICIDS2017 further expanded the evaluation landscape with its extraction of 80 features across five days of traffic. These datasets represented a critical attempt to balance legitimate and malicious traffic while introducing modern attack categories. However, as network environments become increasingly decentralised, even these extensive datasets are showing signs of age, particularly in the face of domain-specific threats.
3. The Specialisation of IoT-Centric Datasets
The proliferation of the Internet of Things (IoT) has necessitated a shift towards domain-specific telemetry to address unique architectural vulnerabilities. Datasets such as  BoT-IoT ,  ToN-IoT , and  Stratosphere IoT (CTU-23)  have emerged to fill this void, focusing on botnet behaviours and emulated smart-environment traffic.A critical observation from recent performance analysis is the high degree of variability in NIDS performance across these specialised sets. For instance, while a Deep Neural Network (DNN) can achieve an impressive average F1 score of 0.8537 across general datasets, its performance often plummets when applied to specific IoT contexts. A pronounced divergence is seen in the Kitsune architecture, which achieves an accuracy of 0.9923 on the BoT-IoT dataset but falls to 0.5540 on CICIDS2017.Key IoT Datasets:
* BoT-IoT & ToN-IoT:  These datasets provide a mix of legitimate and emulated IoT traffic, serving as a robust testing ground for detecting automated botnet propagation.
* Stratosphere IoT (CTU-23):  Unlike heavily emulated sets, Stratosphere focuses on realistic threat and behavioural representation, providing the "normative profile" essential for anomaly detection.
* Mirai (Kitsune):  A dataset dedicated to capturing the lifecycle of the Mirai botnet, specifically designed to evaluate the plug-and-play efficacy of the Kitsune ensemble of autoencoders.Researcher analysis suggests that the discrepancy between high performance on BoT-IoT and lower results on Stratosphere requires further investigation into the inherent differences between emulated and realistic traffic, as the latter poses a significantly higher challenge for modern classifiers.
4. Critical Methodology Critique: "Bad Design Smells" and Practical Barriers
The "Expectations Versus Reality" gap is largely symptomatic of what we describe as "bad design smells" in current dataset and NIDS development methodologies. These flaws do not merely complicate research; they act as a fundamental barrier to scientific reproducibility.
1. The Usability Crisis and Invalidated Systems:  Recent studies reveal a crisis in academic software engineering. Over 10 modern NIDS investigated were invalidated due to runtime or dependency errors. A specific, recurring failure is the incompatibility between Keras and Tensorflow versions—notably causing "Tensors found on two or more devices" errors. The absence of provided virtualised environments makes most academic codebases nearly impossible to deploy "out of the box."
2. The Pcap/Flow Discrepancy:  Converting between raw packets (pcaps) and processed flows is non-trivial. When dataset authors fail to provide both, researchers must rely on third-party extractors, which introduces additional noise and potentially skews the diagnostic results of the evaluation.
3. Absence of Benign Baselines:  Many anomaly-based IDSs, such as Kitsune or HELAD, require a "normative profile" of benign traffic to function. However, training these models on "initial benign traffic" in datasets that are not scenario-specific often results in inadequate performance, failing to provide a proper baseline for real-world anomalies.
4. Data Wrangling and Error-Prone Output:  The intensive process of dataset creation often leads to "error-prone output," requiring practitioners to engage in extensive modification before a dataset is usable for standardised testing.
5. Transitioning to Real-World Telemetry and Honeypot Data
To mitigate the inherent biases of synthetic data, there is a burgeoning movement toward real-world telemetry derived from honeypots. The  Kyoto  dataset remains a notable example of unsimulated data, offering a more challenging and realistic perspective for NIDS evaluation than generated datasets.Contemporary honeypot telemetry, such as the nfcapd flow data, offers a superior level of ground truth. In these datasets, flows are marked as  "Attack_Verified"  (as seen in the label column of verified flow data), providing higher confidence scores than emulated traffic. This allows for the granular detection of evolving threat vectors like Port-81-Scan and HTTP-Alt-Probe.
Anatomy of Modern Honeypot Telemetry Based on verified nfcapd flow telemetry
Feature
	Example Data
	Diagnostic Value for NIDS
	Attack Type
	Port-81-Scan, Telnet-Brute
	Enables granular detection of specific, evolving adversarial behaviours.
	MITRE Technique
	T1046 (Discovery), T1110 (Brute Force)
	Aligns system alerts with industry-standard adversarial frameworks for faster incident response.
	MITRE Tactic
	discovery, credential-access
	Identifies the specific stage of the attack lifecycle (e.g., initial-access).
	Confidence Score
	honeypot-verified
	Utilises honeypot:port-match evidence to provide a high-fidelity ground truth for supervised learning.
	Attack Category
	reconnaissance, brute-force
	Categorises the broad intent of the flow to assist in multi-class classification.
	By utilising dynamic telemetry that accounts for "concept drift," researchers can ensure that NIDS remain effective against shifting attacker behaviours that static benchmarks like CICIDS2017 inevitably fail to capture.
6. Setting the Stage for a New Generation Dataset
Closing the gap between research and practice requires a "Next-Gen" philosophy in dataset design. We must move beyond the era of inflated F1 scores and prioritise transparency, reproducibility, and deployment-ready frameworks. Mandatory Requirements for Next-Gen NIDS Datasets:
1. Availability of Raw Pcaps:  To eliminate the information loss inherent in third-party feature extraction and ensure compatibility across packet-based and flow-based systems.
2. Verified Ground Truth:  Moving beyond simple emulated labels to use honeypot-match and threat intelligence scores, ensuring high-confidence labelling (e.g., "Attack_Verified").
3. Mandatory Virtualisation:  Future datasets must be bundled with virtualised environments (Docker or VMs) to eliminate the dependency errors that currently invalidate the majority of NIDS research.
4. Scenario-Specific Benign Baselines:  To improve the effectiveness of autoencoder-based systems and reduce the false-positive rates that currently plague operational deployments.Only by addressing these methodological failures can the research community produce NIDS architectures that provide genuine, verifiable protection in the complex networking environments of the future.
7. References
* Ahmad, R., Alsmadi, I., Alhamdani, W., & Tawalbeh, L. (2022).  A comprehensive deep learning benchmark for IoT IDS.  Computers & Security , 114, 102588.
* Hesford, J., Cheng, D., Wan, A., Huynh, L., Kim, S., Kim, H., & Hong, J. B. (2024).  Expectations Versus Reality: Evaluating Intrusion Detection Systems in Practice.  arXiv:2403.17458v2 .
* Moustafa, N., & Slay, J. (2015).  UNSW-NB15: a comprehensive data set for network intrusion detection systems.  IEEE Military Communications and Information Systems Conference (MilCIS) .
* Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018).  Toward generating a new intrusion detection dataset and intrusion traffic characterization.  ICISSp .
* Zhong, Y., Chen, W., Wang, Z., et al. (2020).  HELAD: A novel network anomaly detection model based on heterogeneous ensemble learning.  Computer Networks , 169, 107049.