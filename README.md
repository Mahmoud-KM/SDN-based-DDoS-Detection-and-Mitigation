There are Three files in this repository, apart from the README file.
1- detection_8hosts.CVS  : Results datasets 
2- dynamic_traffic_ewma.py : Software Defined Networking (SDN) controller code runned in RYU Controller
3- multihost_topology.py : Network Topology runned in Mininet simulation environment

This is the second version of my work, implemented under Exponentially Weighted Moving Average (EWMA) and K factor dynamic
The first version will be uploaded later: which uses adaptive threshold with static values (k & mean)
Actual work consist of using Entropy detection method in combination EWMA as : threshold > emwa_k.dynamic and threshold > Entropy.
This approach conscist of another later of detection, then mitigate.
Once this done with a comprehensive approach, I am planning to implement a machine learning approach on top of the above to put another layer of detection, then mitigate.

===========================================================================================================================================================================

**ABSTRACT**

Software-Defined Networking (SDN) is an architectural approach that centralizes network management by separating the control plane from the data plane, enabling centralized, programmable, and flexible network management. This architecture is widely used in data centers, cloud networks, and enterprises for easier management and rapid traffic adaptation.
Furthermore, a network can be the target for Distributed Denial of Service (DDoS) attacks, where malicious traffic floods the network, causing congestion, packet loss, and service disruption. Common attacks include TCP SYN, UDP, and ICMP floods among other. 
This project uses an SDN controller to detect and mitigate DDoS attacks. The SDN controller continuously monitor the traffic, using an adaptive threshold approach suspicious flows are detected, dropped to protect both the controller and the network while maintaining normal service.
Our research objectives are to:
- Evaluate the performance of SDN-based Adaptive threshold mechanism in DDoS detection, 
- Develop an efficient mitigation strategy based on the detection mechanism.


**METHODOLOGY**

We used a Mininet SDN testbed of 8 hosts across 3 switches, controlled by a Ryu controller, which polls per-flow statistics every 5 seconds to monitor packet rates per source IP. The controller tracks traffic behavior using an Exponentially Weighted Moving Average (EWMA), which gives more weight to recent observations while smoothing out short-term fluctuations:
         **EWMAnew​=λ×rate+(1−λ)×EWMAold​(λ=0.125)**
The detection threshold adapts dynamically through a sensitivity factor k, which scales based on the Coefficient of Variation (CV = std / mean) of observed traffic:   
          **k=clamp(KBASE​+CVSCALE​×CV,KMIN​,KMAX​)**

         **Threshold=EWMA+k×max(σEWMA, MIN_STD)**
         
k adapts to traffic: tighter for stable, looser for bursty; MIN_STD avoids collapse. EWMA updates only on normal traffic to prevent drift.  Detected sources are blocked for 60s, then auto re-evaluated.


**EXPERMIENT AND RESULTS
**

We evaluated the system in Mininet using a multi-host SDN topology with 4 simultaneous attackers generating TCP SYN, UDP, ICMP, and mixed DDoS traffic, while legitimate traffic remained active. The controller polled flow statistics every 5s and applied the adaptive EWMA + dynamic k threshold for real-time detection.
Across all scenarios, 1,832 mitigation events were recorded: ICMP (56.2%), TCP SYN (22.5%), mixed ICMP+TCP (10.6%), mixed TCP+UDP (7.0%), and UDP (3.6%). All attackers were detected and blocked independently using flow-level rules.

**CONCLUSION
**

SDN enables real-time DDoS detection and mitigation through centralized control. The adaptive threshold (EWMA + dynamic sensitivity) effectively distinguishes attack traffic from normal behavior, outperforming static approaches. Malicious flows are quickly dropped across all switches, ensuring uninterrupted legitimate traffic.
Future improvements include entropy-based detection and machine learning models to enhance detection accuracy and enable early attack prediction.


