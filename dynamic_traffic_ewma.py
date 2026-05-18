###############                  ####################
#                                                   #
#   Last Modified: April 8, Wednesday 2026          #
#   Added: Adaptive Threshold Detection             #
#           DDoS Mitigation (drop rules)            #
#           Detection CSV logging                   #
###############                  ####################

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp as arp_proto
from ryu.lib.packet import tcp, udp
import csv
import time
import ipaddress
import collections
import math


# ── Global constants ─────────────────────────────────────────────────────────

POLL_INTERVAL    = 5      # seconds — poll cycle length, used for rate calculation

# ── EWMA parameters ───────────────────────────────────────────────────────────
# Reference: Cisar & Cisar (2007) — EWMA Statistic in Adaptive Threshold Algorithm
#
# EWMA formula:  ewma_new = LAMBDA * rate + (1 - LAMBDA) * ewma_old
#
# LAMBDA (smoothing factor, 0 < λ < 1):
#   - Small λ (e.g. 0.05) = slow adaptation, very stable baseline, slow to follow
#     legitimate traffic growth — good for stable networks
#   - Large λ (e.g. 0.3)  = fast adaptation, tracks traffic changes quickly —
#     risk of baseline following attack ramp-up if attack is gradual
#   - λ = 0.125 is recommended by Cisar & Cisar as balanced starting point
#     (equivalent weight to roughly last 8 observations)
EWMA_LAMBDA      = 0.125

# Minimum number of poll cycles before detection starts
# Gives EWMA time to converge on a stable baseline before comparing
# 10 cycles × 5s = 50 seconds of warmup
WARMUP_CYCLES    = 10

# ── Dynamic k parameters ──────────────────────────────────────────────────────
# Instead of fixed k=2.0, k adapts based on traffic stability (CV = std/mean)
#
# Coefficient of Variation (CV) measures relative traffic variability:
#   CV = ewma_std / ewma   (normalized — works across different traffic scales)
#
# Logic:
#   - Stable traffic   (low CV)  → tighten k → catch subtle attacks earlier
#   - Bursty traffic   (high CV) → loosen k → avoid false positives on bursts
#
# k is clamped between K_MIN and K_MAX to prevent extreme values
K_BASE           = 2.0   # base sensitivity (lecturer's x2 rule)
K_MIN            = 1.5   # tightest threshold — very stable traffic
K_MAX            = 3.5   # loosest threshold  — very bursty traffic
CV_SCALE         = 2.0   # how aggressively k responds to CV changes
                         # k = K_BASE + CV_SCALE * CV, clamped to [K_MIN, K_MAX]

# ── Minimum EWMA std ──────────────────────────────────────────────────────────
# Prevents threshold collapsing to zero on perfectly flat/idle traffic
# Without this, std=0 gives threshold=ewma, flagging any tiny fluctuation
MIN_EWMA_STD     = 10.0

# ── Mitigation parameters ─────────────────────────────────────────────────────
BLOCK_DURATION      = 60   # seconds — OVS hard_timeout auto-removes drop rule
MITIGATION_PRIORITY = 100  # drop rules beat all other rules (IP=10, ARP=5, miss=0)


class TrafficMonitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}

    def __init__(self, *args, **kwargs):
        super(TrafficMonitor, self).__init__(*args, **kwargs)

        # ── Core switch state ─────────────────────────────────────────────
        self.datapaths    = {}
        self.mac_to_port  = {}
        self.prev_stats   = {}
        self._flow_buffer = {}

        # ── EWMA adaptive threshold state ─────────────────────────────────
        # Per (switch_id, src_ip, ingress_port) EWMA state:
        #   ewma     — exponentially weighted moving average of pkt_rate
        #   ewma_var — exponentially weighted variance (for std calculation)
        #   cycles   — number of observations so far (used for warmup check)
        #
        # Using defaultdict so first access auto-initialises to None
        self.ewma_state = collections.defaultdict(
            lambda: {'ewma': None, 'ewma_var': 0.0, 'cycles': 0}
        )

        # Blocked IPs: src_ip -> unblock timestamp
        self.blocked = {}

        self.monitor_thread = hub.spawn(self._monitor)

        ts = int(time.time())

        # ── Flow stats CSV ────────────────────────────────────────────────
        self.flow_file   = open(f'flow_stats_{ts}.csv', 'w', newline='')
        self.flow_writer = csv.writer(self.flow_file)
        self.flow_writer.writerow([
            'timestamp', 'switch_id',
            'src_ip', 'dst_ip',
            'ingress_port',
            'packet_count', 'byte_count',
            'pkt_rate', 'byte_rate',
            'ip_proto', 'duration_sec'
        ])

        # ── Aggregate stats CSV ───────────────────────────────────────────
        self.aggregate_file   = open(f'aggregate_stats_{ts}.csv', 'w', newline='')
        self.aggregate_writer = csv.writer(self.aggregate_file)
        self.aggregate_writer.writerow([
            'timestamp', 'switch_id',
            'src_ip', 'ingress_port',
            'total_pkt_rate', 'total_byte_rate',
            'flow_count'
        ])

        # ── Port stats CSV ────────────────────────────────────────────────
        self.port_file   = open(f'port_stats_{ts}.csv', 'w', newline='')
        self.port_writer = csv.writer(self.port_file)
        self.port_writer.writerow([
            'timestamp', 'switch_id',
            'port_no',
            'rx_packets', 'tx_packets',
            'rx_bytes',   'tx_bytes'
        ])

        # ── Detection log CSV ─────────────────────────────────────────────
        # Logs every observation with detection state for poster graphs:
        # shows normal baseline -> attack spike -> threshold -> mitigation -> recovery
        self.detection_file   = open(f'detection_log_{ts}.csv', 'w', newline='')
        self.detection_writer = csv.writer(self.detection_file)
        self.detection_writer.writerow([
            'timestamp', 'switch_id',
            'src_ip', 'ingress_port',
            'pkt_rate',        # current observed rate this cycle
            'ewma',            # EWMA baseline (replaces simple mean)
            'ewma_std',        # EWMA standard deviation
            'dynamic_k',       # adaptive k factor based on traffic CV
            'threshold',       # ewma + dynamic_k * max(ewma_std, MIN_EWMA_STD)
            'cv',              # coefficient of variation = ewma_std / ewma
            'alert',           # 1=attack detected, 0=normal
            'mitigated',       # 1=drop rule installed this cycle, 0=no action
            'phase',           # 'warmup' | 'normal' | 'attack' | 'mitigated'
            'dominant_proto',  # ICMP | TCP | UDP | MIXED
            'attack_type'      # human-readable attack classification
        ])

        self.logger.info(
            "TrafficMonitor started | lambda=%.3f | warmup=%d cycles | "
            "k=[%.1f-%.1f] | block=%ds",
            EWMA_LAMBDA, WARMUP_CYCLES, K_MIN, K_MAX, BLOCK_DURATION
        )

    # ── Helper ────────────────────────────────────────────────────────────────

    def is_valid_ip(self, value):
        try:
            ipaddress.IPv4Address(str(value))
            return True
        except ValueError:
            return False

    # ── Switch lifecycle ──────────────────────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions,
                 buffer_id=None, hard_timeout=0):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        inst    = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                actions)]
        kwargs  = dict(datapath=datapath, priority=priority,
                       match=match, instructions=inst,
                       hard_timeout=hard_timeout)
        if buffer_id:
            kwargs['buffer_id'] = buffer_id
        datapath.send_msg(parser.OFPFlowMod(**kwargs))

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.logger.info("Switch connected: %016x", datapath.id)
            self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id is None:
                return
            self.logger.info("Switch disconnected: %016x", datapath.id)
            self.datapaths.pop(datapath.id, None)
            self._flow_buffer.pop(datapath.id, None)
            self.prev_stats = {
                k: v for k, v in self.prev_stats.items()
                if k[0] != datapath.id
            }

    # ── Monitoring loop ───────────────────────────────────────────────────────

    def _monitor(self):
        while True:
            # Clean up expired blocks each cycle
            now     = time.time()
            expired = [ip for ip, t in self.blocked.items() if now > t]
            for ip in expired:
                del self.blocked[ip]
                self.logger.info("UNBLOCKED: %s block expired after %ds",
                                 ip, BLOCK_DURATION)

            for dp in list(self.datapaths.values()):
                self._request_stats(dp)
            hub.sleep(POLL_INTERVAL)

    def _request_stats(self, datapath):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        datapath.send_msg(parser.OFPFlowStatsRequest(datapath))
        datapath.send_msg(parser.OFPPortStatsRequest(datapath, 0,
                                                     ofproto.OFPP_ANY))

    # ── Packet-in handler ─────────────────────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match['in_port']

        pkt     = packet.Packet(msg.data)
        eth     = pkt.get_protocols(ethernet.ethernet)[0]
        ip_pkt  = pkt.get_protocol(ipv4.ipv4)
        arp_pkt = pkt.get_protocol(arp_proto.arp)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst  = eth.dst
        src  = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions  = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:

            if ip_pkt:
                # Priority 10 — IP rule
                # L4 ports excluded: one flow per (src, dst, proto)
                # keeps aggregate stats clean for per-source detection
                match = parser.OFPMatch(
                    in_port  = in_port,
                    eth_type = 0x0800,
                    ipv4_src = ip_pkt.src,
                    ipv4_dst = ip_pkt.dst,
                    ip_proto = ip_pkt.proto
                )
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 10, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 10, match, actions)

            elif arp_pkt:
                # Priority 5 — ARP rule
                # Lower than IP rules so IP always wins for IP packets
                match = parser.OFPMatch(
                    in_port  = in_port,
                    eth_type = 0x0806,
                    eth_dst  = dst,
                    eth_src  = src
                )
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 5, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 5, match, actions)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out  = parser.OFPPacketOut(
                    datapath  = datapath,
                    buffer_id = msg.buffer_id,
                    in_port   = in_port,
                    actions   = actions,
                    data      = data
               )
        datapath.send_msg(out)

    # ── Flow stats reply ──────────────────────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        datapath  = ev.msg.datapath
        switch_id = datapath.id
        timestamp = time.time()

        if switch_id not in self._flow_buffer:
            self._flow_buffer[switch_id] = []
        self._flow_buffer[switch_id].extend(ev.msg.body)

        if ev.msg.flags & datapath.ofproto.OFPMPF_REPLY_MORE:
            return

        full_body = self._flow_buffer.pop(switch_id, [])
        self._process_flow_stats(switch_id, datapath, timestamp, full_body)

    # ── Flow stats processor ──────────────────────────────────────────────────

    def _process_flow_stats(self, switch_id, datapath, timestamp, body):

        ip_stats = {}

        for stat in body:

            # Accept priority 10 (IP rules) and 5 (ARP rules) only
            # Skip table-miss (0) and mitigation drop rules (100)
            if stat.priority not in (5, 10):
                continue

            src_ip       = stat.match.get('ipv4_src')
            dst_ip       = stat.match.get('ipv4_dst')
            ingress_port = stat.match.get('in_port')
            ip_proto     = stat.match.get('ip_proto')
            proto_name   = self.PROTO_MAP.get(ip_proto, 'N/A')
            duration     = stat.duration_sec or 0

            if not src_ip or not self.is_valid_ip(src_ip):
                continue

            # Rate calculation — delta from previous poll
            flow_key = (switch_id, src_ip, dst_ip, ingress_port, ip_proto)
            prev     = self.prev_stats.get(flow_key)

            if prev:
                pkt_rate  = max(0.0, (stat.packet_count - prev['pkts'])  / POLL_INTERVAL)
                byte_rate = max(0.0, (stat.byte_count   - prev['bytes']) / POLL_INTERVAL)
            else:
                pkt_rate  = 0.0
                byte_rate = 0.0

            self.prev_stats[flow_key] = {
                'pkts':  stat.packet_count,
                'bytes': stat.byte_count
            }

            self.flow_writer.writerow([
                timestamp, switch_id,
                src_ip,
                dst_ip       or 'N/A',
                ingress_port or 'N/A',
                stat.packet_count,
                stat.byte_count,
                round(pkt_rate,  2),
                round(byte_rate, 2),
                proto_name,
                duration
            ])
            self.flow_file.flush()

            self.logger.info(
                "Flow: switch=%s src=%s dst=%s port=%s "
                "pkts=%d bytes=%d pkt_rate=%.1f byte_rate=%.1f proto=%s dur=%ds",
                switch_id, src_ip, dst_ip, ingress_port,
                stat.packet_count, stat.byte_count,
                pkt_rate, byte_rate, proto_name, int(duration)
            )

            agg_key = (src_ip, ingress_port)
            if agg_key not in ip_stats:
                ip_stats[agg_key] = {
                    'pkt_rate':   0.0,
                    'byte_rate':  0.0,
                    'flow_count': 0,
                    # Per-protocol rate breakdown — used to classify attack type
                    'icmp_rate':  0.0,
                    'tcp_rate':   0.0,
                    'udp_rate':   0.0,
                }
            ip_stats[agg_key]['pkt_rate']   += pkt_rate
            ip_stats[agg_key]['byte_rate']  += byte_rate
            ip_stats[agg_key]['flow_count'] += 1
            # Accumulate per-protocol rates for attack classification
            if ip_proto == 1:
                ip_stats[agg_key]['icmp_rate'] += pkt_rate
            elif ip_proto == 6:
                ip_stats[agg_key]['tcp_rate']  += pkt_rate
            elif ip_proto == 17:
                ip_stats[agg_key]['udp_rate']  += pkt_rate

        for (src_ip, ingress_port), stats in ip_stats.items():
            total_pkt_rate  = round(stats['pkt_rate'],  2)
            total_byte_rate = round(stats['byte_rate'], 2)

            self.aggregate_writer.writerow([
                timestamp, switch_id,
                src_ip, ingress_port,
                total_pkt_rate, total_byte_rate,
                stats['flow_count']
            ])
            self.logger.info(
                "AGG: switch=%s src=%s port=%s flows=%d pkt_rate=%.1f byte_rate=%.1f",
                switch_id, src_ip, ingress_port,
                stats['flow_count'], total_pkt_rate, total_byte_rate
            )

            # Run adaptive threshold detection for this source
            self._detect_and_mitigate(
                switch_id, datapath, timestamp,
                src_ip, ingress_port, total_pkt_rate,
                stats['icmp_rate'], stats['tcp_rate'], stats['udp_rate']
            )

        self.aggregate_file.flush()

    # ── EWMA Adaptive Threshold Detection with Dynamic k ─────────────────────
    #
    # Algorithm (based on Cisar & Cisar 2007, simplified per lecturer guidance):
    #
    # 1. EWMA update (every normal cycle):
    #       ewma     = λ × rate    + (1-λ) × ewma_old
    #       ewma_var = λ × (rate - ewma)² + (1-λ) × ewma_var_old
    #       ewma_std = sqrt(ewma_var)
    #
    # 2. Dynamic k (adapts to traffic burstiness):
    #       CV    = ewma_std / ewma          (coefficient of variation)
    #       k     = K_BASE + CV_SCALE × CV   (more bursty → looser threshold)
    #       k     = clamp(k, K_MIN, K_MAX)
    #
    # 3. Threshold:
    #       threshold = ewma + k × max(ewma_std, MIN_EWMA_STD)
    #
    # 4. Detection:
    #       if rate > threshold → ATTACK → install drop rule
    #
    # 5. Baseline protection:
    #       EWMA is only updated during NORMAL traffic
    #       Attack samples never pollute the baseline
    #       This prevents the threshold from drifting upward under attack
    # ─────────────────────────────────────────────────────────────────────────

    def _detect_and_mitigate(self, switch_id, datapath, timestamp,
                              src_ip, ingress_port, pkt_rate,
                              icmp_rate=0.0, tcp_rate=0.0, udp_rate=0.0):

        state = self.ewma_state[(switch_id, src_ip, ingress_port)]

        alert     = 0
        mitigated = 0
        phase     = 'warmup'
        dynamic_k = K_BASE
        cv        = 0.0

        # ── Protocol classification ───────────────────────────────────────
        # dominant_proto identifies the protocol driving the traffic
        # attack_type is only labelled when an alert fires — otherwise Normal
        proto_rates = {'ICMP': icmp_rate, 'TCP': tcp_rate, 'UDP': udp_rate}
        dominant    = max(proto_rates, key=proto_rates.get)
        total       = icmp_rate + tcp_rate + udp_rate

        if total > 0:
            ratios = {k: v/total for k, v in proto_rates.items() if v > 0}
            active = [k for k, r in ratios.items() if r > 0.2]
            if len(active) >= 3:
                dominant_proto = 'MIXED'
                detected_type  = 'Mixed DDoS (ICMP + TCP + UDP)'
            elif len(active) == 2:
                dominant_proto = '+'.join(sorted(active))
                detected_type  = f'Mixed DDoS ({dominant_proto})'
            else:
                dominant_proto = dominant
                detected_type  = {
                    'ICMP': 'ICMP Flood',
                    'TCP':  'TCP SYN Flood',
                    'UDP':  'UDP Flood'
                }.get(dominant, 'Unknown')
        else:
            dominant_proto = 'N/A'
            detected_type  = 'Normal'

        # attack_type shown only when alert fires — Normal otherwise
        # This prevents warmup/normal phases from showing attack labels
        attack_type = detected_type  # will be overridden to Normal if no alert

        # ── EWMA initialisation on first observation ──────────────────────
        if state['ewma'] is None:
            state['ewma']     = pkt_rate
            state['ewma_var'] = 0.0
            state['cycles']   = 1
            self.detection_writer.writerow([
                timestamp, switch_id, src_ip, ingress_port,
                round(pkt_rate, 2),
                round(state['ewma'], 2),
                0.0, K_BASE, round(state['ewma'] * K_BASE, 2), 0.0,
                0, 0, 'warmup', dominant_proto, 'Normal'
            ])
            self.detection_file.flush()
            return

        # ── Compute current EWMA and dynamic threshold ────────────────────
        ewma     = state['ewma']
        ewma_var = state['ewma_var']
        ewma_std = math.sqrt(ewma_var) if ewma_var > 0 else 0.0

        # Coefficient of Variation — normalised measure of traffic burstiness
        # CV = 0 means perfectly flat traffic → tighten k
        # CV = 1 means std equals mean → very bursty → loosen k
        cv = (ewma_std / ewma) if ewma > 0 else 0.0

        # Dynamic k — scales with burstiness
        # More bursty traffic gets a looser threshold to avoid false positives
        dynamic_k = K_BASE + CV_SCALE * cv
        dynamic_k = max(K_MIN, min(K_MAX, dynamic_k))  # clamp to safe range

        # Threshold: EWMA baseline + dynamic_k × variability
        threshold = ewma + dynamic_k * max(ewma_std, MIN_EWMA_STD)

        # ── Warmup period — observe but don't alert ───────────────────────
        if state['cycles'] < WARMUP_CYCLES:
            phase = 'warmup'
            # Update EWMA during warmup regardless — we're learning
            state['ewma']     = EWMA_LAMBDA * pkt_rate + (1 - EWMA_LAMBDA) * ewma
            state['ewma_var'] = EWMA_LAMBDA * (pkt_rate - state['ewma'])**2 \
                                + (1 - EWMA_LAMBDA) * ewma_var
            state['cycles']  += 1

            self.detection_writer.writerow([
                timestamp, switch_id, src_ip, ingress_port,
                round(pkt_rate,   2), round(ewma,      2),
                round(ewma_std,   2), round(dynamic_k, 2),
                round(threshold,  2), round(cv,        4),
                0, 0, 'warmup', dominant_proto, 'Normal'
            ])
            self.detection_file.flush()
            self.logger.info(
                "WARMUP [%d/%d]: src=%s rate=%.1f ewma=%.1f k=%.2f threshold=%.1f",
                state['cycles'], WARMUP_CYCLES, src_ip,
                pkt_rate, ewma, dynamic_k, threshold
            )
            return

        # ── Detection phase — warmup complete ────────────────────────────
        phase       = 'normal'
        attack_type = 'Normal'  # default — only overridden when alert fires

        if pkt_rate > threshold:
            alert       = 1
            phase       = 'attack'
            attack_type = detected_type  # now show the real attack label

            if src_ip not in self.blocked:
                self._install_drop_rule(datapath, src_ip)
                self.blocked[src_ip] = time.time() + BLOCK_DURATION
                mitigated = 1
                phase     = 'mitigated'
                self.logger.warning(
                    "*** ATTACK DETECTED & BLOCKED *** "
                    "src=%s switch=%s port=%s type=%s "
                    "rate=%.1f ewma=%.1f k=%.2f threshold=%.1f cv=%.3f",
                    src_ip, switch_id, ingress_port, attack_type,
                    pkt_rate, ewma, dynamic_k, threshold, cv
                )
            else:
                mitigated = 1
                phase     = 'mitigated'
                self.logger.info(
                    "ATTACK ONGOING (blocked): src=%s rate=%.1f threshold=%.1f",
                    src_ip, pkt_rate, threshold
                )

        # ── Update EWMA only during normal traffic ────────────────────────
        # Critical: attack samples must NOT shift the baseline upward
        # If they did, the threshold would rise and stop detecting the attack
        if alert == 0:
            state['ewma']     = EWMA_LAMBDA * pkt_rate + (1 - EWMA_LAMBDA) * ewma
            state['ewma_var'] = EWMA_LAMBDA * (pkt_rate - state['ewma'])**2 \
                                + (1 - EWMA_LAMBDA) * ewma_var
            state['cycles']  += 1

        # ── Log detection event ───────────────────────────────────────────
        self.detection_writer.writerow([
            timestamp, switch_id, src_ip, ingress_port,
            round(pkt_rate,   2), round(ewma,      2),
            round(ewma_std,   2), round(dynamic_k, 2),
            round(threshold,  2), round(cv,        4),
            alert, mitigated, phase,
            dominant_proto, attack_type
        ])
        self.detection_file.flush()

        self.logger.info(
            "DETECT: src=%s port=%s rate=%.1f ewma=%.1f std=%.1f "
            "k=%.2f cv=%.3f threshold=%.1f alert=%d phase=%s type=%s",
            src_ip, ingress_port, pkt_rate, ewma, ewma_std,
            dynamic_k, cv, threshold, alert, phase, attack_type
        )

    # ── Drop rule installation ────────────────────────────────────────────────

    def _install_drop_rule(self, datapath, src_ip):
        parser = datapath.ofproto_parser
        # Match ALL IP traffic from attacker — protocol-agnostic block
        match  = parser.OFPMatch(
            eth_type = 0x0800,
            ipv4_src = src_ip
        )
        # Empty actions = DROP
        # priority 100 beats everything
        # hard_timeout = OVS auto-removes after BLOCK_DURATION seconds
        self.add_flow(
            datapath,
            priority     = MITIGATION_PRIORITY,
            match        = match,
            actions      = [],
            hard_timeout = BLOCK_DURATION
        )
        self.logger.warning(
            "DROP RULE: src=%s switch=%s priority=%d duration=%ds",
            src_ip, datapath.id, MITIGATION_PRIORITY, BLOCK_DURATION
        )

    # ── Port stats reply ──────────────────────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        timestamp = time.time()
        switch_id = ev.msg.datapath.id

        for stat in ev.msg.body:
            if stat.port_no == 0xFFFFFFFE:
                continue

            self.port_writer.writerow([
                timestamp, switch_id,
                stat.port_no,
                stat.rx_packets, stat.tx_packets,
                stat.rx_bytes,   stat.tx_bytes
            ])
            self.logger.info(
                "Port %d rx_pkts=%d tx_pkts=%d rx_bytes=%d tx_bytes=%d",
                stat.port_no,
                stat.rx_packets, stat.tx_packets,
                stat.rx_bytes,   stat.tx_bytes
            )

        self.port_file.flush()

    # ── Shutdown ──────────────────────────────────────────────────────────────

    def stop(self):
        self.logger.info("Closing CSV files...")
        self.flow_file.close()
        self.aggregate_file.close()
        self.port_file.close()
        self.detection_file.close()
        super(TrafficMonitor, self).stop()