#!/usr/bin/env python3
"""
Enhanced SDN DDoS Topology - Flat Single Subnet
=================================================
Multi-attacker, multi-victim topology - same flat 10.0.0.0/24 subnet
No routing needed - works with existing Ryu controller zero changes

Architecture:
                    10.0.0.0/24 - Single Subnet
    
    ATTACKERS     CORE SWITCHES(CONTROLLER)      VICTIMS (SERVERS)
                      |   |  |    |
    h1 (10.0.0.1) \   |   |  |    |           / h5 (10.0.0.5) Web Server
    h2 (10.0.0.2)  -- s1 -- s2 -- s3 --  h6 (10.0.0.6) File Server
    h3 (10.0.0.3) /       |  |             \ h7 (10.0.0.7) DNS Server
    h4 (10.0.0.4) /        \s4
                             |
                         h8 (10.0.0.8) ← secondary victim

Improvements over original 3h/3s topology:
    - 4 attackers instead of 1 (coordinated DDoS simulation)
    - 4 victims instead of 1 (multi-target attack simulation)  
    - 4 switches (more realistic campus/enterprise topology)
    - Flow table grows measurably - validates scalability
    - All hosts same subnet - zero controller changes needed

Research contributions:
    - Coordinated multi-attacker DDoS detection
    - Multi-target attack identification
    - Flow table growth analysis
    - Detection latency under increased load

Author  : Mahmoud Soilihi
Date    : May 2026
Purpose : SOURCE Poster Presentation Showcase - Valparaiso University, May 30 2026
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink


def enhanced_flat_topology():

    net = Mininet(
        controller=RemoteController,
        switch=OVSKernelSwitch,
        link=TCLink
    )

    info('*** Adding Remote Controller (Ryu)\n')
    c0 = net.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6633
    )

    # ── Switches ──────────────────────────────────────────────────────────────
    info('*** Adding Switches\n')
    s1 = net.addSwitch('s1', protocols='OpenFlow13')  # Attacker-side
    s2 = net.addSwitch('s2', protocols='OpenFlow13')  # Core hub
    s3 = net.addSwitch('s3', protocols='OpenFlow13')  # Victim-side
    s4 = net.addSwitch('s4', protocols='OpenFlow13')  # Secondary victim-side

    # ── Attacker Hosts ────────────────────────────────────────────────────────
    info('*** Adding Attacker Hosts\n')
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')  # Bot 1
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')  # Bot 2
    h3 = net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')  # Bot 3
    h4 = net.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')  # Bot 4

    # ── Victim Hosts (Servers) ────────────────────────────────────────────────
    info('*** Adding Victim Hosts (Servers)\n')
    h5 = net.addHost('h5', ip='10.0.0.5/24', mac='00:00:00:00:00:05')  # Web server
    h6 = net.addHost('h6', ip='10.0.0.6/24', mac='00:00:00:00:00:06')  # File server
    h7 = net.addHost('h7', ip='10.0.0.7/24', mac='00:00:00:00:00:07')  # DNS server
    h8 = net.addHost('h8', ip='10.0.0.8/24', mac='00:00:00:00:00:08')  # Secondary victim

    # ── Links ─────────────────────────────────────────────────────────────────
    info('*** Adding Links\n')

    # Attackers to s1
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(h4, s1)

    # Primary victims to s3
    net.addLink(h5, s3)
    net.addLink(h6, s3)
    net.addLink(h7, s3)

    # Secondary victim to s4
    net.addLink(h8, s4)

    # Switch interconnects — s2 is core hub
    net.addLink(s1, s2)   # attacker side → core
    net.addLink(s3, s2)   # victim side → core
    net.addLink(s4, s2)   # secondary victim → core

    # ── Start Network ─────────────────────────────────────────────────────────
    info('*** Starting Network\n')
    net.build()
    c0.start()
    s1.start([c0])
    s2.start([c0])
    s3.start([c0])
    s4.start([c0])

    info('*** Setting OpenFlow 1.3 on all switches\n')
    for sw in [s1, s2, s3, s4]:
        sw.cmd(f'ovs-vsctl set bridge {sw.name} protocols=OpenFlow13')

    info('\n')
    info('=================================================================\n')
    info('  Enhanced Flat Topology Ready — SOURCE Conference 2026\n')
    info('=================================================================\n')
    info('  ATTACKER ZONE\n')
    info('    h1 = 10.0.0.1  (Bot/Attacker 1) -- s1\n')
    info('    h2 = 10.0.0.2  (Bot/Attacker 2) -- s1\n')
    info('    h3 = 10.0.0.3  (Bot/Attacker 3) -- s1\n')
    info('    h4 = 10.0.0.4  (Bot/Attacker 4) -- s1\n')
    info('\n')
    info('  VICTIM ZONE (Servers)\n')
    info('    h5 = 10.0.0.5  (Web Server)       -- s3\n')
    info('    h6 = 10.0.0.6  (File Server)      -- s3\n')
    info('    h7 = 10.0.0.7  (DNS Server)       -- s3\n')
    info('    h8 = 10.0.0.8  (Secondary Victim) -- s4\n')
    info('\n')
    info('  SWITCHES\n')
    info('    s1 = Attacker-side switch\n')
    info('    s2 = Core hub switch (all traffic crosses here)\n')
    info('    s3 = Primary victim-side switch\n')
    info('    s4 = Secondary victim-side switch\n')
    info('=================================================================\n')
    info('\n')
    info('  QUICK START COMMANDS:\n')
    info('  1. pingall\n')
    info('  2. h5 iperf -s &  |  h5 iperf -s -u &\n')
    info('  3. h1 ping -i 0.5 10.0.0.5 &  (baseline)\n')
    info('  4. Wait 60s for baseline\n')
    info('  5. h1 hping3 -S --flood -p 80 10.0.0.5 &  (attack)\n')
    info('=================================================================\n')
    info('\n')

    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    enhanced_flat_topology()
