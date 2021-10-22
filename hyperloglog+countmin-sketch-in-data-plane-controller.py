from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
from scapy.all import Ether, sniff
import time

LOG_FILE="logs/controller.txt"

class P4Controller(object):

    def __init__(self, sw_name):
        self.topo = Topology(db="topology.db")
        self.sw_name = sw_name
        self.thrift_port = self.topo.get_thrift_port(sw_name)
        self.controller = SimpleSwitchAPI(self.thrift_port)
        self.cpu_port = self.topo.get_cpu_port_index(self.sw_name)

        self.add_mirror()

    # Mitigation functionality

    def add_mirror(self):
        if self.cpu_port:
            self.controller.mirroring_add(100, self.cpu_port)

    def start_mitigation(self):
        self.controller.table_clear("repeater")
        with open(LOG_FILE, "a") as log_file:
            log_file.write(str(time.time()) + "\n")

    def recv_msg_cpu(self, pkt):
        packet = Ether(str(pkt))
        if packet.type == 0x1234:
            self.start_mitigation()

    def run_cpu_port_loop(self):
        cpu_port_intf = str(self.topo.get_cpu_port_intf(self.sw_name).replace("eth0", "eth1"))
        sniff(iface=cpu_port_intf, prn=self.recv_msg_cpu)

if __name__ == "__main__":
    P4Controller("s1").run_cpu_port_loop()
