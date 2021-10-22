from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import *
from crc import Crc
import socket, struct, pickle, os, numpy, time, contextlib, io, sys

@contextlib.contextmanager
def nostdout():
    save_stdout = sys.stdout
    sys.stdout = io.BytesIO()
    yield
    sys.stdout = save_stdout

crc32_polinomials = [0x04C11DB7, 0xEDB88320, 0xDB710641, 0x82608EDB, 0x741B8CD7, 0xEB31D82E,
                     0xD663B05, 0xBA0DC66B, 0x32583499, 0x992C1A4C, 0x32583499, 0x992C1A4C]


class HLLCMController(object):

    def __init__(self, sw_name, set_hash):

        self.topo = Topology(db="topology.db")
        self.sw_name = sw_name
        self.set_hash = set_hash
        self.thrift_port = self.topo.get_thrift_port(sw_name)
        self.controller = SimpleSwitchAPI(self.thrift_port)

        # used for storing value of total packet counter
        self.packet_counter = 0

        # number of hash functions used per CountMin sketch
        self.rows_per_countmin_sketch = 3

        # active sketches
        self.active_hyperloglog_sketch = 0
        self.active_countmin_sketch = 0

        # number of registers used by HyperLogLog and CountMin sketches
        self.hyperloglog_register_num = 2
        self.countmin_register_num = self.rows_per_countmin_sketch * 2
        self.total_register_num = self.hyperloglog_register_num + self.countmin_register_num

        # number of custom CRCs used
        self.custom_calcs = self.controller.get_custom_crc_calcs()

        self.init()

        # sketch registers
        self.hyperloglog_registers = []
        self.countmin_registers = []

    def init(self):
        if self.set_hash:
            self.set_crc_custom_hashes()
        self.create_hashes()

    def set_forwarding(self):
        self.controller.table_add("forwarding", "set_egress_port", ['1'], ['2'])
        self.controller.table_add("forwarding", "set_egress_port", ['2'], ['1'])

    # Resets all registers
    def reset_registers(self):
        for i in range(self.countmin_register_num):
            self.controller.register_reset("countmin_sketch{}".format(i))
        for i in range(self.hyperloglog_register_num):
            self.controller.register_reset("hyperloglog_sketch{}".format(i))
        self.controller.register_reset("ddos_detected")

    def ip_to_bytestream(self, ip):
        return socket.inet_aton(ip)

    def set_crc_custom_hashes(self):
        i = 0
        for custom_crc32, width in sorted(self.custom_calcs.items()):
            self.controller.set_crc32_parameters(custom_crc32, crc32_polinomials[i], 0xffffffff, 0xffffffff, True, True)
            i+=1

    def get_active_sketches(self):
        self.active_hyperloglog_sketch = int(self.controller.register_read("active_hyperloglog_sketch")[0])
        self.active_countmin_sketch = int(self.controller.register_read("active_countmin_sketch")[0])

    def switch_active_sketches(self):
        #self.read_packet_counter()
        self.get_active_sketches()

        print time.time()

        # switch active HyperLogLog sketch
        if int(self.active_hyperloglog_sketch) == 0:
            self.controller.register_write("active_hyperloglog_sketch", 0, 1)
            self.controller.register_reset("hyperloglog_sketch0")
        elif int(self.active_hyperloglog_sketch) == 1:
            self.controller.register_write("active_hyperloglog_sketch", 0, 0)
            self.controller.register_reset("hyperloglog_sketch1")
        # switch active CountMin sketch
        if int(self.active_countmin_sketch) == 0:
            for i in range(3):
                self.controller.register_write("active_countmin_sketch", 0, 1)
                self.controller.register_reset("countmin_sketch{}".format(i))
        elif int(self.active_countmin_sketch) == 1:
            for i in range(3, 6):
                self.controller.register_write("active_countmin_sketch", 0, 0)
                self.controller.register_reset("countmin_sketch{}".format(i))
        #self.reset_packet_counter()

    def read_packet_counter(self):
        self.packet_counter = self.controller.counter_read("packet_counter", 0).packets

    def reset_packet_counter(self):
        self.controller.counter_reset("packet_counter")

    def create_hashes(self):
        self.hashes = []
        for i in range(self.total_register_num):
            self.hashes.append(Crc(32, crc32_polinomials[i], True, 0xffffffff, True, 0xffffffff))

    def read_hyperloglog_registers(self, get_inactive):
        self.hyperloglog_registers = []
        self.get_active_sketches()
        if (self.active_hyperloglog_sketch == 0 and not get_inactive) or (self.active_hyperloglog_sketch == 1 and get_inactive):
            self.hyperloglog_registers.append(self.controller.register_read("hyperloglog_sketch0"))
        elif (self.active_hyperloglog_sketch == 1 and not get_inactive) or (self.active_hyperloglog_sketch == 0 and get_inactive):
            self.hyperloglog_registers.append(self.controller.register_read("hyperloglog_sketch1"))

    def read_countmin_registers(self, get_inactive):
        self.countmin_registers = []
        self.get_active_sketches()

        if (self.active_countmin_sketch == 0 and not get_inactive) or (self.active_countmin_sketch == 1 and get_inactive):
            for i in range(3):
                self.countmin_registers.append(self.controller.register_read("countmin_sketch{}".format(i)))
        elif (self.active_countmin_sketch == 1 and not get_inactive) or (self.active_countmin_sketch == 0 and get_inactive):
            for i in range(3, 6):
                self.countmin_registers.append(self.controller.register_read("countmin_sketch{}".format(i)))

    ########################################
    # Calculate estimates in control plane #
    ########################################

    def decode_hyperloglog_registers(self, m, get_inactive):
        self.read_hyperloglog_registers(get_inactive)
        #print(self.hyperloglog_registers[0])
        sum = 0
        for i in range(0, m):
            sum += 2**(-self.hyperloglog_registers[0][i])
        if m == 16:
            E = 0.673 * m**2 * sum**(-1)
        elif m == 32:
            E = 0.697 * m**2 * sum**(-1)
        elif m == 64:
            E = 0.709 * m**2 * sum**(-1)
        elif m >= 128:
            E = 0.7213/(1 + 1.079/m) * m**2 * sum**(-1)
        #print("E: {}".format(E))
        if E <= 2.5 * m:
            #print("Applying small range correction...")
            a = numpy.array(self.hyperloglog_registers[0])
            V = len(self.hyperloglog_registers[0]) - numpy.count_nonzero(a)
            if V != 0:
                E_final = m * numpy.log(m/float(V))
            else:
                E_final = E
        elif E <= float(2**32)/30:
            E_final = E
        elif E > float(2**32)/30:
            #print("Applying large range correction...")
            E_final = - 2**32 * numpy.log(1 - E/2**32)
        #print("E*: {}".format(E_final))
        print(E_final)

    def decode_countmin_registers(self, flow, mod, get_inactive):
        self.read_countmin_registers(get_inactive)
        values = []
        for i in range(self.rows_per_countmin_sketch):
            if not get_inactive:
                hash_index = i if self.active_countmin_sketch == 0 else i + self.rows_per_countmin_sketch
            else:
                hash_index = i if self.active_countmin_sketch == 1 else i + self.rows_per_countmin_sketch
            index = self.hashes[hash_index].bit_by_bit_fast((self.ip_to_bytestream(flow))) % mod
            values.append(self.countmin_registers[i][index])
        print min(values)

    #####################################################
    # Read estimates that were calculated in data plane #
    #####################################################

    def calculate_hll_avg(self, sum):
        if self.m == 16:
            result = 0.673 * self.m**2 * sum**(-1)
        elif self.m == 32:
            result = 0.697 * self.m**2 * sum**(-1)
        elif self.m == 64:
            result = 0.709 * self.m**2 * sum**(-1)
        elif self.m >= 128:
            result = 0.7213/(1 + 1.079/self.m) * self.m**2 * sum**(-1)
        return result

    def calculate_hll_est(self):
        hyperloglog_registers = []
        hyperloglog_registers.append(self.controller.register_read("hyperloglog_sketch0"))
        self.m = len(hyperloglog_registers[0])
        sum = 0
        for i in range(0, self.m):
            sum += 2**(-hyperloglog_registers[0][i])
        E = self.calculate_hll_avg(sum)
        #print("E: {}".format(E))
        if E <= 2.5 * self.m:
            #print("Applying small range correction...")
            a = numpy.array(hyperloglog_registers[0])
            V = self.m - numpy.count_nonzero(a)
            #print("V = {}".format(V))
            if V != 0:
                E_final = self.m * numpy.log(self.m/float(V))
            else:
                E_final = E
        elif E <= float(2**32)/30:
            E_final = E
        elif E > float(2**32)/30:
            #print("Applying large range correction...")
            E_final = - 2**32 * numpy.log(1 - E/2**32)
        #print("E*: {}".format(E_final))
        return E_final

    def read(self):
        with nostdout():
            truth = self.controller.counter_read("packet_counter", 0)

        # Calculate controller HLL estimate
        hll_est_controller = self.calculate_hll_est()

        # Calculate switch HLL estimate
        hll_src_applied = self.controller.register_read("small_range_correction_applied", 0)
        hll_est_raw = self.controller.register_read("hyperloglog_est", 0)
        hll_est_switch = 0.0
        #  Reverse left shift
        left_shift_bits = int(33 - numpy.log2(self.m))
        for i in range(0, left_shift_bits):
            lsb = hll_est_raw & 1
            if lsb:
                hll_est_switch += 2**(-left_shift_bits+i)
            hll_est_raw = hll_est_raw >> 1
        #  Add integer part
        hll_est_switch += hll_est_raw
        if hll_src_applied == 0:
            hll_est_switch = self.calculate_hll_avg(hll_est_switch)

        # Print true packet counter value
        print("True number of packets: {}".format(truth.packets))

        # Print both HLL estimates
        print("HyperLogLog estimate (number of source IPs): by controller: {}, by switch: {}".format(hll_est_controller, hll_est_switch))

        # Get controller CM estimate
        cm_est_switch = self.controller.register_read("countmin_est", 0)
        print("CountMin estimate (number of packets): {}".format(cm_est_switch))

if __name__ == "__main__":

    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--sw', help="switch name to configure" , type=str, required=False, default="s1")
    parser.add_argument('--hyperloglog-registers', help="number of registers used by HyperLogLog sketch", type=int, required=False, default=8)
    parser.add_argument('--countmin-registers', help="number of cells in each CountMin sketch row", type=int, required=False, default=28)
    parser.add_argument('--countmin-flow', help="flow (dst IP) to get a CountMin estimate for", type=str, required=False, default="10.0.1.1")
    parser.add_argument('--get-inactive', help="get estimates from inactive sketches", type=bool, required=False, default=False)
    # parser.add_argument('--reset-threshold', help="number of packets after which one of the sketches alternatingly gets reset", type=int, required=False, default=10000)
    parser.add_argument('--option', help="controller option", type=str, required=False, default="set_hashes")
    args = parser.parse_args()

    set_hashes = args.option == "set_hashes"
    controller = HLLCMController(args.sw, set_hashes)

    if args.option == "decode_hyperloglog":
        controller.decode_hyperloglog_registers(args.hyperloglog_registers, args.get_inactive)

    elif args.option == "decode_countmin":
        controller.decode_countmin_registers(args.countmin_flow, args.countmin_registers, args.get_inactive)

    elif args.option == "reset_all":
        controller.reset_registers()

    elif args.option == "switch_active_sketches":
        controller.switch_active_sketches()

    elif args.option == "read_estimates":
        controller.read()

