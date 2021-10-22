from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import *
from crc import Crc
import socket, struct, pickle, os, numpy

crc32_polinomials = [0x04C11DB7, 0xEDB88320, 0xDB710641, 0x82608EDB, 0x741B8CD7, 0xEB31D82E,
                     0xD663B05, 0xBA0DC66B, 0x32583499, 0x992C1A4C, 0x32583499, 0x992C1A4C]


class CMSController(object):

    def __init__(self, sw_name, set_hash):

        self.topo = Topology(db="topology.db")
        self.sw_name = sw_name
        self.set_hash = set_hash
        self.thrift_port = self.topo.get_thrift_port(sw_name)
        self.controller = SimpleSwitchAPI(self.thrift_port)

        self.custom_calcs = self.controller.get_custom_crc_calcs()
        self.register_num =  len(self.custom_calcs)

        self.init()
        self.registers = []

    def init(self):
        if self.set_hash:
            self.set_crc_custom_hashes()
        self.create_hashes()

    def set_forwarding(self):
        self.controller.table_add("forwarding", "set_egress_port", ['1'], ['2'])
        self.controller.table_add("forwarding", "set_egress_port", ['2'], ['1'])

    def reset_registers(self):
        for i in range(self.register_num):
            self.controller.register_reset("sketch{}".format(i))

    def flow_to_bytestream(self, flow):
        return socket.inet_aton(flow[0]) + socket.inet_aton(flow[1]) + struct.pack(">HHB",flow[2], flow[3], 6)

    def set_crc_custom_hashes(self):
        i = 0
        for custom_crc32, width in sorted(self.custom_calcs.items()):
            self.controller.set_crc32_parameters(custom_crc32, crc32_polinomials[i], 0xffffffff, 0xffffffff, True, True)
            i+=1

    def create_hashes(self):
        self.hashes = []
        for i in range(self.register_num):
            self.hashes.append(Crc(32, crc32_polinomials[i], True, 0xffffffff, True, 0xffffffff))

    def read_registers(self):
        self.registers = []
        #for i in range(self.register_num):
        #    self.registers.append(self.controller.register_read("sketch{}".format(i)))
        self.registers.append(self.controller.register_read("hyperloglog_sketch0"))

    def get_cms(self, flow, mod):
        values = []
        for i in range(self.register_num):
            index = self.hashes[i].bit_by_bit_fast((self.flow_to_bytestream(flow))) % mod
            values.append(self.registers[i][index])
        return min(values)

    def decode_registers(self, m):
        self.read_registers()
        #print(self.registers[0])
        sum = 0
        for i in range(0, m):
            sum += 2**(-self.registers[0][i])
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
            a = numpy.array(self.registers[0])
            V = len(self.registers[0]) - numpy.count_nonzero(a)
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


if __name__ == "__main__":

    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--sw', help="switch name to configure" , type=str, required=False, default="s1")
    parser.add_argument('--m', help="number of registers used by HyperLogLog sketch", type=int, required=False, default=8)
    parser.add_argument('--option', help="controller option can be either set_hashes, decode or reset registers", type=str, required=False, default="set_hashes")
    args = parser.parse_args()

    set_hashes = args.option == "set_hashes"
    controller = CMSController(args.sw, set_hashes)

    if args.option == "decode":
        controller.decode_registers(args.m)

    elif args.option == "reset":
        controller.reset_registers()
