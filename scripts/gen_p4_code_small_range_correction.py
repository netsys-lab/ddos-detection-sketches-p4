# HOW TO: Can be copied to clipboard by piping, e.g.:
# python3 gen_p4_code_small_range_correction.py 256 | xclip -selection c

import numpy, sys

def main():
	if not len(sys.argv) > 1:
		sys.exit("Usage: python3 gen_p4_code_small_range_correction.py <NUMBER_OF_HYPERLOGLOG_REGISTERS>")

	m = int(sys.argv[1]) # Number of HyperLogLog registers
	s = int(33 - numpy.log2(m)) # Number of bits to left-shift (maximum rho)
	w = len(bin(int(m * numpy.log(m) * 2**s))[2:]) # Number of bits of HLL estimate

	for x in range(1, m):
		print("              else if (number_of_empty_registers == {}) {{ hll_result = {}w{}; }}".format(x, w, int(m * numpy.log(m/x) * 2**s)))

if __name__ == "__main__":
	main()