# HOW TO: Can be copied to clipboard by piping, e.g.:
# python3 gen_p4_code_add_hll_register.py 256 | xclip -selection c

import sys

def main():
	if not len(sys.argv) > 1:
		sys.exit("Usage: python3 gen_p4_code_add_hll_register.py <NUMBER_OF_HYPERLOGLOG_REGISTERS>")

	m = int(sys.argv[1]) # Number of HyperLogLog registers

	for x in range(0, m):
		print("            HLL_EST_ADD_REGISTER({})".format(x))

if __name__ == "__main__":
	main()