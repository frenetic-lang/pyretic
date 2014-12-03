import yappi
import sys


def read_yappi(fname):
    stat = yappi.YFuncStats()
    stat.add(fname)
    stat.sort('ttot')
    stat.print_all()
if __name__ == "__main__":
    read_yappi(sys.argv[1])
