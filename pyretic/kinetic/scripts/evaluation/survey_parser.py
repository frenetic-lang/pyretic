#!/usr/bin/python

import re
import sys
from collections import defaultdict, OrderedDict
import operator

PRINT_PARSING_EXCEPTION=False
FUZZY_SPELLING=True

if FUZZY_SPELLING:
    kinetic_p = re.compile('k\w+tic',re.I)
    pyretic_p = re.compile('p\w+tic',re.I)
else:
    kinetic_p = re.compile('kinetic',re.I)
    pyretic_p = re.compile('pyretic',re.I)
pox_p = re.compile('pox',re.I)
integer_p = re.compile('[0-9]+')
tab_p = re.compile('\t')

if __name__ == '__main__':

    file_name = sys.argv[1]

    results = defaultdict(lambda: 0)
    ordering = defaultdict(lambda: defaultdict(lambda: 0))
    
    f = open(file_name,'r')
    for line in f.xreadlines():
        
        try:
            count,line = tab_p.split(line,1)
            count = int(count)
        except:
#            print 'skipping'
            continue

        position = dict()

        kinetic_m = kinetic_p.search(line)
        pyretic_m = pyretic_p.search(line)
        pox_m = pox_p.search(line)
        numbering = integer_p.findall(line)
        numbering = map(int,numbering)

        if kinetic_m:
            position['kinetic'] = kinetic_m.start()
        if pyretic_m:
            position['pyretic'] = pyretic_m.start()
        if pox_m:
            position['pox'] = pox_m.start()

        position = OrderedDict(sorted(position.items(),key=operator.itemgetter(1)))
        order = [k for k,v in position.items()]

        if len(numbering) == 0 or len(numbering) > 3 or max(numbering) > 3:
            numbering = [1,2,3]

        if len(order) != len(numbering):
            if PRINT_PARSING_EXCEPTION:
                print '---- parsing exception -----'
                print line,
                print len(order),len(numbering)
                print '----------------------------'
            continue

        ranked = zip(order,numbering)

        for platform,rank in ranked:
            ordering[rank][platform] += count
    
    print '---- count of first/second/third place ---------'
    for rank,platform_count in sorted(ordering.items()):
        print 'Rank %d' % rank, 
        print [(platform,count) for platform,count in platform_count.items()]
