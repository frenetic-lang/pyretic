#!/usr/bin/python

import re
import sys
from collections import defaultdict, OrderedDict
import operator

PRINT_PARSING_EXCEPTION=False
FUZZY_SPELLING=True

answer_p = re.compile('\d+\t[\w\s]+', re.I)
answer_p = re.compile('(\d+)\t(.+)\n', re.I)

if __name__ == '__main__':

    file_name = sys.argv[1]
    f = open(file_name,'r')

    value_number_map = {}
    total_responses = 0

    for line in f.xreadlines():
        answer_m = answer_p.search(line)

        # Actual entry 
        if answer_m: 
            value = int(answer_m.group(1).rstrip('\t'))
            entry_name = answer_m.group(2).rstrip('\t')
            value_number_map[entry_name] = value

            total_responses = total_responses + value
        else:
            if line!='\n':
                # Very likely a the question itself.
                print '\n============================' 
                print 'Question:',line.rstrip('\n')
                print '============================\n' 

    print 'Total responses:',total_responses,'\n'
    print 'Entry_Name & ' + 'Number_of_responses & ' + 'Percentage\n'
    entry_string = ''
    entry_string = ''

    for k in value_number_map:
        percentage = (float(value_number_map[k])/float(total_responses) ) * 100.0
        line_str = '' 
        line_str += k + ' & ' + str(value_number_map[k]) + ' & ' + "%.2f" % percentage + '\\\\' 
        print line_str
    print '\hline'
    print 'Total & ' + str(total_responses) + ' & 100\\\\'
    print '\n'
