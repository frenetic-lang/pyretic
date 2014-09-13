#################################################
# (c) Copyright 2014 Hyojoon Kim
# All Rights Reserved 
# 
# email: deepwater82@gmail.com
#################################################

import os
from optparse import OptionParser
import python_api
import plot_lib
import sys
import pickle
import numpy as np

def plot_the_event(input_dir, output_dir, saveAsFileName, plot_title):
    xa = [1,10,20,40,60,80,100]
    ymap = {}
    
    files = os.listdir(input_dir)
    # for different number of FSMs loaded,
    for f in files:
        fd = open(input_dir + f,'rb')
        data = pickle.load(fd)
        fd.close()

        print data.keys()

        nfsm = str(f).lstrip('measure_map_event').rstrip('.p')
        ymap[nfsm] = []
        # for each rate,
        for x in xa:
            mea_list = data[(x,1)]
        
            m_list = []
            # for each measurement
            for m in mea_list:
                m_list.append(m[1])
            ymap[nfsm].append(m_list)
            

    print xa
    print ymap

    #### Do your stuff

    plot_lib.plot_multiline_dist(xa, ymap, output_dir, saveAsFileName, plot_title)

    return   


def plot_the_data(data, output_dir, saveAsFileName, plot_title):
    xa = []
    ymap = {}
    
    #### Do your stuff

    x_ax = np.arange(len(data))
    plot_lib.plot_singleline(x_ax, data, './', saveAsFileName, plot_title)
#    plot_lib.plot_distribution(xa, ymap, output_dir, saveAsFileName, plot_title)

    return   

def main():
    desc = ( 'Plotting data' )
    usage = ( '%prog [options]\n'
                          '(type %prog -h for details)' )
    op = OptionParser( description=desc, usage=usage )

    # Options
    op.add_option( '--input', '-i', action="store", \
                   dest="input_t", help = "Pickled data")
 
    op.add_option( '--outputdir', '-o', action="store", \
                   dest="output_dir", help = "Directory to store plots")

    op.add_option( '--type', '-t', action="store", choices=['event','newfsm'],\
                   default='newfsm',dest="type_plot", help = "Type of plot [event, newfsm]")
 

    # Parsing and processing args
    options, args = op.parse_args()
    args_check = sys.argv[1:]
    if len(args_check) != 6:
        print 'Something wrong with paramenters. Please check.'
        print op.print_help()
        sys.exit(1)

    # Check and add slash to directory if not there.
    output_dir = python_api.check_directory_and_add_slash(options.output_dir)
    if options.type_plot=='event':
        input_t= python_api.check_directory_and_add_slash(options.input_t)

        # Get data from input directory 
        saveAsFileName = 'nevent.png'  # Add file extension yourself.
        plot_title = 'Event processing time'
        plot_the_event(input_t, output_dir, saveAsFileName, plot_title)

    elif options.type_plot=='newfsm':
        # Check file, open, read
        if os.path.isfile(options.input_t) is True:
            fd = open(options.input_t, 'r')
            data = pickle.load(fd)
            fd.close()
        saveAsFileName = 'newfsm.png'  # Add file extension yourself.
        plot_title = 'Compilation time based on number of LPEC FSMs'
        plot_the_data(data, output_dir, saveAsFileName, plot_title)
 
    else: 
        print 'Wrong plot type. Abort'
        print op.print_help()
        sys.exit(1)



######        
if __name__ == '__main__':
    main()
