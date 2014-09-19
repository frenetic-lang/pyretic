#################################################
# (c) Copyright 2014 Hyojoon Kim
# All Rights Reserved 
# 
# email: deepwater82@gmail.com
#################################################

import operator
import string
import pickle
import sys
import re
import time
import os
import sqlite3 as db
import shlex, subprocess
import hashlib
import xml.etree.ElementTree as ET
from multiprocessing import Process
from multiprocessing import Pool
from collections import namedtuple
from datetime import datetime
import tarfile
import matplotlib as mpl
mpl.use('PS')
#mpl.use('pdf')
#mpl.use('AGG')
import matplotlib.pyplot as plt
from matplotlib.ticker import MultipleLocator
from numpy.random import normal
import numpy as np
from optparse import OptionParser
from matplotlib.patches import ConnectionPatch
import struct
from socket import *


mpl.rc('text', usetex=True)
#mpl.rc('font', **{'family':'serif', 'sans-serif': ['Times'], 'size': 9})
mpl.rc('font',**{'family':'sans-serif','sans-serif':['Helvetica'],'size':9})
mpl.rc('figure', figsize=(3.33, 2.06))
mpl.rc('axes', linewidth=0.5)
mpl.rc('patch', linewidth=0.5)
mpl.rc('lines', linewidth=0.5)
mpl.rc('grid', linewidth=0.25)


def plot_multi_cdf(y_map,output_dir,saveAsFileName,plot_title):
  fig = plt.figure(dpi=700)
  ax = fig.add_subplot(111)
  colors = ['r-','k--','g-','m:','r-']
  pl = []
  #  ax.set_yscale('log')
#    ax.xaxis.grid(True, which='major')
  ax.yaxis.grid(True, which='major')

  #  ind = np.arange(len(ya))

  for idx,y in enumerate(sorted(y_map.keys())):
    x_ax,y_ax = y_map[y]
    cidx = idx%len(colors)
    pl.append( plt.plot(x_ax, y_ax, '%s' %(colors[cidx]), label="",linewidth=1.5) )
  
  plt.xlim(0,25)

  ff = plt.gcf()
  ff.subplots_adjust(top=0.73)
  ff.subplots_adjust(bottom=0.20)
  ff.subplots_adjust(left=0.15)
  plt.title(plot_title)
  plt.xlabel('Time to complete verification process (ms)')
  plt.ylabel('CDF', rotation=90)

  l = plt.legend([pl[0][0],pl[1][0],pl[2][0],pl[3][0]], ['Prgm=IDS, nProp=1','Prgm=IDS, nProp=100','Prgm=Composed, nProp=1','Prgm=Composed, nProp=100'], bbox_to_anchor=(0.5, 1.4), loc='upper center',ncol=2, fancybox=True, shadow=False, prop={'size':6.8})    
#  l = plt.legend([pl[0][0],pl[1][0],pl[2][0],pl[3][0]], ['M=Auth,S=1','M=Auth,S=1000','M=Composed,S=1','M=Composed,S=1000'], bbox_to_anchor=(0.92, 0.9), loc='upper center',ncol=1, fancybox=True, shadow=False, prop={'size':5.5})    
  
  plt.savefig(output_dir + str(saveAsFileName), dpi=700)





def plot_distribution(x_ax, y_map, output_dir, filename, title):
    fig = plt.figure(dpi=700)
    ax = fig.add_subplot(111)
    colors = ['r-+','k-*','g-^','c-h','r-.']
    pl = []
    #  ax.set_yscale('log')
  #    ax.xaxis.grid(True, which='major')
    ax.yaxis.grid(True, which='major')
  
    nflows_median = []
    nflows_maxerr = []
    nflows_minerr = []
    instances_list = y_map.keys()
    nflows_len = len(y_map[instances_list[0]])

    for i in range(nflows_len):
        this_flow_list = []
        for idx2,y in enumerate(y_map):
            this_flow_list.append(y_map[y][i])
        nflows_median.append(np.median(this_flow_list))
        nflows_maxerr.append(np.max(this_flow_list) - np.median(this_flow_list))
        nflows_minerr.append(np.median(this_flow_list) - np.min(this_flow_list))

    pl.append(plt.errorbar(x_ax, nflows_median, yerr=[nflows_minerr, nflows_maxerr], fmt='r-o',markersize=1.5))

  
    ff = plt.gcf()
    ff.subplots_adjust(bottom=0.20)
    ff.subplots_adjust(left=0.15)
    ff.subplots_adjust(right=0.6)
    plt.title(title)
    plt.xlabel('Number of flows')
    plt.ylabel('Delay (seconds)', rotation=90)
    
    plt.savefig(output_dir + str(filename), dpi=700)


def plot_singleline(x_ax, y_ax, output_dir, filename, title):

  fig = plt.figure(dpi=700)
  ax = fig.add_subplot(111)
  colors = ['r-+','k-*','g-^','c-h','r-.']
  pl = []
  #  ax.set_yscale('log')
#    ax.xaxis.grid(True, which='major')
  ax.yaxis.grid(True, which='major')

  #  ind = np.arange(len(ya))

  cidx = 0
  pl.append( plt.plot(x_ax, y_ax, '%s' %(colors[cidx]), label="",markersize=2) )
  
  # xlabels = ['0', '10', '20', '30', '40', '50', '60']
  #  majorind = np.arange(len(ya),step=99)
  #  plt.xticks(majorind,xlabels)
 
#  plt.xlim(0,150)

  ff = plt.gcf()
  ff.subplots_adjust(bottom=0.20)
  ff.subplots_adjust(left=0.15)
  plt.title(title)
  plt.xlabel('Number of LPEC FSMs')
  plt.ylabel('Compilation time (seconds)', rotation=90)

#  l = plt.legend([pl[0][0],pl[1][0],pl[2][0],pl[3][0]], ['One Task','50 Tasks','100 Tasks','150 Tasks'], bbox_to_anchor=(0.5, 1.1), loc='upper center',ncol=2, fancybox=True, shadow=False, prop={'size':7.0})    
  
  plt.savefig(output_dir + str(filename), dpi=700)


def plot_multiline_dist_verify(x_ax, y_map, output_dir, filename, title):

    fig = plt.figure(dpi=700)
    ax = fig.add_subplot(111)
    colors = ['r--^','k-*','g-^','c-h','r-.']
    pl = []
  #  ax.set_yscale('log')
#    ax.xaxis.grid(True, which='major')
    ax.yaxis.grid(True, which='major')

    sorted_keys = sorted(y_map.keys())

    for idx,y in enumerate(sorted_keys):
        y_ax_map = y_map[y]
        y_ax = sorted(y_ax_map.keys())
        cidx = idx%len(colors)
    
        data_median_list = []
        data_maxerr_list = []
        data_minerr_list = []
        data_stderr_list = []

        for i in y_ax:
            this_flow_list = y_ax_map[i]
            data_median_list.append(np.median(this_flow_list))
            data_maxerr_list.append(np.max(this_flow_list) - np.median(this_flow_list))
            data_minerr_list.append(np.median(this_flow_list) - np.min(this_flow_list))
            data_stderr_list.append(np.std(this_flow_list))
 
 
#        pl.append(plt.errorbar(x_ax, data_median_list, yerr=data_stderr_list, fmt='%s' %(colors[cidx]), markersize=4.0,linewidth=1))
        pl.append(plt.errorbar(x_ax, data_median_list,  fmt='%s' %(colors[cidx]), markersize=4.0,linewidth=1))
        print colors[cidx]

  
  # xlabels = ['0', '10', '20', '30', '40', '50', '60']
  #  majorind = np.arange(len(ya),step=99)
  #  plt.xticks(majorind,xlabels)
 
    plt.xlim(0,120)
    plt.ylim(0,30)

    ff = plt.gcf()
    ff.subplots_adjust(bottom=0.18)
    ff.subplots_adjust(left=0.13)
    ff.subplots_adjust(right=0.95)
    plt.title(title)
    plt.xlabel('Number of properties')
    plt.ylabel('Verification time (ms)', rotation=90)

#    if len(pl) > 1:
#        l = plt.legend([pl[0][0],pl[1][0],pl[2][0],pl[3][0]], ['100 FSMs','1000 FSMs','10000 FSMs','50000 FSMs'], bbox_to_anchor=(0.5, 1.1), loc='upper center',ncol=2, fancybox=True, shadow=False, prop={'size':7.0})    
    
    l = plt.legend([pl[0][0],pl[1][0] ], ['Single','Composed'], bbox_to_anchor=(0.49, 1.1), loc='upper center',ncol=3, fancybox=True, shadow=False, prop={'size':7.8})    
    plt.savefig(output_dir + str(filename), dpi=700)






def plot_multiline_dist(x_ax, y_map, output_dir, filename, title):

    fig = plt.figure(dpi=700)
    ax = fig.add_subplot(111)
    colors = ['r-+','k-*','g-^','c-h','r-.']
    pl = []
  #  ax.set_yscale('log')
#    ax.xaxis.grid(True, which='major')
    ax.yaxis.grid(True, which='major')

  #  ind = np.arange(len(ya))

    nfsms_sorted_keys = sorted(y_map.keys())
    print nfsms_sorted_keys

#    for idx,y in enumerate(y_map):
    for idx,y in enumerate(nfsms_sorted_keys):
        y_ax = y_map[y]
        cidx = idx%len(colors)
    
        data_median_list = []
        data_maxerr_list = []
        data_minerr_list = []

        for i in y_map[y]:
            this_flow_list = i
            data_median_list.append(np.median(this_flow_list))
            data_maxerr_list.append(np.max(this_flow_list) - np.median(this_flow_list))
            data_minerr_list.append(np.median(this_flow_list) - np.min(this_flow_list))
 
#        pl.append(plt.errorbar(x_ax, data_median_list, yerr=[data_minerr_list, data_maxerr_list], fmt='%s' %(colors[cidx]), markersize=1.5))
        pl.append(plt.errorbar(x_ax, data_median_list, yerr=[data_minerr_list, data_maxerr_list], fmt='%s' %(colors[cidx]), markersize=1.5))
        print colors[cidx]

  
  # xlabels = ['0', '10', '20', '30', '40', '50', '60']
  #  majorind = np.arange(len(ya),step=99)
  #  plt.xticks(majorind,xlabels)
 
#  plt.xlim(0,150)

    ff = plt.gcf()
    ff.subplots_adjust(bottom=0.20)
    ff.subplots_adjust(left=0.15)
    plt.title(title)
    plt.xlabel('Number of events per second')
    plt.ylabel('Recompilation time (seconds)', rotation=90)

#    if len(pl) > 1:
#        l = plt.legend([pl[0][0],pl[1][0],pl[2][0],pl[3][0]], ['100 FSMs','1000 FSMs','10000 FSMs','50000 FSMs'], bbox_to_anchor=(0.5, 1.1), loc='upper center',ncol=2, fancybox=True, shadow=False, prop={'size':7.0})    
    
    l = plt.legend([pl[0][0],pl[1][0],pl[2][0]], ['1000 FSMs','10000 FSMs','45000 FSMs'], bbox_to_anchor=(0.5, 1.1), loc='upper center',ncol=3, fancybox=True, shadow=False, prop={'size':6.2})    
    plt.savefig(output_dir + str(filename), dpi=700)





def plot_multiline(x_ax, y_map, output_dir, filename, title):

  fig = plt.figure(dpi=700)
  ax = fig.add_subplot(111)
  colors = ['r-+','k-*','g-^','c-h','r-.']
  pl = []
  #  ax.set_yscale('log')
#    ax.xaxis.grid(True, which='major')
  ax.yaxis.grid(True, which='major')

  #  ind = np.arange(len(ya))


  for idx,y in enumerate(y_map):
    y_ax = y_map[y]
    cidx = idx%len(colors)
    pl.append( plt.plot(x_ax, y_ax, '%s' %(colors[cidx]), label="") )
  
  # xlabels = ['0', '10', '20', '30', '40', '50', '60']
  #  majorind = np.arange(len(ya),step=99)
  #  plt.xticks(majorind,xlabels)
 
  if filename.find('add_delay') != -1:
       pass
#      plt.ylim(0,20)
#      plt.ylim(0,100)

  elif filename.find('mod_delay') != -1:
      pass
#      plt.ylim(0,5)
#      plt.ylim(0,200)

#  plt.xlim(0,150)

  ff = plt.gcf()
  ff.subplots_adjust(bottom=0.20)
  ff.subplots_adjust(left=0.15)
  plt.title(title)
  plt.xlabel('Number of flows')
  plt.ylabel('Delay (seconds)', rotation=90)

#  l = plt.legend([pl[0][0],pl[1][0],pl[2][0],pl[3][0]], ['One Task','50 Tasks','100 Tasks','150 Tasks'], bbox_to_anchor=(0.5, 1.1), loc='upper center',ncol=2, fancybox=True, shadow=False, prop={'size':7.0})    
  
  plt.savefig(output_dir + str(filename), dpi=700)
 

def figplot_bar(xa,cmap, output_dir, filename, title):

    cdict = {'red': ((0.0, 0.0, 0.0),
                     (205.0,102.0,29.0),
                     (1.0, 1.0, 1.0)),
          'green': ((0.0, 0.0, 0.0),
                    (0.5, 1.0, 0.0),
                    (1.0, 1.0, 1.0)),
          'blue': ((0.0, 0.0, 0.0),
                   (0.5, 1.0, 0.0),
                   (1.0, 0.5, 1.0))}
          
#    my_cmap = mpl.colors.LinearSegmentedColormap('my_colormap',cdict,256)
#    pcolor(rand(10,10),cmap=my_cmap)
#    colorbar()

    # Plot
    fig = plt.figure(dpi=700)
    ax = fig.add_subplot(111)
    xlabels = []

    ax.set_yscale('log',basey=10)

    for x in xa:
        if x%200!=0 or x==100:
            continue
 
        xlabels.append(str(x))
        
    ind = np.arange(len(xlabels))
    width = 0.7
    ya1 = []
    yerr1 = []

    modes = sorted(cmap.keys(),reverse=True)
    pl = []
    
    colors = ['#8B8878','#C1CDCD','black','grey']
    hatch = ['','.....','||||']
    # Different modes
    for idx,m in enumerate(modes):

        ya1_c =[]
        yerr1_c = []
        ya1_h =[]
        yerr1_h = []
        rate= cmap[m][0]
        print 'Mode:',m

        # Need to sort rate
        str_rate = []
        int_rate = []
        for r in rate.keys():
            int_rate.append(int(str(r)))
            str_rate.append(str(r))


        sorted_rate = sorted(int_rate)

        # Different rates
        for r in sorted_rate:
            if r%200!=0 or r==100:
                print r
                continue
            list_of_tuples = rate[str(r)]
            compile_times = []
            handle_times = []

            for l in list_of_tuples:
                compile_times.append(l[0]*1000.0)
                handle_times.append(l[1]*1000.0)

            # Get median for each rate
            ya1_c.append(np.median(compile_times))
            ya1_h.append(np.median(handle_times))
            yerr1_c.append(np.std(compile_times))
            yerr1_h.append(np.std(handle_times))

        print ya1_c
        print ya1_h

        if (len(modes)%2==0):
            shift_factor = len(modes)/2 - idx

            # Plot event handling time. Stack on top of compilation
            pl.append( plt.bar(ind-(width/2.0)*shift_factor,ya1_h, width/2, \
                                color=colors[1], fill=True,   hatch=hatch[idx])  )
            # Plot compiliation time
            pl.append( plt.bar(ind-(width/2.0)*shift_factor,ya1_c, width/2, \
                               color=colors[0], fill=True,  hatch=hatch[idx] )  )


        else:
#            shift_factor = width/2.0
            pass
#

    plt.ylim(1,1000)
    majorind = np.arange(len(xlabels),step=1)
    plt.xticks(majorind,xlabels, rotation=0)
##  ax.xaxis.grid(True, which='major')
    ax.yaxis.grid(True, which='major')
#
#    ax.annotate(str(int(ya1[0])), xy=(0-0.2,int(ya1[0])+200))
#    ax.annotate(str(int(ya1[1])), xy=(1-0.2,int(ya1[1])+200))
#    ax.annotate(str(int(ya1[2])), xy=(2-0.2,int(ya1[2])+200))
##  ax.annotate(str(int(ya1[3])), xy=(3-0.2,int(ya1[3])+200))
#
    ff = plt.gcf()
    ff.subplots_adjust(top=0.9)
    ff.subplots_adjust(bottom=0.20)
    ff.subplots_adjust(left=0.15)
    ff.subplots_adjust(right=0.98)
##  plt.axis([-1,len(ind)+0.5,0,max(ya1+ya2)+max(yerr1+yerr2)+1])
#    plt.title(title)
    plt.xlabel('Event arrival rate (events/second)')
    plt.ylabel('Event reaction time (ms)', rotation=90)

    import matplotlib.patches as mpatches
    event_patch = mpatches.Patch(color='grey', label='The eventh data')
    compile_patch = mpatches.Patch(color='black', label='The compile data')

    single_patch = mpatches.Patch(color='none', fill=True,label='The nohatch data')
    multi_patch = mpatches.Patch(hatch='.....', fill=True,color='none', label='The hatched data')

    ### Legends
    plt.legend([pl[0][0],pl[1][0],single_patch,multi_patch], \
#               ['Single-handle time','Single-compile time','Composed-handle time','Composed-compile time'],\
               ['Event handling time','Recompilation time','Single','Multi'],\
               bbox_to_anchor=(0.5, 1.1), loc='upper center',ncol=2, fancybox=True, \
               shadow=False, prop={'size':7.0})    
 

    plt.savefig(output_dir + str(filename), dpi=700)




def get_cdf2(arr):
  '''
      Fn to get CDF of an array
      Input: unsorted array with values
      Output: 2 arrays - x and y axes values
  '''
  sarr = np.sort(arr)
  l = len(sarr)
  x = []
  y = []
  for i in range(0,l):
    x.append(sarr[i])
    y.append(float(i+1)/l)

  return x,y
