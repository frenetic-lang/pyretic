#################################################
# (c)  Copyright 2014 Hyojoon Kim
# All Rights Reserved 
# 
# email: deepwater82@gmail.com
#################################################

import sys
import os
import pickle
import re
import operator

def check_directory_and_add_slash(path):
  return_path = path

  # No path given  
  if return_path == None:
    print "None is given as path. Check given parameter."
    return ''
    
  # Path is not a directory, or does not exist.  
  if os.path.isdir(return_path) is False:
    print "Path is not a directory, or does not exist.: '%s'. Abort" % (return_path)
    return ''

  # Add slash if not there.  
  if return_path[-1] != '/':
    return_path = return_path + '/'

  # Return
  return return_path


def save_data_as_pickle(data, filename, output_dir):
  print '\nSaving Result: %s\n' %(str(filename) + '.p')
  pickle_fd = open(str(output_dir) + str(filename) + '.p','wb')
  pickle.dump(data,pickle_fd)
  pickle_fd.close()

  return


def sort_map_by_value(the_map):

  # list of tuples (key, value)
  sorted_tup = sorted(the_map.iteritems(), key=operator.itemgetter(1), reverse=True)

  # Returns a list of tuples [(key, value),]
  return sorted_tup
