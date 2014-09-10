import subprocess
import platform
import os
import sys

class ModelChecker(object):
    
    def __init__(self, smv_str, appname_str):
        arch_str = platform.architecture()
        if arch_str:
            if not os.environ.has_key('KINETICPATH'):
                print 'KINETICPATH env variable not set. Set it with export command.\n'
                sys.exit()
                return
            kinetic_path_str = os.environ['KINETICPATH']
            if arch_str[0].startswith('32'):  
                self.exec_cmd = kinetic_path_str + '/smv/NuSMV_32'
            else:
                self.exec_cmd = kinetic_path_str + '/smv/NuSMV_64'
        self.smv_file_directory = kinetic_path_str + '/smv/smv_files/'
        self.filename = self.smv_file_directory + appname_str + '.smv'
        self.smv_str = smv_str +'\n'

    def add_spec(self,spec_str):
        self.smv_str = self.smv_str + spec_str + '\n'

    def save_as_smv_file(self):
        fd = open(self.filename, 'w')
        fd.write(self.smv_str)
        fd.close()

    def verify(self):
        print self.smv_str
        print '========================== NuSMV OUTPUT ==========================\n'

        import datetime as dt
        n1=dt.datetime.now()

        p = subprocess.Popen([self.exec_cmd, '-r', self.filename], stdout=subprocess.PIPE) 
        out, err = p.communicate()

        n2=dt.datetime.now()
        print "\n=== Verification takes (ms): ",float((n2-n1).microseconds)/1000.0,"==="
        print "=== Verification takes (s): ",float((n2-n1).seconds),"===\n"
 
        print out

        print '======================== NuSMV OUTPUT END ========================\n'
