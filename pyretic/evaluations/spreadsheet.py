import sys
import os

def create_spreadsheet(fname, outname):
    f = open(outname, 'w')
    exp_paths = []
    for exp in os.listdir(fname):
        try:
            exp = "%03d" % int(exp)
        except:
            pass
        exp_paths.append(exp)
    exp_paths.sort()
    '''exp_paths = []
    for i in range(30, 75, 5):
        #exp_paths.append("%d-%d" % (i, i))
        exp_paths.append("%d" % (i))
    '''
    for exp in exp_paths:
        try:
            exp = str(int(exp))
        except:
            pass

        exp_path = os.path.join(fname, os.path.join(exp, 'excel_report.txt'))
        if os.path.exists(exp_path):
            g = open(exp_path, 'r')
            f.write(g.readline())
            g.close()
        

    f.close()

if __name__ == "__main__":
    create_spreadsheet(sys.argv[1], sys.argv[2])    
