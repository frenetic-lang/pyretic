import os,sys,re
ofile = open('lines.txt','w+')

def getlines(dirs):
    n = 0
    ln=0
    ifile = open(dirs,'r')
    flag = 0
    main_flag = 0
    comma_flag = 0
    for line in ifile.readlines():
        ln+=1
        if flag== 0 and main_flag == 0:
            line = line.strip(' ')
            match_1 = re.match('(from .* )*import ',line)
            match_pr = re.match('print ',line)
            match_2 = re.search(',\s*$',line)
            if line.startswith('#') or line.startswith('//') or line =='\n' or line.startswith('"""') or line.startswith("'''"):
                if line.startswith('"""') or line.startswith("'''"):
                    if line.count('"""')!=2:
                        flag=1
                        #continue
            elif line.startswith('def main') or line.startswith('def launch'):
                main_flag=1
                continue

            # import statements                    
            elif match_1:
                continue

            # print statements                    
            elif match_pr:
                continue


            elif match_2:
                comma_flag = 1
                continue

            else:
                n+=1
                print line
        elif main_flag == 1:
            if line.startswith('def ') or line.startswith('class '):
                main_flag=0
        elif comma_flag == 1:
            match_3 = re.search(',\s*$',line)
            if match_3 is None:
                print line
                n+=1
                comma_flag = 0

        elif flag ==1:
            if '"""' in line or "'''" in line:
                flag=0
        else:
            print 'what?'

    return n

fdir_prev=''
for r,d,f in os.walk(os.getcwd()):
    for files in f:
        if files.endswith('.py') or files.endswith('.java'):
            print files
            dirs = os.path.join(r,files)
            fdir = dirs.split(files)[0]
            if fdir!=fdir_prev:
                ofile.write('\n\n## Dir: '+fdir+'\n')

            n_line = getlines(dirs)
            ofile.write(files+': '+str(n_line)+'\n')


            fdir_prev= fdir
