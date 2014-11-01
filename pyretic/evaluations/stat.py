import time
import os
from functools import wraps

stats = {}
classifier = {}
general_stats = {}
monitoring = False

path = '/home/mininet/pyretic/pyretic/evaluations/results/'
dfa_path = '/tmp/pyretic-regexes.txt.dot'
symbol_path = '/tmp/symbols.txt'
rule_cnt_file = 'rule-count.txt'
clean_tmp = False

def start(results_folder=None):
    global path
    global monitoring
    global dfa_path
    global symbol_path
    global clean_tmp

    if results_folder:
        path = results_folder

    if not os.path.exists(results_folder):
        os.mkdir(results_folder)

    clean_tmp = True
    try:
        os.remove(dfa_path)
        os.remove(symbol_path)
    except:
        clean_tmp = False

    monitoring = True

def stop():
    global monitoring
    global path
    global dfa_path
    global symbol_path
    global rule_cnt_file

    print 'stoppppppppppppping', time.time()
    if monitoring:
        report_dfa(dfa_path, symbol_path, path)
        create_overall_report(path, rule_cnt_file, os.path.basename(dfa_path))
        create_excel_report(path, rule_cnt_file, os.path.basename(dfa_path)) 

    monitoring = False



def report_dfa(dfa_path, symbol_path, results_path):
    global clean_tmp
    if clean_tmp:
        import shutil
        try:
            shutil.copy(dfa_path, results_path)
            shutil.copy(symbol_path, results_path)
        except:
            pass
     

def create_overall_report(results_path, rule_cnt, dfa_path):
    def adjust_func(file_path):
        return os.path.join(results_path, file_path)
    

    f = open(adjust_func('performance_report.txt'), 'w')

    # rule count on switches
    try:
        g = open(adjust_func(rule_cnt), 'r');
        for line in g.readlines():
            f.write(line)
        g.close()
    except:
        pass

    # general statstics gathered
    try:
        g = open('general_stats.txt', 'r')
        for line in g.readlines():
            f.write(line)
        f.write('--------------------------------------\n')
        g.close()
    except:
        pass

    # dfa state count
    try:
        g = open(adjust_func(dfa_path), 'r')
        state_cnt = 0
        for line in g.readlines():
            if 'shape' in line:
                state_cnt += 1
        g.close()

        g.close()
        f.write('dfa report \n')
        f.write('dfa state count : %d \n' % state_cnt)
        f.write('--------------------------------------\n')
    except:
        pass
            
    
    # compile times
    def getFileName(file_name):
        return os.path.splitext(file_name)[0]

    files = os.listdir(results_path)
    profiles = [ p for p in files if (".profile" in p)]
    cls = [p for p in files if ".cls" in p]

    for prof in profiles:
        g = open(adjust_func(prof), 'r')
        name = prof[:-8]
        f.write(name + '\n')
        for line in g.readlines():
            f.write(line)
        g.close()
        c = [p for p in cls if getFileName(name) == getFileName(p)]
        if len(c) == 1:
            g = open(adjust_func(c[0]), 'r')
            for line in g.readlines():
                f.write(line)
        f.write('--------------------------------------\n')

    f.close() 
    

def create_excel_report(results_path, rule_cnt, dfa_path):
    cols = [ ["makeDFA_vector", 'compile', 'forwarding_compile', 'tagging_compile', 'capture_compile', 'tag_fw_cap_compile'],
                ['vf_tag_compile', 'vf_untag_compile', 'whole_policy_compile'],   
            ]

    def adjust_func(file_path):
        return os.path.join(results_path, file_path)
    
    f = open(adjust_func('excel_report.txt'), 'w')
    
    for col in cols:
        for c in col:
            cpath = adjust_func(c + '.profile')
            if os.path.exists(cpath):
                g = open(cpath, 'r')
                for line in g.readlines():
                    if "average" in line:
                        f.write(line[line.index(':') + 2 :-1] + "\t")
                        break
                g.close()
            else:
                f.write('0\t')

            cpath = adjust_func(c + '.cls')
            if os.path.exists(cpath):
                g = open(cpath, 'r')
                for line in g.readlines():
                    if "classifier" in line:
                        f.write(line[line.index(':') + 2 :-1] + "\t")
                        break
                g.close()

        f.write('\n')
    
    dfa_state_cnt = 0
    try:
        g = open(adjust_func(dfa_path), 'r')
        for line in g.readlines():
            if 'shape' in line:
                dfa_state_cnt += 1

        g.close()
    except:
        pass
 

    rule_cnt = 0
    rule_avg = 0
   
    try:
        g = open(adjust_func(rule_cnt), 'r')
        for line in g.readlines():

            if 'total rule count' in line:
                rule_cnt = int(line[line.index(':') + 2 : -1])

            elif 'average rule count' in line:
                rule_avg = float(line[line.index(':') + 2 : -1])
        g.close()
    except:
        pass

    tagging_edge = 0
    capture_edge = 0
   
    try:
        g = open(adjust_func('general_stats.txt'), 'r')
        for line in g.readlines():
            if "tagging edges" in line:
                tagging_edge = int(line[line.index(':') + 2:-1])

            elif 'capture edges' in line:
                capture_edge = int(line[line.index(':') + 2 : -1])

        g.close()
    except:
        pass

    gen_list = [rule_avg, rule_cnt, dfa_state_cnt, tagging_edge, capture_edge] 

    for gen in gen_list:
        f.write(str(gen) + "\t")
    f.write('\n')        

    f.close()



def gather_general_stats(stat_name, stat_value, init, aggr=True):
    global general_stats
    global path
    global monitoring

    if monitoring:
        if not aggr:
            general_stats[stat_name] = stat_value

        else:
            if not stat_name in general_stats:
                general_stats[stat_name] = init
            general_stats[stat_name] += stat_value

        f = open(os.path.join(path, 'general_stats.txt'), 'w')
        for s in general_stats:
            f.write('%s: %s\n' % (s, str(general_stats[s])))

        f.close()

def classifier_size(func):
    global classifier
    global path
    global monitoring

    @wraps(func)
    def profiled_func(*args, **kwargs):
        res = func(*args, **kwargs)

        if monitoring:
            fname = func.__name__
            
            if fname not in classifier:
                classifier[fname] = 0
            
            classifier[fname] += len(res.rules)
            
            f = open(os.path.join(path, '%s.cls' % fname), 'a')
            f.write(('classifier size: %d' % classifier[fname]) + '\n')
            f.close()
        return res

    return profiled_func
        
def elapsed_time(func):
    global stats
    global path
    global monitoring

    @wraps(func)
    def profiled_func(*args, **kwargs):
        start_time = time.time()
        res = func(*args, **kwargs)

        if monitoring:
            elapsed = time.time() - start_time
            fname = func.__name__
            if fname not in stats:
                stats[fname] = [0, []] #ncalls, times

            stats[fname][0] += 1
            stats[fname][1].append(elapsed)
         
            f = open(os.path.join(path, '%s.profile' % fname), 'w')
            f.write(('number of calls: %d' % stats[fname][0]) + '\n')

            time_list = stats[fname][1]
            f.write( ('total time: %f' % sum(time_list)) + '\n')
            f.write( ('average time: %f' % ( sum(time_list) / len(time_list) )) + '\n')
            f.write('---times----\n')
            f.write(str(time_list) + '\n')

            f.close()

 
        return res

    return profiled_func

