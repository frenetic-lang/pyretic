import time
import os
from functools import wraps

stats = {}
classifier = {}
general_stats = {}

path = '/home/mininet/pyretic/pyretic/evaluations/results/'


def gather_general_stats(stat_name, stat_value, init, aggr=True):
    global general_stats
    global path

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

    @wraps(func)
    def profiled_func(*args, **kwargs):
        res = func(*args, **kwargs)
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

    @wraps(func)
    def profiled_func(*args, **kwargs):
        start_time = time.time()
        res = func(*args, **kwargs)
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


def stat_aggr(func, stats):
    fname = "/home/mininet/pyretic/pyretic/evaluations/results/%s.profile" % (func.__name__)
    try:
        stats.add(fname)
    except IOError:
        pass
    stats.save(fname)


@elapsed_time
def my_sum(x, y):
    return x + y


def path_adj(name):
    return '/home/mininet/pyretic/pyretic/evaluations/' + name
    
    
if __name__ == "__main__":
    start(path_adj)
    my_sum(2, 3)
    stop()
        
