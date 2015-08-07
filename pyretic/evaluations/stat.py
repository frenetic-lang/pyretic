import time
import os
import shutil
from functools import wraps

class Stat(object):
    
    ## stat collectors ##
    times = {}
    classifiers = {}
    general_stats = {}
    monitoring = False
    ################

    ## result path ##
    home_dir = os.path.expanduser('~')
    base_path = os.path.join(home_dir, "pyretic/pyretic/evaluations/")
    results_path = os.path.join(home_dir, 'pyretic/pyretic/evaluations/results/')
    ################

    ## tmp files ##
    dfa_path = '/tmp/graph.dot'
    symbol_path = '/tmp/symbols.txt'
    pickle_path = '/tmp/pickle_symbols.txt'
    ################

    ## opt_flags ##
    disjoint_enabled = False
    integrate_enabled = False
    multitable_enabled = False
    ragel_enabled = False
    ################

    rule_cnt_file = 'rule-count.txt'
    clean_tmp = False

    policies = []
    pol_cls = []

    @classmethod
    def start(cls, results_folder=None, opt_flags = None):
        
        cls.times = {}
        cls.classifiers = {}
        cls.general_stats = {}
        
        if results_folder:
            cls.results_path = os.path.join(cls.base_path, results_folder)
        
        if opt_flags:
            (cls.disjoint_enabled, cls.integrate_enabled, cls.multitable_enabled, cls.ragel_enabled) = opt_flags

        if os.path.exists(cls.results_path):
            shutil.rmtree(cls.results_path)
            
        os.mkdir(cls.results_path)

        try:
            os.remove(cls.dfa_path)
            os.remove(cls.symbol_path)
            os.remove(cls.pickle_path)
            cls.clean_tmp = True
        except:
            pass

        cls.monitoring = True

    @classmethod
    def stop(cls):
        if cls.monitoring:
            cls.dump_stats()
            cls.create_excel_report()
            cls.monitoring = False
    
    @classmethod
    def dump_stats(cls):
        path = os.path.join(cls.results_path, 'stat.txt')
        f = open(path, 'w')
        
        times = []
        for fname in cls.times:
            ftimes = [(fname, x) for x in cls.times[fname]]
            times.append(ftimes)
        classifiers = []
        for fname in cls.classifiers:
            fclassifiers = [(fname, x) for x in cls.classifiers[fname]]
            classifiers.append(fclassifiers)
        
        f.write('############# Time/Space Stats ###############\n')
        compile_phases = ['in_table', 'out_table', 'compile_stage']
        phase_times = [cls.times[x] for x in cls.times if x in compile_phases]
        total_time = [sum(x) for x in zip(*phase_times)]
        stats = zip(*(times + classifiers))
        for i, stat in zip(range(len(stats)), stats):
            f.write('-----------%d------------\n' % i)
            f.write('total time : %f\n' % total_time[i])
            f.write('\n'.join([str(x) for x in stat]) + "\n----------------\n")
        
        cls.report_dfa(f)
        f.write(str(cls.general_stats) + "\n--------------\n")
        f.close()

    @classmethod
    def elapsed_time(cls, func):

        @wraps(func)
        def profiled_func(*args, **kwargs):
            start_time = time.time()
            res = func(*args, **kwargs)
            
            if isinstance(res, tuple) and len(res) == 2 and (isinstance(res[1], float) or isinstance(res[1], str)): 
                #ATTENTION: This if tries to distinguish only netkat compiler results.
                #           May need to be changed if other functions are registered  
                #           for time analysis.
                try:
                    elapsed = float(res[1])
                except:
                    elapsed = 0.0
                res = res[0]
            else:
                elapsed = time.time() - start_time
            
            if cls.monitoring:
                
                fname = func.__name__
                if fname not in cls.times:
                    cls.times[fname] = [] #ncalls, times
                cls.times[fname].append(elapsed)
                #print fname, elapsed    
            return res

        return profiled_func
    
    @classmethod
    def classifier_size_stats(cls, classifier):
        switch_specific = {}
        all_switches = 0
        for rule in classifier.rules:
            try:
                rule_map = rule.match.map
                if 'switch' in rule_map:
                    s = rule_map['switch']
                    if not s in switch_specific:
                        switch_specific[s] = 0
                    switch_specific[s] += 1
                else:
                    all_switches += 1
            except Exception as e:
                all_switches += 1
        return (switch_specific, all_switches)


    @classmethod
    def classifier_stat(cls, func):

        @wraps(func)
        def profiled_func(*args, **kwargs):
            res = func(*args, **kwargs)
            
            if cls.monitoring and res:
                fname = func.__name__

                if fname not in cls.classifiers:
                    cls.classifiers[fname] = []
                try:
                    (switch_specific, all_switches) = cls.classifier_size_stats(res)
                except:
                    print fname
                    print res
                    raise TypeError
                switch_specific_values = switch_specific.values()
                if len(switch_specific_values) > 0:
                    max_cnt = max(switch_specific_values) + all_switches
                    mean_cnt = sum(switch_specific_values) / len(switch_specific) + all_switches
                else:
                    max_cnt = all_switches
                    mean_cnt = all_switches
               
                cls.classifiers[fname].append((len(res.rules), max_cnt, mean_cnt))
                #print fname, cls.classifiers[fname]
                fi = open(os.path.join(cls.results_path, fname), 'w')
                fi.write(str(res))
                fi.close() 
            return res

        return profiled_func

    
    @classmethod
    def collects(cls, stat_reg_info_list):
        '''
        stat_reg_info_list : is a list of tuples, each structured in the
                             following way:
                             (stat_name, init_value = 0, aggr = False)
                             The default values will be used if the tuple has less 
                             then 3 elements.
        '''
        def f(func):
            @wraps(func)
            def profiled_func(*args, **kwargs):
                
                if cls.monitoring:
                    for stat_tuple in stat_reg_info_list:
                        tuple_length = len(stat_tuple) if type(stat_tuple) == tuple else 0
                        stat_name = stat_tuple[0] if tuple_length > 0 else stat_tuple
                        init_value = stat_tuple[1] if tuple_length > 1 else 0
                        aggr = stat_tuple[2] if tuple_length > 2 else False
                        cls.general_stats[stat_name] = {'value' : init_value, 'aggr' : aggr}

                return func(*args, **kwargs)

            return profiled_func
        return f

    @classmethod
    def collect_stat(cls, stat_name, stat_value):

        if cls.monitoring:
            if stat_name in cls.general_stats:
                aggr = cls.general_stats[stat_name]['aggr']
                if aggr:
                    if isinstance(cls.general_stats[stat_name]['value'], list):
                            cls.general_stats[stat_name]['value'].append(stat_value)
                    else:
                        cls.general_stats[stat_name]['value'] += stat_value
                else:
                    cls.general_stats[stat_name]['value'] = stat_value

    @classmethod
    def create_excel_report(cls):
        print 'create excel report'

    @classmethod
    def create_overall_report(cls):
        print 'create overall report'

    @classmethod
    def report_dfa(cls, f):
        path = cls.results_path
        try:
            shutil.copy(cls.dfa_path, path)
            shutil.copy(cls.symbol_path, path)
            #shutil.copy(cls.pickle_path, path)
        except:
            print 'exception in dfa report'

        d_list = ['dfa', 'dfa_utils', 'pred_in_list', 'pred_out_list']
        args = [cls.general_stats[d]['value'] for d in d_list]
        for d in d_list:
            del cls.general_stats[d]

        dfa_list_info = zip(*args)
        f.write('############# DFA Stats ###############\n')
        for i, info in zip(range(len(dfa_list_info)), dfa_list_info):
            analyzer = DFA_Analyzer(*info)
            f.write('-----------%d------------\n' % i)
            f.write('state count : %s\n' % str(analyzer.state_count()))
            f.write('edge count : %s\n' % str(analyzer.edge_count()))
            f.write('in/out tag/cap dist : %s\n' % str(analyzer.edge_gen_dist()))
            f.write('--------------------\n')

    @classmethod
    def create_dist(cls, vals):
        dist = {}
        for val in vals:
            if not val in dist:
                dist[val] = 0
            dist[val] += 1
        return dist

class DFA_Analyzer(object):

    def __init__(self, dfa, dfa_utils, in_list, out_list):
        self.dfa = dfa
        self.du = dfa_utils
        self.edges = [dfa_utils.get_edge_attributes(dfa, e, in_list, out_list) for e in dfa_utils.get_edges(dfa)]
    
    def state_count(self):
        return self.du.get_num_states(self.dfa)

    def edge_count(self): 
        in_count = 0
        out_count = 0

        for (_, _, _, _, _, typ) in self.edges:
            if typ.__name__ == '__in__':
                in_count += 1
            elif typ.__name__ == '__out__':
                out_count += 1
            else:
                raise TypeError

        return (in_count, out_count)

    def edge_dist(self):
        
        edge_per_state = {'__in__':{}, '__out__':{}} 
        
        for (_, src_num, _, _, _, typ) in self.edges:
            if not src_num in edge_per_state[typ.__name__]:
                edge_per_state[typ.__name__][src_num] = 0
            edge_per_state[typ.__name__][src_num] += 1

        return (edge_per_state['__in__'], edge_per_state['__out__'])

    def edge_gen_dist(self):
        
        tag_edge = {'__in__':0, '__out__':0}
        cap_edge = {'__in__':0, '__out__':0}

        for (src, _, dst, _, _, typ) in self.edges:
            if not self.du.is_dead(self.dfa, src):
                tag_edge[typ.__name__] += 1
            if self.du.is_accepting(self.dfa, dst):
                cap_edge[typ.__name__] += 1

        return ((tag_edge['__in__'], cap_edge['__in__']), (tag_edge['__out__'], cap_edge['__out__']))

    def pred_size_dist(self):

        classifier_size = {'__in__':{}, '__out__':{}}
        
        for (_, _, _, _, pred, typ) in self.edges:
            if not pred in classifier_size[typ.__name__]:
                classifier_size[typ.__name__][pred] = len(pred.compile().rules())

        return (classifier_size['__in__'], classifier_size['__out__'])

   
'''
def create_excel_report(results_path, rule_cnt, dfa_path):
    global multitable_enabled
    global integrate_enabled
    global ragel_enabled

    first_col = 'makeDFA_vector'
    if ragel_enabled:
        first_col = 'regexes_to_dfa'

    row = None
    if multitable_enabled:
        if integrate_enabled:
            row =  [first_col, 'compile', 'forwarding_compile', 
                    'in_table_compile', 'out_table_compile']
            row.extend(['tab'] )


        else:
            row =  [first_col, 'compile', 'forwarding_compile', 
                    'tagging_compile', 'out_tagging_compile', 
                    'capture_compile', 'out_capture_compile', 
                    'in_table_compile', 'tab', 'out_table_compile', 'tab']
            row.extend(['tab'] )

    else:
        row = [first_col, 'compile', 'forwarding_compile', 
                'tagging_compile', 'out_tagging_compile', 'tag_fwd_compile',
                'capture_compile', 'out_capture_compile', 'full_out_capture_compile']            
        row.extend(['tab'] * 2)
   
    create_excel_report_general(results_path, rule_cnt, dfa_path, row)

def dump_dist(dist, filename):
    global path
    
    f = open(os.path.join(path, filename), 'w')
    for k,v in dist.items():
        f.write("%d %d\n" % (k, v))
    f.close()

def create_excel_report_general(results_path, rule_cnt, dfa_path, row):
    def adjust_func(file_path):
        return os.path.join(results_path, file_path)

    f = open(adjust_func('excel_report.txt'), 'w')

    for c in row:
        if c == 'tab':
            f.write('0\t')
            continue
        cpath = adjust_func(c + '.profile')
        if c == 'compile' and not os.path.exists(cpath):
            cpath = adjust_func('add_query.profile')
        if os.path.exists(cpath):
            g = open(cpath, 'r')
            for line in g.readlines():
                if "average" in line:
                    f.write(line[line.index(':') + 2 :-1] + "\t")
                    break
            g.close()

            cpath = adjust_func(c + '.cls')
            if os.path.exists(cpath):
                g = open(cpath, 'r')
                cls = '\t'
                avg = ''
                max_cnt = ''
                for line in g.readlines():
                    if "classifier size" in line:
                        cls = line[line.index(':') + 2 :-1] + "\t"
                    elif "average" in line:
                        avg = line[line.index(':') + 2 :-1] + "\t"
                    elif "max" in line:
                        max_cnt = line[line.index(':') + 2 :-1] + "\t"

                f.write(cls + avg + max_cnt)
                g.close()


        else:
            f.write('0\t0\t')

            #    f.write('\n')

    dfa_state_cnt = 0
    in_tagging_edge = 0
    out_tagging_edge = 0
    in_capture_edge = 0
    out_capture_edge = 0
    switch_cnt = 0
    rule_cnt = 0
    
    create_pol = 0
   
    ######
    in_table_edge_per_state_avg = 0
    in_table_edge_per_state_max = 0
    out_table_edge_per_state_avg = 0
    out_table_edge_per_state_max = 0
    in_pred_classifier_size_avg = 0
    in_pred_classifier_size_max = 0
    out_pred_classifier_size_avg = 0
    out_pred_classifier_size_max = 0

    in_table_ast_cnt = 0
    out_table_ast_cnt = 0

    try:
        g = open(adjust_func('general_stats.txt'), 'r')
        for line in g.readlines():
            if "in tagging edges" in line:
                in_tagging_edge = int(line[line.index(':') + 2:-1])

            elif "out tagging edges" in line:
                out_tagging_edge = int(line[line.index(':') + 2:-1])

            elif 'in capture edges' in line:
                in_capture_edge = int(line[line.index(':') + 2 : -1])

            elif 'out capture edges' in line:
                out_capture_edge = int(line[line.index(':') + 2 : -1])

            elif 'dfa state count' in line:
                dfa_state_cnt = int(line[line.index(':') + 2 : -1])
            
            elif 'create pol' in line:
                create_pol =  float(line[line.index(':') + 2 : -1])
             
            ######
            elif "in max edge per state" in line:
                in_table_edge_per_state_max = int(line[line.index(':') + 2:-1])

            elif "in avg edge per state" in line:
                in_table_edge_per_state_avg = float(line[line.index(':') + 2:-1])

            elif 'out max edge per state' in line:
                out_table_edge_per_state_max = int(line[line.index(':') + 2 : -1])

            elif 'out avg edge per state' in line:
                out_table_edge_per_state_avg = float(line[line.index(':') + 2 : -1])

            elif 'in max pred classifier size' in line:
                in_pred_classifier_size_max = int(line[line.index(':') + 2 :-1])

            elif 'in avg pred classifier size' in line:
                in_pred_classifier_size_avg = float(line[line.index(':') + 2 : -1])
            
            elif 'out max pred classifier size' in line:
                out_pred_classifier_size_max = int(line[line.index(':') + 2 :-1])

            elif 'out avg pred classifier size' in line:
                out_pred_classifier_size_avg = float(line[line.index(':') + 2 : -1])

            elif 'in table ast cnt' in line:
                in_table_ast_cnt = int(line[line.index(':') + 2 : -1])
            
            elif 'out table ast cnt' in line:
                out_table_ast_cnt =  int(line[line.index(':') + 2 : -1])

        g.close()
    except:
        pass
 '''
'''
rule_avg = 0
if switch_cnt and rule_cnt:
    rule_avg = float(rule_cnt) / switch_cnt
'''
'''
    rule_avg = switch_cnt
    gen_list = [dfa_state_cnt, in_tagging_edge, out_tagging_edge, in_capture_edge, out_capture_edge]
   
   
    pred_part = stats['pred_part'][1][0]
    if pred_part > 0 or create_pol > 0:
        gen_list.extend([pred_part, create_pol])

    for gen in gen_list:
        f.write(str(gen) + "\t")
    f.write('\n')

    f.close()

    f = open(adjust_func('stat_report.txt'), 'w')
    stat_lost = [in_table_edge_per_state_avg, in_table_edge_per_state_max, out_table_edge_per_state_avg, out_table_edge_per_state_max,
                in_table_ast_cnt, out_table_ast_cnt, in_pred_classifier_size_avg, in_pred_classifier_size_max,
                out_pred_classifier_size_avg, out_pred_classifier_size_max]

    for s in stat_lost:
        f.write(str(s) + "\t")
    f.write('\n')
    f.close()


'''
