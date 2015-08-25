from pyretic.lib.path import *
from collections import Counter
from pyretic.evaluations.Tests import fattree
from pyretic.evaluations.Tests import congested_link, ddos, firewall, path_packet_loss, slice_isolation, traffic_matrix
import time
tests = [congested_link, ddos, slice_isolation, firewall, path_packet_loss, traffic_matrix]

def get_filter_type(pol):
    '''  
    This is assuming that we have cleared 
    the match from redundant identity and drops
    meaning that 
      id + x is replaced by id
      id ; x is replaced by x
      drop + x is replaced by x
      drop ; x is replaced by drop
    thus the only case in which we have id or drop
    in a filter is that the filter is actually equal to
    id or drop without having anything else
    '''

    assert isinstance(pol, Filter)
    
    if pol == identity:
        return set()
    elif pol == drop:
        return set()
    elif isinstance(pol, match): 
        try:
            return set(pol.map.keys())
        except:
            return set()
    elif isinstance(pol, CombinatorPolicy):
        res = set()
        for p in pol.policies:
            res |= get_filter_type(p)
        return res
    else:
        raise TypeError

def get_types_dict(query):    

    if isinstance(query, path_combinator):
        in_type = Counter()
        out_type = Counter()
        for p in query.paths:
            (tin, tout) = get_types_dict(p)
            in_type.update(tin)
            out_type.update(tout)
        return (in_type, out_type)

    elif isinstance(query, in_out_atom):
        in_fields = frozenset(get_filter_type(query.in_pred))  
        in_type = Counter({ in_fields: 1 if len(in_fields) > 0 else 0})
        out_fields = frozenset(get_filter_type(query.out_pred))  
        out_type = Counter({ out_fields: 1 if len(out_fields) > 0 else 0})
        return (in_type, out_type)
    else:
        raise TypeError

def get_type(query):
    (in_dict, out_dict) = get_types_dict(query)
    return (join_list(in_dict.items()), join_list(out_dict.items()))

def join_type(t1, t2):
    (fset1, n1) = t1
    (fset2, n2) = t2
    
    final_count = None
    if len(fset1) == 0:
        final_count = n2 + 1
    elif len(fset2) == 0:   
        final_count = n1 + 1
    elif len(fset1 & fset2) == 0:
        final_count = (n1 + 1) * (n2 + 1) - 1
    elif fset1 <= fset2 or fset2 <= fset1:
        final_count = n1 + n2
    elif len(fset1 & fset2) > 0:
        final_count = (n1 + 1) * (n2 + 1) - 1

    return (fset1 | fset2, final_count)

def join_list(type_list):
    if len(type_list) == 0:
        return (0, [])
    res = reduce(lambda acc, typ: join_type(acc, typ), type_list)
    return res

def join_list_inout(type_list):
    in_list = [t[0] for t in type_list]
    out_list = [t[1] for t in type_list]
    return (join_list(in_list), join_list(out_list))

def join((in1, out1), (in2, out2)):
    return (join_type(in1, in2), join_type(out1, out2))

def pack(type_list, limit):
    stages = []
    assgn = {}

    for (q, typ) in type_list:
        assigned = False
        for i in range(len(stages)):
            new_typ = join(stages[i], typ)
            ((in_fset, in_cnt), (out_fset, out_cnt)) = new_typ 
            if in_cnt <= limit and out_cnt <= limit:
                stages[i] = new_typ
                if not i in assgn:
                    assgn[i] = []
                assgn[i].append(q)
                assigned = True
                break
        if not assigned:
            ((_, in_cnt), (_, out_cnt)) = typ 
            if in_cnt <= limit and out_cnt <= limit:
                stages.append(typ)
                assgn[len(stages) - 1] = [q]
            else:
                print q, in_cnt, out_cnt
                raise TypeError
    return assgn

def pack_queries(q_list, limit):
    q_list = [get_type(q) for q in q_list]
    q_list = zip(range(len(q_list)), q_list)
    return pack(q_list, limit)

def compact(l):
    if len(l) == 0:
        return []
    res = [l[0]]
    last = l[0]
    for elem in l[1:]:
        if res[-1] == '-' and elem == last + 1:
            pass
        elif elem == last + 1:
            res.append('-')
        elif res[-1] == '-':
            res.append(last)
            res.append(elem)
        else:
            res.append(elem)
        last = elem
    if res[-1] != last:
        res.append(last)
    return res

def all_queries_together(limit = 2000):
    queries = [t.policy.path_main(k = 8, fout = 4) for t in tests]  
    offsets = []
    off = 0
    for q in queries:
        if isinstance(q, path_policy_union): 
            offsets.append((off, off + len(q.path_policies)))
            off += len(q.path_policies)
        else:
            offsets.append((off, off + 1))
            off += 1
    print offsets
    query = reduce(lambda acc, p: acc + p, queries)
    t_s = time.time()
    res = pack_queries(query.path_policies, limit)
    print time.time() - t_s
    print len(res)
    for s in res:
        print s, compact(res[s])

def each_query_as_unit(limit = 2000):
    queries = [t.policy.path_main(k = 8, fout = 4) for t in tests] 
    q_list = []
    for q in queries:
        if isinstance(q, path_policy_union):
            type_list = [get_type(x) for x in q.path_policies]
            q_list.append(join_list_inout(type_list))
        else:
            q_list.append(get_type(q))
    print q_list
    q_list = zip(range(len(q_list)), q_list)
    res = pack(q_list, limit)
    print len(res)
    for s in res:
        print s, compact(res[s])

if __name__ == "__main__":  
    all_queries_together()
    print '----------------'
    each_query_as_unit(3500)
