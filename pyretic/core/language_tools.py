from pyretic.core.language import *

###############################################################################
# Class hierarchy syntax tree traversal

def ast_fold(fun, acc, policy):
    import pyretic.lib.query as query
    if (  policy == identity or
          policy == drop or
          isinstance(policy,match) or
          isinstance(policy,modify) or
          policy == Controller or
          isinstance(policy,Query)):
        return fun(acc,policy)
    elif (isinstance(policy,negate) or
          isinstance(policy,parallel) or
          isinstance(policy,union) or
          isinstance(policy,sequential) or
          isinstance(policy,intersection)):
        acc = fun(acc,policy)
        for sub_policy in policy.policies:
            acc = ast_fold(fun,acc,sub_policy)
        return acc
    elif (isinstance(policy,difference) or
          isinstance(policy,if_) or
          isinstance(policy,fwd) or
          isinstance(policy,xfwd) or
          isinstance(policy,DynamicPolicy) or
          isinstance(policy,query.packets)):
        acc = fun(acc,policy)
        return ast_fold(fun,acc,policy.policy)
    else:
        raise NotImplementedError
    
def add_dynamic_sub_pols(acc, policy):
    if isinstance(policy,DynamicPolicy):
        return acc | {policy}
    else:
        return acc

def add_query_sub_pols(acc, policy):
    from pyretic.lib.query import packets
    if ( isinstance(policy,Query) or
         isinstance(policy,packets)) : ### TODO remove this hack once packets is refactored 
        return acc | {policy}
    else:
        return acc

def add_all_sub_pols(acc, policy):
    return acc | {policy}

def queries_in_eval(acc, policy):
    res,pkts = acc
    if policy == drop:
        acc = (res,set())
    elif policy == identity:
        pass
    elif (isinstance(policy,match) or 
          isinstance(policy,modify) or 
          isinstance(policy,negate)):
        new_pkts = set()
        for pkt in pkts:
            new_pkts |= policy.eval(pkt)
        acc = (res,new_pkts)
    elif isinstance(policy,Query):
        acc = (res | {policy}, set())
    elif isinstance(policy,DerivedPolicy):
        acc = queries_in_eval(acc,policy.policy)
    elif isinstance(policy,parallel):
        parallel_res = set()
        parallel_pkts = set()
        for sub_pol in policy.policies:
            new_res,new_pkts = queries_in_eval((res,pkts),sub_pol)
            parallel_res |= new_res
            parallel_pkts |= new_pkts
        acc = (parallel_res,parallel_pkts)
    elif isinstance(policy,sequential):
        for sub_pol in policy.policies:
            acc = queries_in_eval(acc,sub_pol)
            if not acc[1]:
                break
    return acc


def on_recompile_path(acc,pol_id,policy):
    if (  policy == identity or
          policy == drop or
          isinstance(policy,match) or
          isinstance(policy,modify) or
          policy == Controller or
          isinstance(policy,Query)):
        return set()
    elif (isinstance(policy,negate) or
          isinstance(policy,parallel) or
          isinstance(policy,union) or
          isinstance(policy,sequential) or
          isinstance(policy,intersection)):
        sub_acc = set()
        for sub_policy in policy.policies:
            sub_acc |= on_recompile_path(sub_acc,pol_id,sub_policy)
        if sub_acc:
            return acc | {policy} | sub_acc
        else:
            return sub_acc
    elif isinstance(policy,DerivedPolicy):
        if id(policy) == pol_id:
            return acc | {policy}
        else:
            sub_acc = on_recompile_path(set(),pol_id,policy.policy)
            if sub_acc:
                return acc | {policy} | sub_acc
            else:
                return set()
    else:
        raise NotImplementedError
