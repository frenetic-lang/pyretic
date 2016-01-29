from pyretic.core.language import *

###############################################################################
# Class hierarchy syntax tree traversal

def default_mapper(parent, children):
    """Default mapping function for ast_map, which produces a copy of the input
    policy when provided to ast_map. The semantics of thenew policy that will be
    returned by ast_map() is that it is identical to the original policy from
    the point of view of eval(), while all nodes in the new policy AST are
    copies of the original (except for Queries, which share nodes with the input
    policy, to prevent lock sharing issues).
    """
    import copy
    import pyretic.lib.query as query
    from pyretic.core.language import _match, _modify
    # Leaf-level policies
    if ( parent == identity or
         parent == drop or
         isinstance(parent,match) or
         isinstance(parent,modify) or
         isinstance(parent, _match) or
         isinstance(parent, _modify) or
         parent == Controller):
        return copy.deepcopy(parent)
    # Queries are special: we return the actual instance directly because of
    # lock sharing bugs that would arise otherwise
    elif isinstance(parent,Query):
        return parent
    # Combinator policies are re-initialized with the constituent children
    elif ( (isinstance(parent,negate) or
            isinstance(parent,parallel) or
            isinstance(parent,union) or
            isinstance(parent,sequential) or
            isinstance(parent,intersection))):
        return (type(parent))(children)
    # Derived policies are treated case by case:
    elif isinstance(parent,difference):
        return difference(parent.f1, parent.f2)
    elif isinstance(parent,if_):
        return if_(parent.pred, parent.t_branch, parent.f_branch)
    elif isinstance(parent, fwd) or isinstance(parent,xfwd):
        return (type(parent))(parent.outport)
    elif isinstance(parent,query.packets):
        # The packets() constructor doesn't store data required to re-create the
        # object *exactly*. But if we're only concerned about the AST for eval()
        # purposes, then just creating a derived policy with the child policy
        # object is enough.
        return DerivedPolicy(children[0])
    elif isinstance(parent,DynamicPolicy):
        # See explanation for query.packets above; applies here as well.
        return DynamicPolicy(children[0])
    else:
        raise NotImplementedError

def ast_map(fun, policy):
    """
    Apply the function fun to each node, including putting together the results
    of the function application to children nodes and parent node in flexible
    ways.

    :param fun: the map function, which returns a transformed policy.
    :type fun: Policy * Policy list -> Policy
    :param policy: main policy to apply the map function to
    :type policy: Policy

    The map function takes two arguments.
    1. the parent policy
    2. the result of applying ast_map on all the children policies, as a list.
    It produces a new transformed policy that represents the entire tree rooted
    at the policy argument to this function.
    """
    import pyretic.lib.query as query
    children_pols = []
    if (  policy == identity or
          policy == drop or
          isinstance(policy,match) or
          isinstance(policy,modify) or
          policy == Controller or
          isinstance(policy,Query)):
        children_pols = []
    elif (isinstance(policy,negate) or
          isinstance(policy,parallel) or
          isinstance(policy,union) or
          isinstance(policy,sequential) or
          isinstance(policy,intersection)):
        for sub_policy in policy.policies:
            children_pols.append(ast_map(fun, sub_policy))
    elif (isinstance(policy,difference) or
          isinstance(policy,if_) or
          isinstance(policy,fwd) or
          isinstance(policy,xfwd) or
          isinstance(policy,DynamicPolicy) or
          isinstance(policy,query.packets)):
        children_pols.append(ast_map(fun, policy.policy))
    else:
        raise NotImplementedError
    return fun(policy, children_pols)

def ast_fold(fun, acc, policy):
    import pyretic.lib.query as query
    from pyretic.lib.path import QuerySwitch
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
    elif isinstance(policy, QuerySwitch):
        cases = copy.copy(policy.policy_dic)
        if not cases:
            def_policy = drop
            for act in policy.default:
                def_policy += act
            return ast_fold(fun, acc, def_policy)

        tag_value, sub_policy  = cases.popitem()
        match_tag = match(**{policy.tag:tag_value})  
        sub_policy = (match_tag >> sub_policy)
        acc = ast_fold(fun, acc, sub_policy)
        return ast_fold(fun, acc, ~match_tag >> QuerySwitch(policy.tag, cases, policy.default))
        
    else:
        raise NotImplementedError
    
def add_dynamic_sub_pols(acc, policy):
    if isinstance(policy,DynamicPolicy):
        return acc + [policy]
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
    from pyretic.lib.path import QuerySwitch
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
    elif isinstance(policy, QuerySwitch):
        cases = copy.copy(policy.policy_dic)
        if not cases:
            def_policy = drop
            for act in policy.default:
                def_policy += act
            acc = queries_in_eval(acc, def_policy)
        else:
            tag_value, sub_policy  = cases.popitem()
            match_tag = match(**{policy.tag:tag_value})  
            sub_policy = (match_tag >> sub_policy)
            sub_acc = queries_in_eval((res,pkts), sub_policy)
            res_acc = queries_in_eval((res,pkts), ~match_tag >> QuerySwitch(policy.tag, cases, policy.default))
            acc = (sub_acc[0] | res_acc[0], sub_acc[1] | res_acc[1]) 
    else:
        raise RuntimeError("unknown policy type")
    return acc


def on_recompile_path_set(acc,pol_id,policy):
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
            sub_acc |= on_recompile_path_set(sub_acc,pol_id,sub_policy)
        if sub_acc:
            return acc | {policy} | sub_acc
        else:
            return sub_acc
    elif isinstance(policy,DerivedPolicy):
        if id(policy) == pol_id:
            return acc | {policy}
        else:
            sub_acc = on_recompile_path_set(set(),pol_id,policy.policy)
            if sub_acc:
                return acc | {policy} | sub_acc
            else:
                return set()
    else:
        raise NotImplementedError

def on_recompile_path_list(pol_id,policy):
    from pyretic.lib.path import QuerySwitch
    if (  policy == identity or
          policy == drop or
          isinstance(policy,match) or
          isinstance(policy,modify) or
          policy == Controller or
          isinstance(policy,Query)):
        return list()
    elif (isinstance(policy,negate) or
          isinstance(policy,parallel) or
          isinstance(policy,union) or
          isinstance(policy,sequential) or
          isinstance(policy,intersection)):
        sub_acc = list()
        for sub_policy in policy.policies:
            sub_acc += on_recompile_path_list(pol_id,sub_policy)
        if sub_acc:
            return [policy] + sub_acc
        else:
            return list()
    elif isinstance(policy,DerivedPolicy):
        if id(policy) == pol_id:
            return [policy]
        else:
            sub_acc = on_recompile_path_list(pol_id,policy.policy)
            if sub_acc:
                return [policy] + sub_acc
            else:
                return list()
    elif isinstance(policy, QuerySwitch):
        cases = copy.copy(policy.policy_dic)
        if not cases:
            def_policy = drop
            for act in policy.default:
                def_policy += act
            return on_recompile_path_list(pol_id, def_policy)

        tag_value, sub_policy  = cases.popitem()
        match_tag = match(**{policy.tag:tag_value})  
        sub_policy = (match_tag >> sub_policy)
        sub_acc = on_recompile_path_list(pol_id, sub_policy)
        return sub_acc + on_recompile_path_list(pol_id, ~match_tag >> QuerySwitch(policy.tag, cases, policy.default))
        

    else:
        raise NotImplementedError
