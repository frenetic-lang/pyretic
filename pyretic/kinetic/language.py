from pyretic.lib.corelib import *
from random import choice
from threading import Lock
import hashlib
import operator
import copy
import sys

## Used globally
policy_to_name_map = {}
complexPolicyStr_to_actualPolicy = {}

def ask_deploy():
    var = raw_input("Deploy? (yes/no): ")
    print "You entered: ", var   
    if var.lower()=='yes' or var.lower()=='y':
        return
    elif var.lower()=='no' or var.lower()=='n':
        sys.exit()
    else:
        print 'Unknown answer. Please enter "yes" or "no".'
        ask_deploy()

def as_comment(s):
    s = '-- ' + s
    s = s.replace('\n', '\n-- ')
    return s

def policy_to_hash(p_named_set,policy_set,p):
    if isinstance(p,sequential):
        newp = sequential(p.policies)
        for c in range(newp.policies.count(identity)):
            if newp.policies!=[identity]:
                newp.policies.remove(identity)
        p = newp
    if isinstance(p,flood):
        p_named_set.add('flood')
        return 'flood'
    elif isinstance(p,fwd):
        p_named_set.add('_'.join(str(p).split()))
        return '_'.join(str(p).split())
    elif isinstance(p, Policy) and p.compile() == drop.compile():
        p_named_set.add('drop')
        return 'drop'
#    elif isinstance(p, Policy) and p.compile() == identity.compile():
#        p_named_set.add('identity')
#        return 'identity'
#    elif isinstance(p,union):
#        print 'yo'
#        return 'union'
    s = str(p) 
    if s=='False':
        return 'FALSE'
    elif s=='True':
        return 'TRUE'
    elif s.isdigit():
        return s
    else: 
        complexPolicyStr_to_actualPolicy[s] = p
        policy_set.add(s)

def to_smv(i):
    if isinstance(i,sequential):
        newp = sequential(i.policies)
        for c in range(newp.policies.count(identity)):
            if newp.policies!=[identity]:
                newp.policies.remove(identity)
        i = newp
 
    if isinstance(i,flood):
        return 'flood'
    elif isinstance(i,fwd):
        return '_'.join(str(i).split())
    elif isinstance(i,NonDetermPolicy):
        policy_list = []
        for p in i.getList():
            policy_list.append(to_smv(p))
        return ' union '.join(policy_list)
    elif isinstance(i,Policy) and i.compile() == drop.compile():
        return 'drop'
#    elif isinstance(i,Policy) and i.compile() == identity.compile():
#        return 'identity'
    s = str(i) 
    if s=='False':
        return 'FALSE'
    elif s=='True':
        return 'TRUE'
    elif s.isdigit():
        return s
    else:
        if policy_to_name_map.has_key(s):
            return policy_to_name_map[s]
        else:
            print "Cannot find this polcy. Given policy is:\n",str(i)
            print "Keys in policy_to_name_map: "
            for k in policy_to_name_map.keys():
                print k
            sys.exit()


### Types

class Type(object):
    def __init__(self,py_type,dom):
        self.py_type=py_type
        self.dom=dom

class BoolType(Type):
    def __init__(self):
        super(BoolType,self).__init__(bool,{True,False})

### Case Expressions

class CaseExpression(object):
    def __call__(self,state,event):
        raise NotImplementedError

    def __eq__(self, other):
        return test_eq(self,other)

    def __ne__(self,other):
        return e_test_ne(self,other)

### Case Atoms

class CaseAtom(CaseExpression):
    def model(self):
        return str(self)

class V(CaseAtom):
    def __init__(self,s):
        self.name=s

    def __call__(self,state,event):
        return state[self.name]

    def __str__(self):
        return 'V(' + self.name + ')'

    def model(self):
        return str(self.name)

class E(CaseAtom):
    def __init__(self,s):
        self.name=s
        self.type=None

    def add_type(self,t):
        self.type=t

    def __call__(self,state,event):
        return event[self.name]

    def __str__(self):
        return 'E(' + self.name + ')'

    def model(self):
        if self.type is None:
            return '{???}'
        else:
            return '{' + ','.join(map(to_smv,self.type.dom)) + '}'
                                  
class C(CaseAtom):
    def __init__(self,val):
        self.val = val

    def __call__(self,state,event):
        return self.val

    def __str__(self):
        if isinstance(self.val,flood):
            return 'C(flood)'
        elif isinstance(self.val,fwd):
            return 'C(' + '_'.join(str(self.val).split()) + ')'
        elif isinstance(self.val,NonDetermPolicy):
            return 'C(' + ' union '.join(self.val.getList())
        else:
#            policynum = int(hashlib.md5(str(self.val)).hexdigest(), 16)
#            return 'C(' + 'policy_' + str(policynum) + ')'
            return 'C(' + str(self.val) + ')'

    def model(self):
        return to_smv(self.val)

### Case Tests

class CaseTest(CaseExpression):
    def __and__(self,other):
        return test_and(self,other)

    def model(self):
        return str(self)

class test_eq(CaseTest):
    def __init__(self,l,r):
        self.l = l
        self.r = r

    def __call__(self,state,event):
        return self.l(state,event)==self.r(state,event)
    
    def __str__(self):
        return '(' + str(self.l) + '=' + str(self.r) + ')'

    def model(self):
        return '(' + self.l.model() + '=' + self.r.model() + ')'

class test_ne(CaseTest):
    def __init__(self,l,r):
        self.l = l
        self.r = r

    def __call__(self,state,event):
        return self.l(state,event)!=self.r(state,event)
    
    def __str__(self):
        return '(' + str(self.l) + '!=' + str(self.r) + ')'

    def model(self):
        return '(' + self.l.model() + '!=' + self.r.model() + ')'

class test_and(CaseTest):
    def __init__(self,l,r):
        self.l = l
        self.r = r

    def __call__(self,state,event):
        return self.l(state,event) and self.r(state,event)
    
    def __str__(self):
        return str(self.l) + ' & ' + str(self.r) 

    def model(self):
        l_model = self.l.model()
        if l_model == 'TRUE':
            return self.r.model()
#        return self.r.model() 
        return self.l.model() + ' & ' + self.r.model()

class test_and_true(CaseTest):
    def __init__(self,l,r):
        self.l = l
        self.r = r

    def __call__(self,state,event):
        return self.l(state,event)==True and self.r(state,event)==True

    def __str__(self):
        return str(self.l) + ' & ' + str(self.r)

    def model(self):
        l_model = self.l.model()
        if l_model == 'TRUE':
            return self.r.model()
        return self.l.model() + ' & ' + self.r.model()


class TrueTest(test_eq):
    def __init__(self):
        super(TrueTest,self).__init__(C(True),C(True))

    def __str__(self):
        return 'TrueTest'

    def model(self):
        return 'TRUE'

class is_true(test_eq):
    def __init__(self,atom):
        super(is_true,self).__init__(atom,C(True))

    def __str__(self):
        return 'is_true(' + str(self.l) + ')'

    def model(self):
        return self.l.model()

class occurred(test_ne):
    def __init__(self,event):
        super(occurred,self).__init__(event,C(None))

    def __str__(self):
        return 'occurred(' + str(self.l) + ')'

    def model(self):
        return 'TRUE'

### Case

class case(object):
    def __init__(self,tst,rslt):
        self.tst=tst
        self.rslt=rslt

    def __str__(self):
        return str(self.tst) + '\t: ' + str(self.rslt)

    def model(self):
        return self.tst.model() + '\t: ' + self.rslt.model()
        
class default(case):
    def __init__(self,rslt):
        super(default,self).__init__(TrueTest(),rslt)

### Transition

class Transition(object):
    def __init__(self,var_name):
        self.var_name = var_name
        self.cases = list()

    def case(self,tst,rslt):
        new_case = case(tst,rslt)
        self.cases.append(new_case)

    def default(self,rslt):
        new_case = default(rslt)
        self.cases.append(new_case)

    def __call__(self,state,event):
        for c in self.cases:
            if c.tst(state,event):
                return c.rslt(state,event)
        raise RuntimeError

    def __str__(self):
        r  = 'next(' + self.var_name + ') :=\n' 
        r += '\tcase\n'
        for c in self.cases:
            r += '\t\t' + str(c) + ';\n' 
        r += '\tesac;'
        return r

    def model(self):
        r  = 'next(' + self.var_name + ') :=\n' 
        r += '\tcase\n'
        for c in self.cases:
            r += '\t\t' + c.model() + ';\n' 
        r += '\tesac;'
        return r

def transition(cases_fn):
    var_name = cases_fn.__name__
    class DecoratedTransition(Transition):
        def __init__(self,var_name):
            Transition.__init__(self,var_name)
            self.event = E(var_name)
            cases_fn(self)
            if (len(self.cases)==0 or 
                not isinstance(self.cases[-1].tst,TrueTest)):                 
                self.default(V(var_name))
            
    DecoratedTransition.__name__ = var_name
    return DecoratedTransition(var_name)

### helper methods

def events(i):
    if isinstance(i,E):
        return {i}
    elif isinstance(i,CaseAtom):
        return set()
    elif isinstance(i,TrueTest):
        return set()
    elif isinstance(i,occurred):
        return events(i.l)
    elif isinstance(i,is_true):
        return events(i.l)
    elif isinstance(i,CaseTest):
        return events(i.l) | events(i.r)
    elif isinstance(i,case):
        return events(i.tst) | events(i.rslt)
    elif isinstance(i,Transition):
        ts = map(events,i.cases)
        r = set()
        for t in ts:
            r |= t
        return r
    else:
        raise TypeError

def variables(i):
    if isinstance(i,V):
        return {i.name}
    elif isinstance(i,CaseAtom):
        return set()
    elif isinstance(i,TrueTest):
        return set()
    elif isinstance(i,occurred):
        return set()
    elif isinstance(i,is_true):
        return variables(i.l)
    elif isinstance(i,CaseTest):
        return variables(i.l) | variables(i.r)
    elif isinstance(i,case):
        return variables(i.tst) | variables(i.rslt)
    elif isinstance(i,Transition):
        ts = map(variables,i.cases)
        r = set()
        for t in ts:
            r |= t
        return r
    else:
        raise TypeError

### FSM Variable

class FSMVar(dict):
    __slots__ = ["_dict"]
    def __init__(self,**kwargs):
        self._dict = dict(endogenous=False,exogenous=False)
        self._dict.update(dict(**kwargs))
        
    def get(self, key, default=None):
        return self._dict.get(key, default)

    def __getitem__(self, item):
        return self._dict[item]

### FSM Definition

class FSMDef(object):
    def __init__(self,**kwargs):
        self.map = dict(**kwargs)


### Nondeterminstic Policy 
class NonDetermPolicy(DynamicPolicy):
    def __init__(self, policy_list):
        self.policy_list = policy_list
        self.initial_policy = policy_list[choice(range(len(policy_list)))]
        self.lock = Lock()
        super(NonDetermPolicy,self).__init__(self.initial_policy)

    def getList(self):
        return list([str(i) for i in self.policy_list])

def fsm_def_compose(fsm_def_1,fsm_def_2,comp_op_str):

    # first, define.
    composed_fsm_def = FSMDef()

    # Put variables except policy from fsm1
    for k,v in fsm_def_1.map.items():
        t=v['type']
        if t.py_type!=Policy:
            composed_fsm_def.map[k] = v

    # Put variables except policy from fsm2 
    for k,v in fsm_def_2.map.items():
        t=v['type']
        if t.py_type!=Policy:
            composed_fsm_def.map[k] = v

    # Build Policy 
    policy_fsmvar_map={}

    policy_set = set()
    p_named_set = set()
    for k1,v1 in fsm_def_1.map.items():
        t1 = v1['type']
        for k2,v2 in fsm_def_2.map.items():
            t2 = v2['type']
            if t1.py_type==Policy and t2.py_type==Policy:
                for p1 in t1.dom:
                    for p2 in t2.dom:
                        if comp_op_str=='>>':
                            policy_to_hash(p_named_set,policy_set, p1>>p2)
                        elif comp_op_str=='+':
                            policy_to_hash(p_named_set,policy_set, p1+p2)
                        else:
                            print 'Unknown composition operator. Abort'
                            sys.exit()
    sorted_list = sorted(list(policy_set))
    for idx,p in enumerate(sorted_list):
        policy_to_name_map[p] = 'policy_'+str(idx+1)

    ### Policy's type and possible values
    real = set()
    pols_list = policy_to_name_map.values()
    pols_list.extend(list(p_named_set))
    for i in pols_list:
        if i.startswith('policy'):
            for j in policy_to_name_map:
                if policy_to_name_map[j] == i:
                    real.add(complexPolicyStr_to_actualPolicy[j])
        else:
            real.add(eval(i))
    p_type_defined = Type(Policy, real)
    policy_fsmvar_map['type'] = p_type_defined 

    ### Policy init
    for k,v in fsm_def_1.map.items():
        t = v['type']
        if t.py_type==Policy:
            f1_init = v['init']
    for k,v in fsm_def_2.map.items():
        t = v['type']
        if t.py_type==Policy:
            f2_init = v['init']
    if comp_op_str=='>>':
        policy_fsmvar_map['init'] = f1_init >> f2_init
    elif comp_op_str=='+':  
        policy_fsmvar_map['init'] = f1_init + f2_init
    else:
        print 'Unknown composition operator. Abort'
        sys.exit()
 
    ### Policy trans
    trans_p = Transition('policy')
    for k,v in fsm_def_1.map.items():
        t = v['type']
        if t.py_type==Policy:
            f1_trans = v['trans']
    for k,v in fsm_def_2.map.items():
        t = v['type']
        if t.py_type==Policy:
            f2_trans = v['trans']


    #### Combined transition
    tests_and_results = {}
    for c1 in f1_trans.cases:
        for c2 in f2_trans.cases:
            if type(c1.tst)==TrueTest and type(c2.tst)==TrueTest:
                this_tst = TrueTest()
                test_str = 'TRUE'
            elif type(c1.tst)==TrueTest:
                this_tst = c2.tst
                test_str = str(c2.tst.model()) 
            elif type(c2.tst)==TrueTest:
                this_tst = c1.tst
                test_str = str(c1.tst.model()) 
            else: 
                this_tst = c1.tst & c2.tst
                test_str = str(c1.tst.model()) + ' & ' + str(c2.tst.model())
            c1val = None
            c2val = None
            if isinstance(c1.rslt,V):
                print 'Default value not given. Cannot deal with that now. Put it default for each variable.'
                sys.exit()
                for k,v in fsm_def_1.map.items():
                    if k==c1.rslt.name:
                        c1val = v['init']
                        break
            if isinstance(c2.rslt,V):
                print 'Default value not given. Cannot deal with that now. Put it default for each variable.'
                sys.exit()
                for k,v in fsm_def_1.map.items():
                    if k==c2.rslt.name:
                        c2val = v['init']
                        break
            if c1val==None:
                c1val = c1.rslt.val
            if c2val==None:
                c2val = c2.rslt.val
            if comp_op_str=='>>':
                this_result = C(c1val >> c2val)
            elif comp_op_str=='+':
                this_result = C(c1val + c2val)
            else:
                print 'Unknown composition operator. Abort'
                sys.exit()
            tests_and_results[this_tst] = this_result

    ## sort
    keys = tests_and_results.keys()
    key_operator_count_map = {}
    for k in keys:
        key_operator_count_map[k] = str(k).count(' & ')
        if isinstance(k,TrueTest):
            key_operator_count_map[k] = -1
    for sk in sorted(key_operator_count_map.iteritems(), key=operator.itemgetter(1),reverse=True):
        trans_p.case(sk[0],tests_and_results[sk[0]])

    # Trans value
    policy_fsmvar_map['trans'] = trans_p
    composed_fsm_def.map['policy'] = policy_fsmvar_map


#    print '========RETURN======'
#    for k,v in composed_fsm_def.map.items():
#        t=v['type']
#        if t.py_type==Policy:
#            print k
#            print v['trans']
#    print '=============='
#




    return composed_fsm_def, fsm_def_to_smv_model(composed_fsm_def)

def fsm_def_to_smv_model_compose(fsm_def_1,fsm_def_2,comp_op_str):
    # First, see if there are complex policies. 
    # If so, number them, and save info.
    policy_set = set()
    p_named_set = set()
    for k1,v1 in fsm_def_1.map.items():
        t1 = v1['type']
        for k2,v2 in fsm_def_2.map.items():
            t2 = v2['type']
            if t1.py_type!=bool and t2.py_type!=bool:
                for p1 in t1.dom:
                    for p2 in t2.dom:
                        if comp_op_str=='>>':
                            policy_to_hash(p_named_set,policy_set, p1>>p2)
                        elif comp_op_str=='+':
                            policy_to_hash(p_named_set,policy_set, p1+p2)
                        else:
                            print 'Unknown composition operator. Abort'
                            sys.exit()
    sorted_list = sorted(list(policy_set))
    for idx,p in enumerate(sorted_list):
        policy_to_name_map[p] = 'policy_'+str(idx+1)

    # Start        
    s =  'MODULE main\n'

    ### VAR part
    s += '  VAR\n'
    for k,v in fsm_def_1.map.items():
        t = v['type']
        if t.py_type==bool:
            s += '    %s\t: %s;\n' % (k,'boolean')
        elif t.py_type!=Policy:
            s += '    %s\t: %s;\n' % (k,'{' + ','.join(map(to_smv,t.dom)) + '}')

    for k,v in fsm_def_2.map.items():
        t = v['type']
        if t.py_type==bool:
            s += '    %s\t: %s;\n' % (k,'boolean')
        elif t.py_type!=Policy:
            s += '    %s\t: %s;\n' % (k,'{' + ','.join(map(to_smv,t.dom)) + '}')
    pols_list = policy_to_name_map.values()
    pols_list.extend(list(p_named_set))
    s += '    %s\t: %s;\n' % ('policy','{' + ','.join(pols_list) + '}')

    ### ASSIGN part 
    s+= '  ASSIGN\n'
    for k,v in fsm_def_1.map.items():
        t = v['type']
        if t.py_type!=Policy:
            s += '    init(%s) := %s;\n' % (k,to_smv(v['init']))
        else:
            f1_init = v['init']
    for k,v in fsm_def_2.map.items():
        t = v['type']
        if t.py_type!=Policy:
            s += '    init(%s) := %s;\n' % (k,to_smv(v['init']))
        else:
            f2_init = v['init']
    if comp_op_str=='>>':
        s += '    init(%s) := %s;\n' % ('policy',to_smv(f1_init >> f2_init))
    elif comp_op_str=='+':  
        s += '    init(%s) := %s;\n' % ('policy',to_smv(f1_init + f2_init))
    else:
        print 'Unknown composition operator. Abort'
        sys.exit()
 
    ### NEXT  part
    for k,v in fsm_def_1.map.items():
        t = v['type']
        if t.py_type!=Policy:
            s += '    '+v['trans'].model()+'\n'
        else:
            f1_trans = v['trans']
    for k,v in fsm_def_2.map.items():
        t = v['type']
        if t.py_type!=Policy:
            s += '    '+v['trans'].model()+'\n'
        else:
            f2_trans = v['trans']


    #### Combined transition
    tests_and_results = {}
    for c1 in f1_trans.cases:
        for c2 in f2_trans.cases:
            if type(c1.tst)==TrueTest and type(c2.tst)==TrueTest:
                test_str = 'TRUE'
            elif type(c1.tst)==TrueTest:
                test_str = str(c2.tst.model()) 
            elif type(c2.tst)==TrueTest:
                test_str = str(c1.tst.model()) 
            else: 
                test_str = str(c1.tst.model()) + ' & ' + str(c2.tst.model())
            if comp_op_str=='>>':
                result = to_smv( c1.rslt.val >> c2.rslt.val)
            elif comp_op_str=='+':
                result = to_smv( c1.rslt.val + c2.rslt.val)
            else:
                print 'Unknown composition operator. Abort'
                sys.exit()
            tests_and_results[test_str] = result

    ## sort
    keys = tests_and_results.keys()
    key_operator_count_map = {}
    for k in keys:
        key_operator_count_map[k] = k.count(' & ')
    ## print policy case
    s += '    next(policy) := \n        case\n'
    for sk in sorted(key_operator_count_map.iteritems(), key=operator.itemgetter(1),reverse=True):
        s += '            ' + sk[0] + ' : ' + tests_and_results[sk[0]] + ';\n'
    s += '        esac;\n'

    # Comment about policies
    mapping_str = ' \n\n=====================================================================\n'
    mapping_str = mapping_str + 'PolicyName (used in NuSMV) to ActualPolicy (used in Pyretic) Mapping\n'
    mapping_str = mapping_str + '=====================================================================\n'
    sorted_tuple = sorted(policy_to_name_map.iteritems(), key=operator.itemgetter(1))
  
    for p in sorted_tuple:
        policy = p[0]
        pname = p[1]
        mapping_str = mapping_str + '---------------------------------------------\n'
        mapping_str = mapping_str + pname + ': (shown below)\n'
        mapping_str = mapping_str + '---------------------------------------------\n'
        mapping_str = mapping_str + policy  + '\n'
        mapping_str = mapping_str + '---------------------------------------------\n\n'

   # Make it as comment, and add to NuSMV input file.        
    mapping_str = as_comment(mapping_str)
    s = s + mapping_str

    return s


def fsm_def_to_smv_model(fsm_def):


    # First, see if there are complex policies. 
    # If so, number them, and save info.
    policy_set = set()
    p_named_set = set()
    for k,v in fsm_def.map.items():
        t = v['type']
        if t.py_type==Policy:
            for p in t.dom:
                policy_to_hash(p_named_set,policy_set, p)
    sorted_list = sorted(list(policy_set))
    for idx,p in enumerate(sorted_list):
        policy_to_name_map[p] = 'policy_'+str(idx+1)

    # Start        
    s =  'MODULE main\n'
    s += '  VAR\n'
    for k,v in fsm_def.map.items():
        t = v['type']
        if t.py_type==bool:
            s += '    %s\t: %s;\n' % (k,'boolean')
        else:
            s += '    %s\t: %s;\n' % (k,'{' + ','.join(map(to_smv,t.dom)) + '}')

    s+= '  ASSIGN\n'
    for k,v in fsm_def.map.items():
        s += '    init(%s) := %s;\n' % (k,to_smv(v['init']))

    for k,v in fsm_def.map.items():
        s += '    '+v['trans'].model()+'\n'

    ## Add comment about policy_name to actual_policy mapping
    mapping_str = ' \n\n=====================================================================\n'
    mapping_str = mapping_str + 'PolicyName (used in NuSMV) to ActualPolicy (used in Pyretic) Mapping\n'
    mapping_str = mapping_str + '=====================================================================\n'
    sorted_tuple = sorted(policy_to_name_map.iteritems(), key=operator.itemgetter(1))
  
    for p in sorted_tuple:
        policy = p[0]
        pname = p[1]
        mapping_str = mapping_str + '---------------------------------------------\n'
        mapping_str = mapping_str + pname + ': (shown below)\n'
        mapping_str = mapping_str + '---------------------------------------------\n'
        mapping_str = mapping_str + policy  + '\n'
        mapping_str = mapping_str + '---------------------------------------------\n\n'

    # Make it as comment, and add to NuSMV input file.        
    mapping_str = as_comment(mapping_str)
    s = s + mapping_str

    return s

