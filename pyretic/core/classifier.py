
from collections import deque
import copy
from pyretic.evaluations import stat
###############################################################################
# Classifiers
# an intermediate representation for proactive compilation.

class Rule(object):
    """
    A rule contains a filter and the parallel composition of zero or more
    Pyretic actions.
    """

    # Matches m should be of the match class.  Actions acts should be a set of
    # modify, identity, and/or Controller/CountBucket/FwdBucket policies.
    # Actions is Rule are semantically meant to run in parallel
    # unlike OpenFlow rules.
    def __init__(self,m,acts,parents=[],op="policy"):
        self.match = m
        self.actions = acts
        self.parents = parents
        """ op is the operator which combined the parents of this rule. Set of
        values it can take:
        - a class name of type CombinatorPolicy (in particular: "negate",
        "parallel", "sequential")
        - "empty_parallel", when two classifiers which are added results in a
        drop classifier because of zero intersection.
        - "policy" (this is a leaf rule directly generated from a policy)
        """
        self.op = op

    def __str__(self):
        return str(self.match) + '\n  -> ' + str(self.actions)

    def __repr__(self):
        return str(self)

    def __eq__(self, other):
        """Based on syntactic equality of policies."""
        return ( id(self) == id(other)
            or ( self.match == other.match
                 and sorted(self.actions) == sorted(other.actions) ) )

    def __ne__(self, other):
        """Based on syntactic equality of policies."""
        return not (self == other)

    def eval(self, in_pkt):
        """
        If this rule matches the packet, then return the union of the sets
        of packets produced by the actions.  Otherwise, return None.
        """
        filtered_pkt = self.match.eval(in_pkt)
        if len(filtered_pkt) == 0:
            return None
        rv = set()
        for pkt in filtered_pkt:
            for act in self.actions:
                rv |= act.eval(pkt)
        return rv


def get_rule_derivation_tree(r, pre_spaces='', only_leaves=False):
    """ Get the tree of rules deriving the current rule."""
    assert isinstance(r, Rule)
    op = r.op
    assert op in ["policy", "parallel", "empty_parallel",
                  "sequential", "negate", "netkat"]
    extra_ind = '    '
    output = ''
    if op == "parallel" or op == "negate" or op == "sequential":
        if not only_leaves:
            output  = pre_spaces + str(r.match) + '\n'
            output += pre_spaces + '-> ' + str(r.actions) + '\n'
        output += pre_spaces + '[operator ' + r.op + ']\n'
        for rp in r.parents:
            output += get_rule_derivation_tree(rp, pre_spaces+extra_ind,
                                               only_leaves)
    elif op == "policy":
        try:
            if r.parents[0]:
                output = pre_spaces + str(r.parents[0]) + '\n'
        except IndexError:
            print "I got an index error! The rule is", r
            print "Parents of this rule are:", r.parents
            import sys
            sys.exit(0)
    elif op == "empty_parallel":
        output = pre_spaces + "empty classifier\n"
    elif op == "netkat":
        output = pre_spaces + str(r) + '\n'
    else:
        raise TypeError
    return output

def get_rule_derivation_leaves(r):
    """ Get just the leaf policies from the derivation tree of a rule, in a
    list. """
    assert isinstance(r, Rule)
    op = r.op
    assert op in ["policy", "parallel", "empty_parallel",
                  "sequential", "negate", "netkat"]
    leaf_list = []
    if op == "parallel" or op == "negate" or op == "sequential":
        for rp in r.parents:
            leaf_list += get_rule_derivation_leaves(rp)
    elif op == "policy":
        if r.parents[0]:
            leaf_list += [r.parents[0]]
    elif op == "empty_parallel":
        pass
    elif op == "netkat":
        leaf_list += [r]
    else:
        raise TypeError
    return leaf_list

# Classifier -> match -> rule
def get_rule_exact_match(classifier, mat):
    """ Get a rule from the classifier with a given match. """
    for r in classifier.rules:
        if r.match == mat:
            return r
    return None

#### Compilation helper functions, exposed for easier testing. ####
# given a test b and an action p, return a test
# b' such that p >> b == b' >> p.
def _commute_test(act, pkts):
    from pyretic.core.language import (match, modify, drop, identity,
                                       Controller, CountBucket,
                                       DerivedPolicy, PathBucket, IdentityClass)
    from pyretic.lib.netflow import NetflowBucket
    while isinstance(act, DerivedPolicy):
        act = act.policy
    if act == identity:
        return pkts
    elif (act == Controller or isinstance(act, PathBucket) or
          isinstance(act, NetflowBucket)):
        return identity
    elif isinstance(act, CountBucket):
        """ TODO(ngsrinivas): inspect which possibility is best """
        return identity
        # return pkts
    elif isinstance(act, modify):
        new_match_dict = {}
        if pkts == identity:
            return identity
        elif pkts == drop:
            return drop
        for f, v in pkts.map.iteritems():
            if f in act.map and act.map[f] == v:
                continue
            elif f in act.map and act.map[f] != v:
                return drop
            else:
                new_match_dict[f] = v
        if len(new_match_dict) == 0:
            return identity
        return match(**new_match_dict)
    else:
        raise TypeError

# sequentially compose actions.  a1 must be a
# single action.  Returns a list of actions.
def _sequence_actions(a1, as2):
    from pyretic.core.language import (match, modify, drop, identity,
                                       Controller, CountBucket,
                                       DerivedPolicy, PathBucket)
    from pyretic.lib.netflow import NetflowBucket
    while isinstance(a1, DerivedPolicy):
        a1 = a1.policy
    # TODO: be uniform about returning copied or modified objects.
    if (a1 == Controller or isinstance(a1, CountBucket) or 
        isinstance(a1, PathBucket) or isinstance(a1, NetflowBucket)):
        return {a1}
    elif a1 == identity:
        return copy.copy(as2)
    elif isinstance(a1, modify):
        new_actions = set()
        for a2 in as2:
            while isinstance(a2, DerivedPolicy):
                a2 = a2.policy
            if (a2 == Controller or isinstance(a2, CountBucket) or
                isinstance(a2, PathBucket) or isinstance(a2, NetflowBucket)):
                new_actions.add(a2)
            elif a2 == identity:
                new_actions.add(a1)
            elif isinstance(a2, modify):
                new_a1_map = a1.map.copy()
                new_a1_map.update(a2.map)
                new_actions.add(modify(**new_a1_map))
                # TODO(ngsrinivas): remove later if no issues
                # new_a1 = modify(**a1.map.copy())
                # new_a1.map.update(a2.map)
                # new_actions.add(new_a1)
            else:
                raise TypeError
        return new_actions
    else:
        raise TypeError

# generates a (potentially) non-total classifier 
# containing a single rule, or None
def _cross_act(r1,act,r2):
    from pyretic.core.language import drop
    m = r1.match.intersect(_commute_test(act, r2.match))
    actions = _sequence_actions(act,r2.actions)
    if m == drop:
        return None
    else:
        return Classifier([Rule(m,actions,[r1,r2],"sequential")])

# returns a potentially non-total classifier
# suitable for concatenating w/ other potentially non-total classifiers
def _cross_rules(r1,r2):
    c = None
    for act in r1.actions:
        cross = _cross_act(r1,act,r2) 
        if c is None:
            c = cross
        elif not cross is None:
            # parallel compose to get c_tmp
            c_tmp = c + cross
            # but since both c and cross were potentially non-total
            # we need to append both c and cross to c_tmp
            c_tmp.append(c)
            c_tmp.append(cross)
            # set c to c_tmp and optimize
            c = c_tmp
            c = c.optimize()
    return c
#### End of exposed classifier helper functions ####

class Classifier(object):
    """
    A classifier contains a list of rules, where the order of the list implies
    the relative priorities of the rules.  Semantically, classifiers are
    functions from packets to sets of packets, similar to OpenFlow flow
    tables.
    """

    def __init__(self, new_rules=list()):
        import types
        if isinstance(new_rules, types.GeneratorType):
            self.rules = deque([r for r in new_rules])
        elif isinstance(new_rules,list):
            self.rules = deque(new_rules)
        elif isinstance(new_rules,deque):
            self.rules = new_rules
        else:
            raise TypeError

    def __len__(self):
        return len(self.rules)

    def __str__(self):
        return '\n '.join(map(str,self.rules))

    def __repr__(self):
        return str(self)

    def __eq__(self, other):
        """Based on syntactic equality of policies."""
        return ( id(self) == id(other)
            or ( self.rules == other.rules ) )

    def __ne__(self, other):
        """Based on syntactic equality of policies."""
        return not (self == other)

    def eval(self, in_pkt):
        """
        Evaluate against each rule in the classifier, starting with the
        highest priority.  Return the set of packets resulting from applying
        the actions of the first rule that matches.
        """
        for rule in self.rules:
            pkts = rule.eval(in_pkt)
            if pkts is not None:
                return pkts
        raise TypeError('Classifier is not total.')

    def prepend(self, item):
        if isinstance(item, Rule):
            self.rules.appendleft(item)
        elif isinstance(item, Classifier):
            self.rules.extendleft(item.rules)
        else:
            raise TypeError            

    def append(self, item):
        if isinstance(item, Rule):
            self.rules.append(item)
        elif isinstance(item, Classifier):
            self.rules.extend(item.rules)
        else:
            raise TypeError

    def remove_last_rule(self):
        self.rules.pop()

    def __copy__(self):
        copied_rules = map(copy.copy,self.rules)
        return Classifier(copied_rules)


    ### NEGATE ###
    def __invert__(self):
        from pyretic.core.language import identity
        new_rules = list()
        for r in self.rules:
            r_new = copy.copy(r)
            if len(r.actions) == 0:
                r_new.actions = {identity}
            elif r.actions == {identity}:
                r_new.actions = set()
            else:
                raise TypeError  # TODO MAKE A CompileError TYPE
            r_new.parents = [r]
            r_new.op = "negate"
            new_rules.append(r_new)
        c = Classifier(new_rules)

        return c


    ### PARALLEL COMPOSITION
            
    def __add__(c1, c2):
        from pyretic.core.language import drop, identity
        def _cross(r1,r2):
            intersection = r1.match.intersect(r2.match)
            if intersection != drop:
                actions = r1.actions | r2.actions
                return Rule(intersection, actions, [r1, r2], "parallel")
            else:
                return None

        # start with an empty set of rules for the output classifier
        c3 = Classifier()
        assert(not (c1 is None and c2 is None))
        # then cross all pairs of rules in the first and second classifiers
        for r1 in c1.rules:
            for r2 in c2.rules:
                crossed_r = _cross(r1,r2)
                if crossed_r:
                    c3.append(crossed_r)
        # if the classifier is empty, add a drop-all rule
        if len(c3) == 0:
            c3.append(Rule(identity,set(),[c1, c2],"empty_parallel"))
        # and optimize the classifier
        else:
            c3 = c3.optimize()

        return c3


    ### SEQUENTIAL COMPOSITION

    def __rshift__(c1, c2):
        from pyretic.core.language import (match, modify, drop, identity,
                                           Controller, CountBucket,
                                           DerivedPolicy, PathBucket)
        # start with an empty set of rules for the output classifier
        # then for each rule in the first classifier (self)
        c3 = Classifier()
        for r1 in c1.rules:
            if len(r1.actions) == 0:
                c3.append(r1)
            else:
                for r2 in c2.rules:
                    c_tmp = _cross_rules(r1,r2)
                    if not c_tmp is None:
                        c3.append(c_tmp)
        # when all rules in c1 and c2 have been crossed
        # optimize c3
        c3 = c3.optimize()

        return c3


    ### SHADOW OPTIMIZATION

    def __div__(c1, c2):
        #TODO: checks
        #TODO: type error?
        #TODO: parent?
        from pyretic.core.language import identity

        def check_classifier_structure(c):
            rules = list(c.rules)
            if len(rules) == 0:
                raise TypeError

            def_rule = rules[-1]
            if def_rule.match != identity:
                raise TypeError

            body_rules = rules[:-1]
            for r in body_rules:
                if r.match == identity:
                    raise TypeError
            return (body_rules, def_rule)

        (body1, def1) = check_classifier_structure(c1)
        (body2, def2) = check_classifier_structure(c2)

        new_rules = list()
        for r in body1:
            r_new = copy.copy(r)
            r_new.actions |= def2.actions 
            r_new.parents = [r, def2]
            r_new.op = "div"
            new_rules.append(r_new)
        
        for r in body2:
            r_new = copy.copy(r)
            r_new.actions |= def1.actions
            r_new.parents = [r, def1]
            r_new.op = "div"
            new_rules.append(r_new)
        
        new_rules.append(Rule(identity, def1.actions|def2.actions, [def1, def2], "div"))
        c = Classifier(new_rules)
        c = c.optimize()
        return c



    def optimize(self):
        return self.remove_shadowed_cover_single()

    def remove_shadowed_exact_single(self):
        # Eliminate every rule exactly matched by some higher priority rule
        opt_c = Classifier()
        for r in self.rules:
            if not reduce(lambda acc, new_r: acc or
                          new_r.match == r.match,
                          opt_c.rules,
                          False):
                opt_c.rules.append(r)
        return opt_c

    def remove_shadowed_cover_single(self):
        # Eliminate every rule completely covered by some higher priority rule
        opt_c = Classifier()
        for r in self.rules:
            if not reduce(lambda acc, new_r: acc or
                          new_r.match.covers(r.match),
                          opt_c.rules,
                          False):
                opt_c.rules.append(r)
        return opt_c
