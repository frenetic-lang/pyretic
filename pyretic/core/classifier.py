
from collections import deque

###############################################################################
# Classifiers
# an intermediate representation for proactive compilation.

class Rule(object):
    """
    A rule contains a filter and the parallel composition of zero or more
    Pyretic actions.
    """

    # Matches m should be of the match class.  Actions acts should be a list of
    # either modify, identity, or drop policies.
    def __init__(self,m,acts):
        self.match = m
        self.actions = acts

    def __str__(self):
        return str(self.match) + '\n  -> ' + str(self.actions)

    def __repr__(self):
        return str(self)

    def __eq__(self, other):
        """Based on syntactic equality of policies."""
        return ( id(self) == id(other)
            or ( self.match == other.match
                 and self.actions == other.actions ) )

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


class Classifier(object):
    """
    A classifier contains a list of rules, where the order of the list implies
    the relative priorities of the rules.  Semantically, classifiers are
    functions from packets to sets of packets, similar to OpenFlow flow
    tables.
    """

    def __init__(self, new_rules=list()):
        import types, copy
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


    ### PARALLEL COMPOSITION
            
    def __add__(c1, c2):
        def _cross(r1,r2):
            from pyretic.core.language import drop
            intersection = r1.match.intersect(r2.match)
            if intersection != drop:
                # TODO (josh) logic for detecting when sets of actions can't be combined
                # e.g., [modify(dstip='10.0.0.1'),fwd(1)] + [modify(srcip='10.0.0.2'),fwd(2)]
                actions = r1.actions + r2.actions
                actions = filter(lambda a: a != drop,actions)
                if len(actions) == 0:
                    actions = [drop]
                return Rule(intersection, actions)
            else:
                return None

        # start with an empty set of rules for the output classifier
        c3 = Classifier()
        # JOSH - this check shouldn't be needed (I think)
        if c2 is None:
            return None
        # then cross all pairs of rules in the first and second classifiers
        for r1 in c1.rules:
            for r2 in c2.rules:
                crossed_r = _cross(r1,r2)
                if crossed_r:
                    c3.append(crossed_r)
        # then append all the rules in the first classifier
        for r1 in c1.rules:
            c3.append(r1)
        # followed by all the rules in the first classifier
        # (it doesn't matter whether c1 or c2 goes first)
        for r2 in c2.rules:
            c3.append(r2)

        # and optimize the classifier
        c3 = c3.optimize()
        return c3


    ### SEQUENTIAL COMPOSITION

    def __rshift__(c1, c2):
        from pyretic.core.language import match, modify, drop, identity, Controller, CountBucket, DerivedPolicy
        def _sequence_actions_classifier(acts, c2):
            def _sequence_action_classifier(act, c2):
                # given a test b and an action p, return a test
                # b' such that p >> b == b' >> p.
                def _commute_test(act, pkts):
                    while isinstance(act, DerivedPolicy):
                        act = act.policy
                    if act == identity:
                        return pkts
                    elif act == drop:
                        return drop
                    elif act == Controller or isinstance(act, CountBucket):
                        return identity
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
                        # TODO (cole) use compile error.
                        # TODO (cole) what actions are allowable?
                        raise TypeError

                # sequentially compose actions.  a1 must be a
                # single action.  Returns a list of actions.
                def _sequence_actions(a1, as2):
                    while isinstance(a1, DerivedPolicy):
                        a1 = a1.policy
                    # TODO: be uniform about returning copied or modified objects.
                    new_actions = []
                    if a1 == drop:
                        return [drop]
                    elif a1 == identity:
                        return as2
                    elif a1 == Controller or isinstance(a1, CountBucket):
                        return [a1]
                    elif isinstance(a1, modify):
                        for a2 in as2:
                            while isinstance(a2, DerivedPolicy):
                                a2 = a2.policy
                            new_a1 = modify(**a1.map.copy())
                            if a2 == drop:
                                new_actions.append(drop)
                            elif a2 == Controller or isinstance(a2, CountBucket): 
                                new_actions.append(a2)
                            elif a2 == identity:
                                new_actions.append(new_a1)
                            elif isinstance(a2, modify):
                                new_a1.map.update(a2.map)
                                new_actions.append(new_a1)
                            elif isinstance(a2, fwd):
                                new_a1.map['outport'] = a2.outport
                                new_actions.append(new_a1)
                            else:
                                raise TypeError
                        return new_actions
                    else:
                        raise TypeError
                # END _commute_test and _sequence_actions

                c3 = Classifier()
                for r2 in c2.rules:
                    pkts = _commute_test(act, r2.match)
                    if pkts == identity:
                        acts = _sequence_actions(act, r2.actions)
                        c3.append(Rule(identity, acts))
                        break
                    elif pkts == drop:
                        continue
                    else:
                        acts = _sequence_actions(act, r2.actions)
                        c3.append(Rule(pkts, acts))

                if len(c3) == 0:
                    c3.append(Rule(identity, [drop]))
                return c3

            # END _sequence_action_classifier

            empty_classifier = Classifier([Rule(identity, [drop])])

            if len(acts) > 0:
                acc = empty_classifier
                for act in acts:
                    acc = acc + _sequence_action_classifier(act, c2)
                return acc
            else:
                # Treat the empty list of actions as drop.
                return empty_classifier
        # END _sequence_actions_classifier


        # core __rshift__ logic begins here.
        # start with an empty set of rules for the output classifier
        # then for each rule in the first classifier (self)
        c3 = Classifier()
        for r1 in c1.rules:
            # sequence the actions in second classifier c2 w/ respect to r1
            c2_seqd = _sequence_actions_classifier(r1.actions, c2)

            # for each rule in the sequenced c2, 
            # intersect the rule's match with r1's match
            for r2 in c2_seqd.rules:
                r2.match = r2.match.intersect(r1.match)
            
            # filter out rules that cannot match any packet
            filtered_rules = deque([r2 for r2 in c2_seqd.rules if r2.match != drop])
            
            # and make a new Classifier, so we can optimize it
            c_tmp = Classifier(filtered_rules)
            c_tmp = c_tmp.optimize()

            # append the optimized rules
            c3.append(c_tmp)

        # when all rules in c1 and c2 have been crossed
        # optimize c3
        c3 = c3.optimize()
        return c3


    ### SHADOW OPTIMIZATION

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
