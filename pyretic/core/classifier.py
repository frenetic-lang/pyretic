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

    def __init__(self, new_rules=[]):
        import types
        if isinstance(new_rules, types.GeneratorType):
            self.rules = [r for r in new_rules]
        elif isinstance(new_rules,list):
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

    def __add__(self,c2):
        from pyretic.core.language import drop
        c1 = self
        if c2 is None:
            return None
        c = Classifier([])
        # TODO (cole): make classifiers iterable
        for r1 in c1.rules:
            for r2 in c2.rules:
                intersection = r1.match.intersect(r2.match)
                if intersection != drop:
                    # TODO (josh) logic for detecting when sets of actions can't be combined
                    # e.g., [modify(dstip='10.0.0.1'),fwd(1)] + [modify(srcip='10.0.0.2'),fwd(2)]
                    actions = r1.actions + r2.actions
                    actions = filter(lambda a: a != drop,actions)
                    if len(actions) == 0:
                        actions = [drop]
                    c.rules.append(Rule(intersection, actions))
        return c.optimize()

    # Helper function for rshift: given a test b and an action p, return a test
    # b' such that p >> b == b' >> p.
    def _commute_test(self, act, pkts):
        from pyretic.core.language import modify, drop, identity, Controller, CountBucket, DerivedPolicy, match
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

    # Helper function for rshift: sequentially compose actions.  a1 must be a
    # single action.  Returns a list of actions.
    def _sequence_actions(self, a1, as2):
        from pyretic.core.language import modify, drop, identity, Controller, CountBucket, DerivedPolicy
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

    # Returns a classifier.
    def _sequence_action_classifier(self, act, c):
        from pyretic.core.language import drop, identity
        # TODO (cole): make classifiers easier to use w.r.t. adding/removing
        # rules.
        if len(c.rules) == 0:
            return Classifier([Rule(identity, [drop])])
        new_rules = []
        for rule in c.rules:
            pkts = self._commute_test(act, rule.match)
            if pkts == identity:
                acts = self._sequence_actions(act, rule.actions)
                new_rules += [Rule(identity, acts)]
                break
            elif pkts == drop:
                continue
            else:
                acts = self._sequence_actions(act, rule.actions)
                new_rules += [Rule(pkts, acts)]
        if new_rules == []:
            return Classifier([Rule(identity, [drop])])
        else:
            return Classifier(new_rules)
                
    def _sequence_actions_classifier(self, acts, c):
        from pyretic.core.language import drop, identity
        empty_classifier = Classifier([Rule(identity, [drop])])
        if acts == []:
            # Treat the empty list of actions as drop.
            return empty_classifier
        acc = empty_classifier
        for act in acts:
            acc = acc + self._sequence_action_classifier(act, c)
        return acc

    def _sequence_rule_classifier(self, r, c):
        from pyretic.core.language import drop
        c2 = self._sequence_actions_classifier(r.actions, c)
        for rule in c2.rules:
            rule.match = rule.match.intersect(r.match)
        c2.rules = [r2 for r2 in c2.rules if r2.match != drop]
        return c2.optimize()

    def __rshift__(self, c2):
        new_rules = []
        for rule in self.rules:
            c3 = self._sequence_rule_classifier(rule, c2)
            new_rules = new_rules + c3.rules
        rv = Classifier(new_rules)
        return rv.optimize()

    def optimize(self):
        return self.remove_shadowed_cover_single()

    def remove_shadowed_exact_single(self):
        # Eliminate every rule exactly matched by some higher priority rule
        opt_c = Classifier([])
        for r in self.rules:
            if not reduce(lambda acc, new_r: acc or
                          new_r.match == r.match,
                          opt_c.rules,
                          False):
                opt_c.rules.append(r)
        return opt_c

    def remove_shadowed_cover_single(self):
        # Eliminate every rule completely covered by some higher priority rule
        opt_c = Classifier([])
        for r in self.rules:
            if not reduce(lambda acc, new_r: acc or
                          new_r.match.covers(r.match),
                          opt_c.rules,
                          False):
                opt_c.rules.append(r)
        return opt_c

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
