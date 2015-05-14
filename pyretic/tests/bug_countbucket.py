from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.core.classifier import *
from pyretic.core.classifier import _cross_rules, _cross_act

ip3 = IP('10.0.0.3')
ip4 = IP('10.0.0.4')
ip5 = IP('10.0.0.5')
ip6 = IP('10.0.0.6')

"""There's a problem in compiling down sequential composition of a policy which
has some rule with a parallel action with some countbucket. Consider the example
below:

-- c1 is a classifier which generates a rule whose actions include a
   modification and a countbucket.

-- The output classifier of c1 >> x for some x depends on which rule appeared
   first in the classifier of x, even though the different rules (in x) may be
   disjoint.

-- Check the difference between the classifiers of c1 >> c2 and c1 >> c3, where
   packets from one switch or the other may be dropped depending on the exact
   way in which the policy e (or f) was written, although the two policies
   are functionally equivalent.

"""

if __name__ == "__main__":
    x = match(dstip=ip3) >> modify(dstip=ip4)
    y = match(dstip=ip3) >> modify(dstip=ip4) >> CountBucket()
    # y = match(dstip=ip3) >> modify(dstip=ip4) >> Controller
    e1 = match(switch=1, outport=2)
    e2 = match(switch=2, outport=2)
    e = (e1 | e2) >> modify(dstip=ip5)
    f = (e2 | e1) >> modify(dstip=ip5)

    c1 = (x+y).compile()
    c2 = e.compile()
    c3 = f.compile()

    print "*** First classifier:"
    print c1
    print

    print "*** Second classifier:"
    print c2
    print

    print "*** Third classifier:"
    print c3
    print

    print "*** Result of sequential composition c1 >> c2"
    print Classifier.__rshift__(c1, c2)
    print

    print "*** Result of sequential composition c1 >> c3"
    print Classifier.__rshift__(c1, c3)
    print

    """ The problem arises because of the parallel composition among multiple
    sequential compositions resulting from just two rules. consider r1 and r2
    below:
    """

    r1 = Rule(match(dstip=ip3), set([modify(dstip=ip4), CountBucket()]))
    r2 = Rule(match(switch=2,outport=2), set([modify(dstip=ip5)]))
    r3 = Rule(match(switch=1,outport=2), set([modify(dstip=ip5)]))

    """This results in a parallel composition between the two policies
    corresponding to

    (match(ip3), modify(ip4)) >> (match(sw=2,op=2), modify(ip5))
    +
    (match(ip3), countbucket) >> (match(sw=2,op=2), modify(ip5))

    which is good for the compilation of r1 >> r2. But the trouble is that if
    there's another rule r3 in the second classifier such that match(ip3) covers
    the match in r3, just appending the classifiers from crossing r1,r2 and
    r1,r3 would be incorrect!

    In this case the parallel composition of (r1 >> r2) completely covers the
    rules resulting from r1 >> r3, because the modify action isn't performed on
    those. So, one can't just append the classifiers from r1 >> r2 and r1 >> r3.
    """
    print "*** crossing action modify of r1 with r2"
    print _cross_act(r1, modify(dstip=ip4), r2)
    print

    print "*** crossing action CountBucket of r1 with r2"
    print _cross_act(r1, CountBucket(), r2)
    print

    print "*** crossing r1 with r2"
    print _cross_rules(r1, r2)
