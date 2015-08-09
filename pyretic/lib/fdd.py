from pyretic.core.language import *
#########################################
#####             FDD               #####
#########################################

class FDD(object):

    def level_repr(self, acc, shift):
        raise NotImplementedError

    def __str__(self):
        lrepr = self.level_repr([], '')
        return '\n'.join(lrepr) + "\n\n-------------------\n"

    def __hash__(self):
        return hash(str(self))

class Node(FDD):
    def __init__(self, test, lchild, rchild):
        assert isinstance(test, tuple) and len(test) == 2
        assert issubclass(lchild.__class__, FDD)
        assert issubclass(rchild.__class__, FDD)
        super(Node, self).__init__()
        self.test = test
        self.lchild = lchild
        self.rchild = rchild
    
    def level_repr(self, acc, shift):
        acc.append(shift + self.test.__repr__())
        acc = (self.lchild.level_repr(acc, shift + '\t'))
        acc = (self.rchild.level_repr(acc, shift + '\t')) 
        return acc

    def __eq__(self, other):
        return (type(self) == type(other) and
                self.test == other.test and
                self.lchild == other.lchild and
                self.rchild == other.rchild)

    def __repr__(self):
        return self.test.__repr__()

class Leaf(FDD):

    def __init__(self, pred_set = frozenset(), path = frozenset()):
        super(Leaf, self).__init__()
        self.pred_set = pred_set
        self.path = path
    
    def level_repr(self, acc, shift):
        acc.append(shift + self.__repr__())
        return acc


    def is_drop(self):
        return len(self.act_set) == 0

    def __add__(self, other):
        new_pred_set = self.pred_set | other.pred_set
        new_path = self.path | other.path
        return Leaf(new_pred_set, new_path)
       
    def __rshift__(self, other):
        new_pred_set = self.pred_set & other.pred_set
        new_path = self.path | other.path
        return Leaf(new_pred_set, new_path)

    def neg(self, pred):
        assert len(self.pred_set) < 2
        if len(self.pred_set) == 0:
            return Leaf(set([pred])) 
        else:
            return Leaf()

    
    def __eq__(self, other):
        res = (isinstance(other, Leaf) and self.pred_set == other.pred_set)
        return res 

    def __hash__(self):
        return hash(self.pred_set)

    def __repr__(self):

        res = '{'
        res += ','.join([str(x) for x in self.pred_set])
        res += '}'
        #res += '{'
        #res += ','.join([str(x) for x in self.path])
        #res += "}"
        return res

#########################################
#####         Translation           #####
#########################################

class FDDTranslator(object):
    
    @classmethod
    def merge(cls, d1, d2, union):
        if isinstance(d1, Node):
            t1 = d1.test
            if isinstance(d2, Node):
                t2 = d2.test
                if t1 == t2:
                    lchild = cls.merge(d1.lchild, d2.lchild, union)
                    rchild = cls.merge(d1.rchild, d2.rchild, union)
                    test = t1
                else:
                    if t1 > t2:
                        d1, d2 = d2, d1
                        t1, t2 = t2, t1
                    
                    (f1, v1) = t1
                    (f2, v2) = t2
                    if f1 == f2 and v1 != v2:
                        lchild = d1.lchild
                        rchild = cls.merge(d1.rchild, d2, union)
                        test = t1
                    else:
                        lchild = cls.merge(d1.lchild, d2, union)
                        rchild = cls.merge(d1.rchild, d2, union)
                        test = t1
                         
            elif isinstance(d2, Leaf):
                lchild = cls.merge(d1.lchild, d2, union)
                rchild = cls.merge(d1.rchild, d2, union)
                test = t1
            else:
                raise TypeError
        elif isinstance(d1, Leaf):
            if isinstance(d2, Node):
                lchild = cls.merge(d2.lchild, d1, union)
                rchild = cls.merge(d2.rchild, d1, union)
                test = d2.test

            elif isinstance(d2, Leaf):
                if union:
                    return d1 + d2
                else:
                    return d1 >> d2
            else:
                raise TypeError
        else: 
            raise TypeError
        
        if rchild == lchild:
            return lchild
        else:
            return Node(test, lchild, rchild)

    @classmethod
    def neg(cls, d, pred):
        if isinstance(d, Node):
            lchild = cls.neg(d.lchild, pred)
            rchild = cls.neg(d.rchild, pred)
            return Node(d.test, lchild, rchild)
                    
        elif isinstance(d, Leaf):
            return d.neg(pred)
        else:
            raise TypeError


    @classmethod
    def get_id(cls, pred, path = set()):
        return Leaf(frozenset([pred]), path)

    @classmethod
    def get_drop(cls, path = set()):
        return Leaf(frozenset(), path)

    @classmethod 
    def translate(cls, pol, pred):
        if pol == identity:
            return cls.get_id(pred)            
        if pol == drop:
            return cls.get_drop()

        typ = type(pol)
        if typ == match:
            fmap = pol.map.items()
            (f, v) = fmap[0]
            res = Node((f, v), cls.get_id(pred), cls.get_drop())

            for (f, v) in fmap[1:]:
                new_match = Node((f, v), cls.get_id(pred), cls.get_drop())
                res = cls.merge(res, new_match, False)
            return res

        elif typ == negate:
            inner_pol = cls.translate(pol.policies[0], pred)
            return cls.neg(inner_pol, pred)
       
        elif issubclass(typ, union):
            res = cls.translate(pol.policies[0], pred)            
            for p in pol.policies[1:]:
                p_fdd = cls.translate(p, pred)
                res = cls.merge(res, p_fdd, True)
            return res
        
        if issubclass(typ, intersection):
            res = cls.translate(pol.policies[0], pred)
            for p in pol.policies[1:]:
                p_fdd = cls.translate(p, pred)
                res = cls.merge(res, p_fdd, False)
            return res

        raise TypeError

    @classmethod
    def assign_path(cls, fdd, path):
        if isinstance(fdd, Node):
            true_test = fdd.test + (True,)
            true_path = path | set([true_test])
            cls.assign_path(fdd.lchild, true_path)
            false_test = fdd.test + (False,)
            false_path = path | set([false_test])
            cls.assign_path(fdd.rchild, false_path)
        elif isinstance(fdd, Leaf):
            fdd.path = path
        else:
            raise TypeError

#########################################
#####             Tests             #####
#########################################

def pred_trans_test():
    pred = match(switch = 2)
    fdd = FDDTranslator.translate(pred, 1)
    FDDTranslator.assign_path(fdd, set())
    print fdd

    pred = ~match(switch = 2)
    fdd = FDDTranslator.translate(pred, 2)
    FDDTranslator.assign_path(fdd, set())
    print fdd

    pred = match(switch = 2) | (~match(inport = 3) & match(outport = 2))
    fdd = FDDTranslator.translate(pred, 3)
    FDDTranslator.assign_path(fdd, set())
    print fdd

    pred = match(switch = 2, inport = 3) | (~match(switch = 3, outport = 4)) | match(inport = 5)
    fdd = FDDTranslator.translate(pred, 4)
    FDDTranslator.assign_path(fdd, set())
    print fdd

def merge_test():   
    base = match(switch = 2, inport = 3) | (~match(switch = 3, outport = 4)) | match(inport = 5)
    base_fdd = FDDTranslator.translate(base, 4)
    FDDTranslator.assign_path(base_fdd, set())
    print base_fdd

    pred = match(srcip = "10.0.0.1")
    fdd = FDDTranslator.translate(pred, 3)
    FDDTranslator.assign_path(fdd, set())
    print fdd

    res = FDDTranslator.merge(fdd, base_fdd, True)
    print res
if __name__ == "__main__":
    merge_test()
