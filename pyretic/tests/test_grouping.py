from pyretic.lib.corelib import *
from pyretic.lib.path import *

class grouptest(object):

    @classmethod
    def list_isinstance(cls, l, typ):
        return reduce(lambda acc, x: acc and isinstance(item, typ), l, True)

    @classmethod
    def groupby_collect(cls, acc, ast):
        assert isinstance(ast, path)
        if isinstance(ast, in_out_group):
            return acc | set([ast])
        else:
            return acc

    @classmethod
    def map_substitute_groupby(cls, vals):
        def actual_mapper(ast):
            assert isinstance(ast, path)
            if isinstance(ast, in_out_group):
                try:
                    val = vals[id(ast)]
                except KeyError:
                    raise RuntimeError("Substitution vals has no "
                                       "substitution for current AST: %s" % repr(ast))
                return vals[id(ast)]
            else:
                return ast
        return actual_mapper

    @classmethod
    def flist_vlist_combos(cls, flist, fvlist):
        """Given a field list `flist`, and a dictionary `fvlist` of field -> [list
        values], generate all combinations of values of the fields as a list of
        lists, where each internal list is the list of values of fields in
        `flist` in the same order as `flist`.
        """
        if len(flist) == 0:
            return []
        else:
            res = []
            for first_val in fvlist[flist[0]]:
                tail_vals = cls.flist_vlist_combos(flist[1:], fvlist)
                if tail_vals:
                    for tail_val in tail_vals:
                        res.append([first_val] + tail_val)
                else:
                    res.append([first_val])
            return res

    @classmethod
    def gen_groupby_substitutes(cls, gatom, fvlist):
        """Given a group atom, generate all possible field combinations this
        grouping atom can take, as a list of dictionaries. Also ensure that the
        field combination results in non-empty matches when substituted into the
        in_out_group.
        """
        assert isinstance(gatom, in_out_group)
        ingby, outgby = gatom.in_groupby, gatom.out_groupby
        inlist = cls.flist_vlist_combos(ingby, fvlist)
        outlist = cls.flist_vlist_combos(outgby, fvlist)
        res = []
        for inl in inlist:
            for outl in outlist:
                res.append(gatom.substitute(
                    {f:v for (f,v) in zip(ingby,  inl)},
                    {f:v for (f,v) in zip(outgby, outl)}))
        return filter(lambda x: not x is None, res)

    @classmethod
    def gatom_to_ioatom_combos(cls, galist, fvlist):
        assert list_isinstance(galist, in_out_group)
        ga_subst_map = {id(gatom): cls.gen_groupby_substitutes(gatom, fvlist)
                        for gatom in galist}
        id_sorted_gatoms = sorted(map(id, galist))
        combos = cls.flist_vlist_combos(id_sorted_gatoms,
                                        ga_subst_map)
        res = []
        for atom_combo in combos:
            res.append({f:v for (f,v) in zip(id_sorted_gatoms, atom_combo)})
        return res

    @classmethod
    def expand_groupby(cls, path_pol, sw_ports):
        """ Statically substitute groupby atoms in queries by query predicates
        that have 'complete' values, e.g.,:

        in_group(match(port=2), ['switch'])
        -> [in_atom(match(switch=1, port=2)),
            in_atom(match(switch=2, port=2)),
            ...
           ]

        Currently, only the switch and port fields are statically replaced in
        grouping atoms, as it's too expensive to pre-compute all destination
        IPs, etc. Instead, applications should use a sampling bucket to collect
        per-header-aggregate statistics.
        """
        return None

if __name__ == "__main__":
    fvlist = {'switch': range(1,4), 'port': range(1,5)}
    gt = grouptest
    print gt.flist_vlist_combos(['switch'], fvlist)
    print gt.flist_vlist_combos(['switch', 'port'], fvlist)
    print gt.flist_vlist_combos(['port', 'switch'], fvlist)
    print gt.flist_vlist_combos(['port', 'switch', 'switch'], fvlist)

    print '****'
    g1 = in_out_group(match(switch=2), identity, ['switch'], ['port'])
    g2 = in_out_group(match(port=3), match(port=1), ['switch'],
                      ['switch','port'])
    id_to_atoms_combos = gt.gatom_to_ioatom_combos([g1, g2], fvlist)
    print "First one:"
    print id_to_atoms_combos[0]
    print "end of first one"
    p = g1 ^ (in_atom(match(srcip='10.0.0.1')) ** g2) ^ g1
    gatm_list = path_policy_utils.path_ast_fold(p, gt.groupby_collect, set())
    print gatm_list
    res = []
    for combo in id_to_atoms_combos:
        res.append(path_policy_utils.path_ast_map(p,
                    gt.map_substitute_groupby(combo)))

    print res[0]
    print len(res), "queries"
    print "Done"
