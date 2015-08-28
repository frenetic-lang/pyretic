from pyretic.lib.corelib import *
from pyretic.lib.path import *


if __name__ == "__main__":
    fvlist = {'switch': range(1,4), 'port': range(1,5)}
    gt = path_grouping
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

    print '======='
    res = gt.expand_groupby(p, fvlist)
    print res[0]
    print len(res), "queries"
    print "Done"
