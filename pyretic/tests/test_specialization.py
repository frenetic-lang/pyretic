from pyretic.lib.path import *
from pyretic.lib.re import *
from pyretic.core.packet import *
from pyretic.core import util
import copy
import sys
import time

base_pkt = Packet({'raw': '\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x01\x81\x00\x00\x02\x08\x00E\x00\x00T\x00\x00@\x00@\x01&\xa6\n\x00\x00\x01\n\x00\x00\x03\x08\x00\xe4@\x11\x9e\x00\x01\xf77\x18S\xfd\x91\n\x00\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./01234567', 'switch': 2, 'inport': 1})
base_pkt = base_pkt.modifymany(get_packet_processor().unpack(base_pkt['raw']))

cg = re_tree_gen
fd = util.frozendict

def __continuation__(ast, trj, gt_list):
    if ast == path_epsilon():
        """ Only return True if the path is completely matched. """
        if len(trj) == 0:
            return (True, path_epsilon(), gt_list)
        else:
            return (False, None, [])
    else:
        """ Some more of the expression left to match, carry on. """
        return specialize(ast, trj, path_epsilon(), gt_list)

def __get_match_dict__(group_atom, pkt):
    """ Given a single group atom and a packet, specialize the grouping atom to
    a basic atom using the value of the groupby fields of the supplied packet.
    """
    groupby = group_atom.groupby
    match_dict = {f: pkt[f] for f in groupby}
    return match_dict

def __sp_group__(group_atom, pkt):
    pred = group_atom.policy
    return atom(pred & match(__get_match_dict__(group_atom,pkt)))

def __append_gtlist__(group_atom, pkt, gt_list, tail_gt_list):
    match_dict = fd(__get_match_dict__(group_atom, pkt))
    return gt_list + [match_dict] + tail_gt_list

def __sp_atom__(ast, c_ast, trj, sp_fun, gt, append_fun):
    if len(trj) == 0:
        return (False, None, [])
    else:
        first_pkt = trj[0]
        pred = ast.policy
        if len(pred.eval(first_pkt)) > 0:
            (matches, sp_ast, new_gt) = __continuation__(c_ast, trj[1:], gt)
            if matches:
                return (True,
                        sp_fun(ast, first_pkt) ^ sp_ast,
                        append_fun(ast, first_pkt, gt, new_gt))
            else:
                return (False, None, [])
        else:
            return (False, None, [])

def __sp_combinator__(ast_list, trj, c_ast, gt_list, map_fun, reduce_fun):
    assert len(ast_list) > 1
    results_list = map(lambda p: map_fun(p, trj, c_ast, gt_list), ast_list)
    return reduce(reduce_fun, results_list)

def specialize(ast, trj, c_ast, gt_list):
    """ Arguments:
    ast: AST to specialize
    trj: packet trajectory to specialize on
    c_ast: continuation AST (i.e., rest of the specialization work after ast)
    gt: group-tuples list (i.e., tuple to which the specialized query's
        counts are accounted to)

    Return value: (matched, sp_ast, new_gt_list), where
    matched: a boolean signifying successful match (True on match)
    sp_ast: specialized AST
    new_gt_list: new group-tuples list resulting from specialization
    """
    if isinstance(ast, path_empty):
        return (False, None, [])

    elif isinstance(ast, path_epsilon):
        return __continuation__(c_ast, trj, gt_list)

    elif isinstance(ast, atom):
        return __sp_atom__(ast, c_ast, trj, lambda x, y: x,
                           gt_list, lambda x, y, z, w: z + w)

    elif isinstance(ast, hook):
        return __sp_atom__(ast, c_ast, trj, __sp_group__,
                           gt_list, __append_gtlist__)

    elif isinstance(ast, path_concat):
        assert len(ast.paths) > 1
        cont_ast = reduce(lambda a, x: a ^ x, ast.paths[1:] + [c_ast])
        return specialize(ast.paths[0], trj, cont_ast, gt_list)

    elif isinstance(ast, path_alternate):
        def alter_reduce_fun(acc, res):
            (m, sp, gt) = acc
            (m_res, sp_res, gt_res) = res
            final_sp = None
            final_gt = None
            if m_res:
                if m:

                    if gt == gt_res:
                        final_sp = sp | sp_res
                        final_gt = gt
                    else:
                        """ Pick grouping from "first" left-to-right successful
                        parse. """
                        final_sp = sp
                        final_gt = gt
                else:
                    final_sp = sp_res
                    final_gt = gt_res
            else:
                final_sp = sp
                final_gt = gt
            return (m or m_res, final_sp, final_gt)

        return __sp_combinator__(ast.paths, trj, c_ast, gt_list,
                                 specialize, alter_reduce_fun)

    elif isinstance(ast, path_inters):
        def inters_reduce_fun(acc, res):
            (m, sp, gt) = acc
            (m_res, sp_res, gt_res) = res
            return (m and m_res and gt == gt_res,
                    sp & sp_res if sp and sp_res and gt == gt_res else None,
                    gt if gt == gt_res else [])

        return __sp_combinator__(ast.paths, trj, c_ast, gt_list,
                                 specialize, inters_reduce_fun)

    elif isinstance(ast, path_star):
        assert len(ast.paths) == 1
        # use the fact that p* == epsilon | (p ^ p*)
        p = ast.paths[0]
        (m,sp,gt) = specialize(path_epsilon(), trj, c_ast, gt_list)
        if m:
            return (m, sp, gt)
        else:
            return specialize(p, trj, ast ^ c_ast, gt_list)

    elif isinstance(ast, path_negate):
        assert len(ast.paths) == 1
        p = ast.paths[0]
        for k in range(0, len(trj)+1):
            (m_pre, sp_pre, _) = specialize(p, trj[0:k], path_epsilon(), [])
            (m_cont, sp_cont, gt_cont) = specialize(c_ast, trj[k:],
                                                    path_epsilon(), gt_list)
            if m_cont and not m_pre:
                return (True, ast ^ sp_cont, gt_cont)
        return (False, None, None)

    else:
        raise TypeError("Can't specialize unknown path type!")

def specialize_main(path_ast, trajectory):
    return specialize(path_ast, trajectory, path_epsilon(), [])

def test1():
    cg.clear()
    a = atom(match(srcip='10.0.0.1'))
    pkt = base_pkt.modifymany({'srcip': '10.0.0.1'})
    (m, sp, gt) = specialize_main(a, [pkt])
    assert m
    assert sp == atom(match(srcip='10.0.0.1'))
    assert gt == []

def test2():
    cg.clear()
    a = atom(match(srcip='10.0.0.1'))
    pkt = base_pkt.modifymany({'srcip': '10.0.0.2'})
    (m, sp, gt) = specialize_main(a, [pkt])
    assert not m
    assert not sp
    assert gt == []

def test3():
    cg.clear()
    a = hook(match(srcip='10.0.0.1'), groupby=['dstip'])
    pkt = base_pkt.modifymany({'srcip': '10.0.0.1', 'dstip': '10.0.0.2'})
    (m, sp, gt) = specialize_main(a, [pkt])
    assert m
    assert sp == atom(match(srcip='10.0.0.1', dstip='10.0.0.2'))
    assert gt == [fd({'dstip': '10.0.0.2'})]

def test4():
    cg.clear()
    a = atom(match(srcip='10.0.0.1'))
    b = hook(match(srcip='10.0.0.1'), groupby=['dstip'])
    pkt1 = base_pkt.modifymany({'srcip': '10.0.0.1'})
    pkt2 = base_pkt.modifymany({'srcip': '10.0.0.1', 'dstip': '10.0.0.2'})
    (m, sp, gt) = specialize_main(a ^ b, [pkt1, pkt2])
    assert m
    assert sp == (atom(match(srcip='10.0.0.1')) ^
                  atom(match(srcip='10.0.0.1', dstip='10.0.0.2')))
    assert gt == [fd({'dstip': '10.0.0.2'})]

def test5():
    cg.clear()
    a = atom(match(srcip='10.0.0.1'))
    b = hook(match(srcip='10.0.0.1'), groupby=['dstip', 'srcip'])
    c = hook(match(srcip='10.0.0.1'), groupby=['srcip'])
    pkt1 = base_pkt.modifymany({'srcip': '10.0.0.1'})
    pkt2 = base_pkt.modifymany({'srcip': '10.0.0.1', 'dstip': '10.0.0.2'})
    pkt3 = base_pkt.modifymany({'srcip': '10.0.0.1'})
    (m, sp, gt) = specialize_main(a ^ b ^ c, [pkt1, pkt2, pkt3])
    assert m
    assert sp == (atom(match(srcip='10.0.0.1')) ^
                  atom(match(srcip='10.0.0.1', dstip='10.0.0.2')) ^
                  atom(match(srcip='10.0.0.1')))
    assert gt == [fd({'dstip':'10.0.0.2', 'srcip':'10.0.0.1'}),
                  fd({'srcip':'10.0.0.1'})]

def test6():
    cg.clear()
    (ml, spl, gtl) = specialize_main(path_epsilon(), [base_pkt])
    (m, sp, gt)    = specialize_main(path_epsilon(), [])
    assert m
    assert not ml
    assert sp == path_epsilon()
    assert gt == []

def test7():
    cg.clear()
    a = atom(match(srcip='10.0.0.1'))
    b = hook(match(srcip='10.0.0.2'), groupby=['dstip'])
    c = hook(match(srcip='10.0.0.1'), groupby=['dstip'])
    d = atom(match(srcip='10.0.0.2'))
    e = atom(match(srcip='10.0.0.1'))
    pkt1 = base_pkt.modifymany({'srcip': '10.0.0.1', 'dstip': '10.0.0.2'})
    pkt2 = base_pkt.modifymany({'srcip': '10.0.0.2', 'dstip': '10.0.0.1'})
    pkt3 = base_pkt.modifymany({'srcip': '10.0.0.1'})
    (m, sp, gt) = specialize_main(((a ^ b) | (c ^ d)) ^ e, [pkt1, pkt2, pkt3])
    assert m
    f = atom(match(srcip='10.0.0.1', dstip='10.0.0.2'))
    g = atom(match(srcip='10.0.0.2', dstip='10.0.0.1'))
    """ If the specialization happened with respect to predicate matching alone,
    both a ^ g ^ e as well as f ^ d ^ e would match against the trajectory, and

    assert sp == (a ^ g ^ e) | (f ^ d ^ e)

    would work correctly. But with an additional constraint of picking the
    grouping corresponding to the leftmost successful parse in an alternation
    query, the result we choose to output instead is just

    a ^ g ^ e.
    """
    assert sp == (a ^ g ^ e)
    assert gt == [fd({'dstip':'10.0.0.1'})]

def test8():
    cg.clear()
    a = atom(match(srcip='10.0.0.1'))
    b = hook(match(srcip='10.0.0.2'), groupby=['dstip'])
    c = hook(match(srcip='10.0.0.2'), groupby=['dstip'])
    d = atom(match(srcip='10.0.0.1'))
    e = atom(match(srcip='10.0.0.1'))
    pkt1 = base_pkt.modifymany({'srcip': '10.0.0.1', 'dstip': '10.0.0.2'})
    pkt2 = base_pkt.modifymany({'srcip': '10.0.0.2', 'dstip': '10.0.0.1'})
    pkt3 = base_pkt.modifymany({'srcip': '10.0.0.1'})
    (m, sp, gt) = specialize_main(((a ^ b) | (c ^ d)) ^ e, [pkt1, pkt2, pkt3])
    b_sp = atom(match(srcip='10.0.0.2', dstip='10.0.0.1'))
    assert m
    # assert sp == (a ^ b_sp ^ e) | (c ^ d ^ e)
    assert sp == (a ^ b_sp ^ e)
    assert gt == [fd({'dstip': '10.0.0.1'})]

def test9():
    cg.clear()
    g = hook(match(srcip='10.0.0.1'), groupby=['switch'])
    a = atom(match(srcip='10.0.0.2'))
    pkt1 = base_pkt.modifymany({'srcip': '10.0.0.1', 'switch': 1})
    pkt2 = base_pkt.modifymany({'srcip': '10.0.0.1', 'switch': 2})
    pkt3 = base_pkt.modifymany({'srcip': '10.0.0.1', 'switch': 3})
    pkt4 = base_pkt.modifymany({'srcip': '10.0.0.1', 'switch': 4})
    pkt5 = base_pkt.modifymany({'srcip': '10.0.0.2'})
    (m, sp, gt) = specialize_main(+g ^ a, [pkt1, pkt2, pkt3, pkt4, pkt5])
    assert m
    g1 = atom(match(srcip='10.0.0.1', switch=1))
    g2 = atom(match(srcip='10.0.0.1', switch=2))
    g3 = atom(match(srcip='10.0.0.1', switch=3))
    g4 = atom(match(srcip='10.0.0.1', switch=4))
    assert sp == g1 ^ g2 ^ g3 ^ g4 ^ a
    assert gt == [fd({'switch': 1}), fd({'switch': 2}),
                  fd({'switch': 3}), fd({'switch': 4})]

def test10():
    cg.clear()
    g = hook(match(srcip='10.0.0.1'), groupby=['switch'])
    a = atom(match(srcip='10.0.0.2'))
    pkt = base_pkt.modifymany({'srcip': '10.0.0.2'})
    (m, sp, gt) = specialize_main(+g ^ a, [pkt])
    assert m
    assert sp == a
    assert gt == []

def test11():
    cg.clear()
    g = hook(match(srcip='10.0.0.1'), groupby=['switch'])
    a = atom(match(srcip='10.0.0.3'))
    pkt1 = base_pkt.modifymany({'srcip': '10.0.0.1', 'switch':1})
    pkt2 = base_pkt.modifymany({'srcip': '10.0.0.2'})
    (m, sp, gt) = specialize_main(+g ^ a, [pkt1, pkt2])
    assert not m
    assert not sp
    assert not gt

def test12():
    cg.clear()
    g = hook(match(srcip='10.0.0.1'), groupby=['switch'])
    a = atom(match(dstip='10.0.0.2'))
    b = atom(match(srcip='10.0.0.1'))
    h = hook(match(dstip='10.0.0.2'), groupby=['switch'])
    c = atom(match(srcip='10.0.0.3'))
    pkt1 = base_pkt.modifymany({'srcip': '10.0.0.1', 'dstip': '10.0.0.2',
                                'switch': 1})
    pkt2 = base_pkt.modifymany({'srcip': '10.0.0.1', 'dstip': '10.0.0.2',
                                'switch': 2})
    pkt3 = base_pkt.modifymany({'srcip': '10.0.0.1', 'dstip': '10.0.0.2',
                                'switch': 3})
    pkt4 = base_pkt.modifymany({'srcip': '10.0.0.1', 'dstip': '10.0.0.2',
                                'switch': 4})
    pkt5 = base_pkt.modifymany({'srcip': '10.0.0.3'})
    (m, sp, gt) = specialize_main(((+g ^ a) | (b ^ +h)) ^ c,
                                   [pkt1, pkt2, pkt3, pkt4, pkt5])
    assert m
    g1 = atom(match(srcip='10.0.0.1', switch=1))
    g2 = atom(match(srcip='10.0.0.1', switch=2))
    g3 = atom(match(srcip='10.0.0.1', switch=3))
    h2 = atom(match(dstip='10.0.0.2', switch=2))
    h3 = atom(match(dstip='10.0.0.2', switch=3))
    h4 = atom(match(dstip='10.0.0.2', switch=4))
    # assert sp == (g1 ^ g2 ^ g3 ^ a ^ c) | (b ^ h2 ^ h3 ^ h4 ^ c)
    assert sp == (g1 ^ g2 ^ g3 ^ a ^ c)
    assert gt == [fd({'switch': 1}), fd({'switch': 2}), fd({'switch': 3})]

def test13():
    cg.clear()
    g = hook(match(srcip='10.0.0.1'), groupby=['switch'])
    a = atom(match(dstip='10.0.0.4'))
    b = atom(match(srcip='10.0.0.1'))
    h = hook(match(dstip='10.0.0.2'), groupby=['switch'])
    c = atom(match(srcip='10.0.0.3'))
    pkt1 = base_pkt.modifymany({'srcip': '10.0.0.1', 'dstip': '10.0.0.2',
                                'switch': 1})
    pkt2 = base_pkt.modifymany({'srcip': '10.0.0.1', 'dstip': '10.0.0.2',
                                'switch': 2})
    pkt3 = base_pkt.modifymany({'srcip': '10.0.0.1', 'dstip': '10.0.0.2',
                                'switch': 3})
    pkt4 = base_pkt.modifymany({'srcip': '10.0.0.1', 'dstip': '10.0.0.2',
                                'switch': 4})
    pkt5 = base_pkt.modifymany({'srcip': '10.0.0.3'})
    (m, sp, gt) = specialize_main(((+g ^ a) | (b ^ +h)) ^ c,
                                   [pkt1, pkt2, pkt3, pkt4, pkt5])
    assert m
    h2 = atom(match(dstip='10.0.0.2', switch=2))
    h3 = atom(match(dstip='10.0.0.2', switch=3))
    h4 = atom(match(dstip='10.0.0.2', switch=4))
    # assert sp == (+g ^ a ^ c) | (b ^ h2 ^ h3 ^ h4 ^ c)
    assert sp == (b ^ h2 ^ h3 ^ h4 ^ c)
    assert gt == [fd({'switch':2}), fd({'switch':3}), fd({'switch':4})]

def test14():
    cg.clear()
    g = hook(match(srcip='10.0.0.1'), groupby=['switch'])
    a = atom(match(dstip='10.0.0.2'))
    b = atom(match(srcip='10.0.0.1'))
    h = hook(match(dstip='10.0.0.2'), groupby=['switch'])
    c = atom(match(srcip='10.0.0.3'))
    pkt1 = base_pkt.modifymany({'srcip': '10.0.0.1', 'dstip': '10.0.0.2',
                                'switch': 1})
    pkt2 = base_pkt.modifymany({'srcip': '10.0.0.1', 'dstip': '10.0.0.2',
                                'switch': 2})
    pkt3 = base_pkt.modifymany({'srcip': '10.0.0.1', 'dstip': '10.0.0.2',
                                'switch': 3})
    pkt4 = base_pkt.modifymany({'srcip': '10.0.0.1', 'dstip': '10.0.0.2',
                                'switch': 4})
    pkt5 = base_pkt.modifymany({'srcip': '10.0.0.3'})
    (m, sp, gt) = specialize_main(((+g ^ a) & (b ^ +h)) ^ c,
                                   [pkt1, pkt2, pkt3, pkt4, pkt5])
    # assert m
    assert not m
    g1 = atom(match(srcip='10.0.0.1', switch=1))
    g2 = atom(match(srcip='10.0.0.1', switch=2))
    g3 = atom(match(srcip='10.0.0.1', switch=3))
    h2 = atom(match(dstip='10.0.0.2', switch=2))
    h3 = atom(match(dstip='10.0.0.2', switch=3))
    h4 = atom(match(dstip='10.0.0.2', switch=4))
    # assert sp == (g1 ^ g2 ^ g3 ^ a ^ c) & (b ^ h2 ^ h3 ^ h4 ^ c)
    assert not sp
    assert gt == []

def test15():
    cg.clear()
    g = hook(match(srcip='10.0.0.1'), groupby=['switch'])
    a = atom(match(dstip='10.0.0.4'))
    b = atom(match(srcip='10.0.0.1'))
    h = hook(match(dstip='10.0.0.2'), groupby=['switch'])
    c = atom(match(srcip='10.0.0.3'))
    pkt1 = base_pkt.modifymany({'srcip': '10.0.0.1', 'dstip': '10.0.0.2',
                                'switch': 1})
    pkt2 = base_pkt.modifymany({'srcip': '10.0.0.1', 'dstip': '10.0.0.2',
                                'switch': 2})
    pkt3 = base_pkt.modifymany({'srcip': '10.0.0.1', 'dstip': '10.0.0.2',
                                'switch': 3})
    pkt4 = base_pkt.modifymany({'srcip': '10.0.0.1', 'dstip': '10.0.0.2',
                                'switch': 4})
    pkt5 = base_pkt.modifymany({'srcip': '10.0.0.3'})
    (m, sp, gt) = specialize_main(((+g ^ a) & (b ^ +h)) ^ c,
                                   [pkt1, pkt2, pkt3, pkt4, pkt5])
    assert not m
    assert not sp
    assert not gt

def test16():
    cg.clear()
    a = atom(match(srcip='10.0.0.1'))
    b = hook(match(srcip='10.0.0.2'), groupby=['dstip'])
    c = hook(match(srcip='10.0.0.2'), groupby=['dstip'])
    d = atom(match(srcip='10.0.0.1'))
    e = hook(match(srcip='10.0.0.1'), groupby=['dstip'])
    pkt1 = base_pkt.modifymany({'srcip': '10.0.0.1', 'dstip': '10.0.0.2'})
    pkt2 = base_pkt.modifymany({'srcip': '10.0.0.2', 'dstip': '10.0.0.1'})
    pkt3 = base_pkt.modifymany({'srcip': '10.0.0.1', 'dstip': '10.0.0.3'})
    (m, sp, gt) = specialize_main(((a ^ b) | (c ^ d)) ^ e, [pkt1, pkt2, pkt3])
    b_sp = atom(match(srcip='10.0.0.2', dstip='10.0.0.1'))
    e_sp = atom(match(srcip='10.0.0.1', dstip='10.0.0.3'))
    assert m
    # assert sp == (a ^ b_sp ^ e_sp) | (c ^ d ^ e)
    assert sp == (a ^ b_sp ^ e_sp)
    assert gt == [fd({'dstip':'10.0.0.1'}), fd({'dstip':'10.0.0.3'})]

def test17():
    cg.clear()
    g = hook(match(srcip='10.0.0.1'), groupby=['switch'])
    a = atom(match(srcip='10.0.0.2'))
    pkt1 = base_pkt.modifymany({'srcip': '10.0.0.1', 'switch': 1})
    pkt2 = base_pkt.modifymany({'srcip': '10.0.0.1', 'switch': 2})
    pkt3 = base_pkt.modifymany({'srcip': '10.0.0.1', 'switch': 3})
    pkt4 = base_pkt.modifymany({'srcip': '10.0.0.1', 'switch': 4})
    pkt5 = base_pkt.modifymany({'srcip': '10.0.0.2'})
    pkt6 = base_pkt
    t = [pkt1, pkt2, pkt3, pkt4, pkt5]
    tl = t + [pkt6]
    (m, sp, gt) = specialize_main(+g ^ a, t)
    (ml, spl, gtl) = specialize_main(+g ^ a, tl)
    assert m
    g1 = atom(match(srcip='10.0.0.1', switch=1))
    g2 = atom(match(srcip='10.0.0.1', switch=2))
    g3 = atom(match(srcip='10.0.0.1', switch=3))
    g4 = atom(match(srcip='10.0.0.1', switch=4))
    assert sp == g1 ^ g2 ^ g3 ^ g4 ^ a
    assert gt == [fd({'switch':1}), fd({'switch':2}),
                  fd({'switch':3}), fd({'switch':4})]
    assert not ml

def test18():
    cg.clear()
    (m, sp, gt) = specialize_main(+path_epsilon(), [])
    assert m
    assert sp == path_epsilon()
    assert gt == []

def test19():
    cg.clear()
    (m, sp, gt) = specialize_main(+path_epsilon(), [base_pkt])
    assert not m

def test20():
    cg.clear()
    a = atom(match(srcip='10.0.0.1'))
    b = atom(match(srcip='10.0.0.2'))
    p = +(path_epsilon() | a) ^ b
    pkt1 = base_pkt.modifymany({'srcip': '10.0.0.1'})
    pkt2 = base_pkt.modifymany({'srcip': '10.0.0.2'})
    (m, sp, gt) = specialize_main(p, [pkt1, pkt2])
    assert m
    assert sp == a ^ b
    assert gt == []

def test21():
    cg.clear()
    a = atom(match(srcip='10.0.0.1'))
    b = atom(match(srcip='10.0.0.2'))
    p = a ^ +(path_epsilon() | b)
    pkt1 = base_pkt.modifymany({'srcip': '10.0.0.1'})
    pkt2 = base_pkt.modifymany({'srcip': '10.0.0.2'})
    (m, sp, gt) = specialize_main(p, [pkt1, pkt2])
    assert m
    assert sp == a ^ b
    assert gt == []

def test22():
    cg.clear()
    a = atom(match(srcip='10.0.0.1'))
    b = atom(match(srcip='10.0.0.2'))
    c = atom(match(srcip='10.0.0.3'))
    e = path_epsilon()
    p1 = base_pkt.modifymany({'srcip':'10.0.0.1', 'dstip':'10.0.0.2'})
    p2 = base_pkt.modifymany({'srcip':'10.0.0.2', 'dstip':'10.0.0.1'})
    p3 = base_pkt.modifymany({'srcip':'10.0.0.3'})

    q1 = path_negate(a) ^ b
    (m1, sp1, _) = specialize_main(q1, [p1, p2])
    assert not m1
    (m2, sp2, _) = specialize_main(q1, [p2])
    assert m2
    assert sp2 == q1
    (m3, sp3, _) = specialize_main(q1, [p3, p3, p1, p2])
    assert m3
    assert sp3 == q1

    q2 = path_negate(e)
    (m4, sp4, _) = specialize_main(q2, [p1, p3])
    assert m4
    assert sp4 == q2
    (m5, sp5, _) = specialize_main(q2, [])
    assert not m5

    q3 = ~(a ^ c) ^ b
    (m6, sp6, _) = specialize_main(q3, [p1, p3, p2])
    assert not m6
    (m7, sp7, _) = specialize_main(q3, [p2])
    assert m7
    assert sp7 == q3
    (m8, sp8, _) = specialize_main(q3, [p1, p2])
    assert m8
    assert sp8 == q3

    q4 = a ^ path_negate(b) ^ c
    (m9, sp9, _) = specialize_main(q4, [p1, p2, p2, p3])
    assert m9
    assert sp9 == q4
    (m10, sp10, _) = specialize_main(q4, [p1, p2, p3])
    assert not m10
    (m11, sp11, _) = specialize_main(q4, [p1, p3])
    assert m11
    assert sp11 == q4

def test23():
    cg.clear()
    a = atom(match(srcip='10.0.0.1'))
    a_h = hook(match(srcip='10.0.0.1'), groupby=['dstip'])
    a_sp = atom(match(srcip='10.0.0.1', dstip='10.0.0.2'))
    b = atom(match(srcip='10.0.0.2'))
    b_h = hook(match(srcip='10.0.0.2'), groupby=['dstip'])
    b_sp = atom(match(srcip='10.0.0.2', dstip='10.0.0.1'))
    c = atom(match(srcip='10.0.0.3'))
    e = path_epsilon()
    p1 = base_pkt.modifymany({'srcip':'10.0.0.1', 'dstip':'10.0.0.2'})
    p2 = base_pkt.modifymany({'srcip':'10.0.0.2', 'dstip':'10.0.0.1'})
    p3 = base_pkt.modifymany({'srcip':'10.0.0.3'})

    q1 = ~(a_h ^ c) ^ b
    (m1, sp1, g1) = specialize_main(q1, [p2])
    assert m1
    assert sp1 == q1
    assert g1 == []
    (m2, sp2, _) = specialize_main(q1, [p1, p3, p2])
    assert not m2
    (m3, sp3, _) = specialize_main(q1, [p1, p3])
    assert not m3

    q2 = ~(a_h ^ c) ^ b_h
    (m4, sp4, g4) = specialize_main(q2, [p1, p2])
    assert m4
    assert sp4 == ~(a_h ^ c) ^ b_sp
    assert g4 == [fd({'dstip':'10.0.0.1'})]

    q3 = ~(a ^ c) ^ b_h
    (m5, sp5, g5) = specialize_main(q3, [p3, p3, p3, p2])
    assert m5
    assert sp5 == ~(a ^ c) ^ b_sp
    assert g5 == [fd({'dstip':'10.0.0.1'})]

    q4 = a_h ^ path_negate(b) ^ b_h
    (m6, sp6, g6) = specialize_main(q4, [p1, p2, p2, p2])
    assert m6
    assert sp6 == a_sp ^ path_negate(b) ^ b_sp
    assert g6 == [fd({'dstip':'10.0.0.2'}), fd({'dstip':'10.0.0.1'})]
    (m7, sp7, _) = specialize_main(q4, [p1, p2, p3])
    assert not m7
    (m8, sp8, g8) = specialize_main(q4, [p1, p2])
    assert m8
    assert sp8 == a_sp ^ path_negate(b) ^ b_sp
    assert g8 == [fd({'dstip':'10.0.0.2'}), fd({'dstip':'10.0.0.1'})]

if __name__ == "__main__":
    test1()
    test2()
    test3()
    test4()
    test5()
    test6()
    test7()
    test8()
    test9()
    test10()
    test11()
    test12()
    test13()
    test14()
    test15()
    test16()
    test17()
    test18()
    """
    There is a known bug which is exposed through the tests commented out
    below. If path regular expression r contains a subexpression s* where s
    itself can match an empty string (i.e., s is nullable), then the
    specialization algorithm loops infinitely.
    """
    #print "Infinite loop cases follow:"
    #time.sleep(3)
    #test19()
    #test20()
    #test21()
    test22()
    test23()
