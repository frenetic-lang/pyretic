from pyretic.lib.path import *
from pyretic.lib.re import *
from pyretic.core.packet import *
import copy
import sys
import time

base_pkt = Packet({'raw': '\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x01\x81\x00\x00\x02\x08\x00E\x00\x00T\x00\x00@\x00@\x01&\xa6\n\x00\x00\x01\n\x00\x00\x03\x08\x00\xe4@\x11\x9e\x00\x01\xf77\x18S\xfd\x91\n\x00\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./01234567', 'switch': 2, 'inport': 1})
base_pkt = base_pkt.modifymany(get_packet_processor().unpack(base_pkt['raw']))

cg = re_tree_gen

def __continuation__(ast, trj):
    if ast == path_epsilon():
        """ Only return True if the path is completely matched. """
        if len(trj) == 0:
            return (True, path_epsilon(), trj)
        else:
            return (False, None, None)
    else:
        """ Some more of the expression left to match, carry on. """
        return specialize(ast, trj, path_epsilon())

def __sp_group__(group_atom, pkt):
    """ Given a single group atom and a packet, specialize the grouping atom to
    a basic atom using the value of the groupby fields of the supplied packet.
    """
    groupby = group_atom.groupby
    pred = group_atom.policy
    match_dict = {f: pkt[f] for f in groupby}
    return atom(pred & match(match_dict))

def __sp_atom__(ast, c_ast, trj, sp_fun):
    if len(trj) == 0:
        return (False, None, [])
    else:
        first_pkt = trj[0]
        pred = ast.policy
        if len(pred.eval(first_pkt)) > 0:
            (matches, sp_ast, rem_trj) = __continuation__(c_ast, trj[1:])
            if matches:
                return (True, sp_fun(ast, first_pkt) ^ sp_ast, rem_trj)
            else:
                return (False, None, [])
        else:
            return (False, None, [])

def __sp_combinator__(ast_list, trj, c_ast, map_fun, reduce_fun):
    assert len(ast_list) > 1
    results_list = map(lambda p: map_fun(p, trj, c_ast), ast_list)
    return reduce(reduce_fun, results_list)

def specialize(ast, trj, c_ast):
    if isinstance(ast, path_empty):
        return (False, None, None)

    elif isinstance(ast, path_epsilon):
        return __continuation__(c_ast, trj)

    elif isinstance(ast, atom):
        return __sp_atom__(ast, c_ast, trj, lambda x, y: x)

    elif isinstance(ast, hook):
        return __sp_atom__(ast, c_ast, trj, __sp_group__)

    elif isinstance(ast, path_concat):
        assert len(ast.paths) > 1
        cont_ast = reduce(lambda a, x: a ^ x, ast.paths[1:] + [c_ast])
        return specialize(ast.paths[0], trj, cont_ast)

    elif isinstance(ast, path_alternate):
        def alter_reduce_fun(acc, res):
            (m, sp, rem_trj) = acc
            (m_res, sp_res, rem_trj_res) = res
            final_sp = None
            if m and m_res:
                final_sp = sp | sp_res
            elif m:
                final_sp = sp
            elif m_res:
                final_sp = sp_res
            else:
                final_sp = None
            return (m or m_res, final_sp, rem_trj)

        return __sp_combinator__(ast.paths, trj, c_ast,
                                 specialize, alter_reduce_fun)

    elif isinstance(ast, path_inters):
        def inters_reduce_fun(acc, res):
            (m, sp, rem_trj) = acc
            (m_res, sp_res, rem_trj_res) = res
            return (m and m_res and rem_trj == rem_trj_res,
                    sp & sp_res if sp and sp_res else None,
                    rem_trj)

        return __sp_combinator__(ast.paths, trj, c_ast,
                                 specialize, inters_reduce_fun)

    elif isinstance(ast, path_star):
        assert len(ast.paths) == 1
        # use the fact that p* == epsilon | (p ^ p*)
        p = ast.paths[0]
        (m,sp,rem_trj) = specialize(path_epsilon(), trj, c_ast)
        if m:
            return (m, sp, rem_trj)
        else:
            return specialize(p, trj, ast ^ c_ast)

    elif isinstance(ast, path_negate):
        assert len(ast.paths) == 1
        p = ast.paths[0]
        """ Whenever trj != [], do part by part match. """
        for k in range(0, len(trj)+1):
            (m_pre, sp_pre, _) = specialize(p, trj[0:k], path_epsilon())
            (m_cont, sp_cont, trj_cont) = specialize(c_ast, trj[k:],
                                                     path_epsilon())
            if m_cont and not m_pre:
                return (True, ast ^ sp_cont, trj_cont)
        return (False, None, None)

    else:
        raise TypeError("Can't specialize unknown path type!")

def specialize_main(path_ast, trajectory):
    return specialize(path_ast, trajectory, path_epsilon())

def test1():
    cg.clear()
    a = atom(match(srcip='10.0.0.1'))
    pkt = base_pkt.modifymany({'srcip': '10.0.0.1'})
    (m, sp, trj) = specialize_main(a, [pkt])
    assert m
    assert sp == atom(match(srcip='10.0.0.1'))
    assert trj == []

def test2():
    cg.clear()
    a = atom(match(srcip='10.0.0.1'))
    pkt = base_pkt.modifymany({'srcip': '10.0.0.2'})
    (m, sp, trj) = specialize_main(a, [pkt])
    assert not m
    assert not sp
    assert trj == []

def test3():
    cg.clear()
    a = hook(match(srcip='10.0.0.1'), groupby=['dstip'])
    pkt = base_pkt.modifymany({'srcip': '10.0.0.1', 'dstip': '10.0.0.2'})
    (m, sp, trj) = specialize_main(a, [pkt])
    assert m
    assert sp == atom(match(srcip='10.0.0.1', dstip='10.0.0.2'))
    assert trj == []

def test4():
    cg.clear()
    a = atom(match(srcip='10.0.0.1'))
    b = hook(match(srcip='10.0.0.1'), groupby=['dstip'])
    pkt1 = base_pkt.modifymany({'srcip': '10.0.0.1'})
    pkt2 = base_pkt.modifymany({'srcip': '10.0.0.1', 'dstip': '10.0.0.2'})
    (m, sp, trj) = specialize_main(a ^ b, [pkt1, pkt2])
    assert m
    assert sp == (atom(match(srcip='10.0.0.1')) ^
                  atom(match(srcip='10.0.0.1', dstip='10.0.0.2')))
    assert trj == []

def test5():
    cg.clear()
    a = atom(match(srcip='10.0.0.1'))
    b = hook(match(srcip='10.0.0.1'), groupby=['dstip'])
    c = hook(match(srcip='10.0.0.1'), groupby=['srcip'])
    pkt1 = base_pkt.modifymany({'srcip': '10.0.0.1'})
    pkt2 = base_pkt.modifymany({'srcip': '10.0.0.1', 'dstip': '10.0.0.2'})
    pkt3 = base_pkt.modifymany({'srcip': '10.0.0.1'})
    (m, sp, trj) = specialize_main(a ^ b ^ c, [pkt1, pkt2, pkt3])
    assert m
    assert sp == (atom(match(srcip='10.0.0.1')) ^
                  atom(match(srcip='10.0.0.1', dstip='10.0.0.2')) ^
                  atom(match(srcip='10.0.0.1')))
    assert trj == []

def test6():
    cg.clear()
    (ml, spl, trjl) = specialize_main(path_epsilon(), [base_pkt])
    (m, sp, trj)    = specialize_main(path_epsilon(), [])
    assert m
    assert not ml
    assert sp == path_epsilon()
    assert trj == []

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
    (m, sp, trj) = specialize_main(((a ^ b) | (c ^ d)) ^ e, [pkt1, pkt2, pkt3])
    assert m
    f = atom(match(srcip='10.0.0.1', dstip='10.0.0.2'))
    g = atom(match(srcip='10.0.0.2', dstip='10.0.0.1'))
    assert sp == (a ^ g ^ e) | (f ^ d ^ e)
    assert trj == []

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
    (m, sp, trj) = specialize_main(((a ^ b) | (c ^ d)) ^ e, [pkt1, pkt2, pkt3])
    b_sp = atom(match(srcip='10.0.0.2', dstip='10.0.0.1'))
    assert m
    # assert sp == (a ^ b_sp ^ e) | (c ^ d ^ e)
    assert sp == (a ^ b_sp ^ e)
    assert trj == []

def test9():
    cg.clear()
    g = hook(match(srcip='10.0.0.1'), groupby=['switch'])
    a = atom(match(srcip='10.0.0.2'))
    pkt1 = base_pkt.modifymany({'srcip': '10.0.0.1', 'switch': 1})
    pkt2 = base_pkt.modifymany({'srcip': '10.0.0.1', 'switch': 2})
    pkt3 = base_pkt.modifymany({'srcip': '10.0.0.1', 'switch': 3})
    pkt4 = base_pkt.modifymany({'srcip': '10.0.0.1', 'switch': 4})
    pkt5 = base_pkt.modifymany({'srcip': '10.0.0.2'})
    (m, sp, trj) = specialize_main(+g ^ a, [pkt1, pkt2, pkt3, pkt4, pkt5])
    assert m
    g1 = atom(match(srcip='10.0.0.1', switch=1))
    g2 = atom(match(srcip='10.0.0.1', switch=2))
    g3 = atom(match(srcip='10.0.0.1', switch=3))
    g4 = atom(match(srcip='10.0.0.1', switch=4))
    assert sp == g1 ^ g2 ^ g3 ^ g4 ^ a
    assert trj == []

def test10():
    cg.clear()
    g = hook(match(srcip='10.0.0.1'), groupby=['switch'])
    a = atom(match(srcip='10.0.0.2'))
    pkt = base_pkt.modifymany({'srcip': '10.0.0.2'})
    (m, sp, trj) = specialize_main(+g ^ a, [pkt])
    assert m
    assert sp == a
    assert trj == []

def test11():
    cg.clear()
    g = hook(match(srcip='10.0.0.1'), groupby=['switch'])
    a = atom(match(srcip='10.0.0.3'))
    pkt1 = base_pkt.modifymany({'srcip': '10.0.0.1', 'switch':1})
    pkt2 = base_pkt.modifymany({'srcip': '10.0.0.2'})
    (m, sp, trj) = specialize_main(+g ^ a, [pkt1, pkt2])
    assert not m
    assert not sp
    assert not trj

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
    (m, sp, trj) = specialize_main(((+g ^ a) | (b ^ +h)) ^ c, 
                                   [pkt1, pkt2, pkt3, pkt4, pkt5])
    assert m
    g1 = atom(match(srcip='10.0.0.1', switch=1))
    g2 = atom(match(srcip='10.0.0.1', switch=2))
    g3 = atom(match(srcip='10.0.0.1', switch=3))
    h2 = atom(match(dstip='10.0.0.2', switch=2))
    h3 = atom(match(dstip='10.0.0.2', switch=3))
    h4 = atom(match(dstip='10.0.0.2', switch=4))
    assert sp == (g1 ^ g2 ^ g3 ^ a ^ c) | (b ^ h2 ^ h3 ^ h4 ^ c)
    assert trj == []

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
    (m, sp, trj) = specialize_main(((+g ^ a) | (b ^ +h)) ^ c, 
                                   [pkt1, pkt2, pkt3, pkt4, pkt5])
    assert m
    h2 = atom(match(dstip='10.0.0.2', switch=2))
    h3 = atom(match(dstip='10.0.0.2', switch=3))
    h4 = atom(match(dstip='10.0.0.2', switch=4))
    # assert sp == (+g ^ a ^ c) | (b ^ h2 ^ h3 ^ h4 ^ c)
    assert sp == (b ^ h2 ^ h3 ^ h4 ^ c)
    assert trj == []

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
    (m, sp, trj) = specialize_main(((+g ^ a) & (b ^ +h)) ^ c,
                                   [pkt1, pkt2, pkt3, pkt4, pkt5])
    assert m
    g1 = atom(match(srcip='10.0.0.1', switch=1))
    g2 = atom(match(srcip='10.0.0.1', switch=2))
    g3 = atom(match(srcip='10.0.0.1', switch=3))
    h2 = atom(match(dstip='10.0.0.2', switch=2))
    h3 = atom(match(dstip='10.0.0.2', switch=3))
    h4 = atom(match(dstip='10.0.0.2', switch=4))
    assert sp == (g1 ^ g2 ^ g3 ^ a ^ c) & (b ^ h2 ^ h3 ^ h4 ^ c)
    assert trj == []

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
    (m, sp, trj) = specialize_main(((+g ^ a) & (b ^ +h)) ^ c,
                                   [pkt1, pkt2, pkt3, pkt4, pkt5])
    assert not m
    assert not sp
    assert not trj

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
    (m, sp, trj) = specialize_main(((a ^ b) | (c ^ d)) ^ e, [pkt1, pkt2, pkt3])
    b_sp = atom(match(srcip='10.0.0.2', dstip='10.0.0.1'))
    e_sp = atom(match(srcip='10.0.0.1', dstip='10.0.0.3'))
    assert m
    # assert sp == (a ^ b_sp ^ e_sp) | (c ^ d ^ e)
    assert sp == (a ^ b_sp ^ e_sp)
    assert trj == []

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
    (m, sp, trj) = specialize_main(+g ^ a, t)
    (ml, spl, trjl) = specialize_main(+g ^ a, tl)
    assert m
    g1 = atom(match(srcip='10.0.0.1', switch=1))
    g2 = atom(match(srcip='10.0.0.1', switch=2))
    g3 = atom(match(srcip='10.0.0.1', switch=3))
    g4 = atom(match(srcip='10.0.0.1', switch=4))
    assert sp == g1 ^ g2 ^ g3 ^ g4 ^ a
    assert trj == []
    assert not ml

def test18():
    cg.clear()
    (m, sp, trj) = specialize_main(+path_epsilon(), [])
    assert m
    assert sp == path_epsilon()
    assert trj == []

def test19():
    cg.clear()
    (m, sp, trj) = specialize_main(+path_epsilon(), [base_pkt])
    assert not m

def test20():
    a = atom(match(srcip='10.0.0.1'))
    b = atom(match(srcip='10.0.0.2'))
    p = +(path_epsilon() | a) ^ b
    pkt1 = base_pkt.modifymany({'srcip': '10.0.0.1'})
    pkt2 = base_pkt.modifymany({'srcip': '10.0.0.2'})
    (m, sp, trj) = specialize_main(p, [pkt1, pkt2])
    assert m
    assert sp == a ^ b
    assert trj == []

def test21():
    a = atom(match(srcip='10.0.0.1'))
    b = atom(match(srcip='10.0.0.2'))
    p = a ^ +(path_epsilon() | b)
    pkt1 = base_pkt.modifymany({'srcip': '10.0.0.1'})
    pkt2 = base_pkt.modifymany({'srcip': '10.0.0.2'})
    (m, sp, trj) = specialize_main(p, [pkt1, pkt2])
    assert m
    assert sp == a ^ b
    assert trj == []

def test22():
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
    #print "Infinite loop cases follow:"
    #time.sleep(3)
    #test19()
    #test20()
    #test21()
    test22()
