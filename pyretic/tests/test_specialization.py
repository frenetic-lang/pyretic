from pyretic.lib.path import *
from pyretic.lib.re import *
from pyretic.core.packet import *
import copy

base_pkt = Packet({'raw': '\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x01\x81\x00\x00\x02\x08\x00E\x00\x00T\x00\x00@\x00@\x01&\xa6\n\x00\x00\x01\n\x00\x00\x03\x08\x00\xe4@\x11\x9e\x00\x01\xf77\x18S\xfd\x91\n\x00\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./01234567', 'switch': 2, 'inport': 1})
base_pkt = base_pkt.modifymany(get_packet_processor().unpack(base_pkt['raw']))

cg = re_tree_gen

def __continuation__(ast, trj):
    if ast == path_epsilon():
        return (True, path_epsilon(), trj)
    else:
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
    if isinstance(ast, atom):
        return __sp_atom__(ast, c_ast, trj, lambda x, y: x)

    elif isinstance(ast, hook):
        return __sp_atom__(ast, c_ast, trj, __sp_group__)

    elif isinstance(ast, path_epsilon):
        return __continuation__(c_ast, trj)

    elif isinstance(ast, path_concat):
        assert len(ast.paths) > 1
        cont_ast = reduce(lambda a, x: a ^ x, ast.paths[1:] + [c_ast])
        return specialize(ast.paths[0], trj, cont_ast)

    elif isinstance(ast, path_alternate):
        def alter_map_fun(p, trj, c_ast):
            (m, sp, rem_trj) = specialize(p, trj, c_ast)
            if m:
                return (True, sp, rem_trj)
            else:
                return (False, p ^ c_ast, [])

        def alter_reduce_fun(acc, res):
            max_len = lambda a, b: a if len(a) > len(b) else b
            (m, sp, rem_trj) = acc
            (m_res, sp_res, rem_trj_res) = res
            return (m or m_res, sp | sp_res, max_len(rem_trj, rem_trj_res))

        return __sp_combinator__(ast.paths, trj, c_ast,
                                 alter_map_fun,
                                 alter_reduce_fun)

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
        (m,sp,rem_trj) = specialize(path_epsilon(), trj, c_ast)
        if m:
            return (m, sp, rem_trj)
        else:
            return specialize(ast.paths[0], trj, ast ^ c_ast)

    elif isinstance(ast, path_negate):
        return NotImplementedError("Negation not implemented yet.")

    else:
        raise TypeError("Can't specialize unknown path type!")

def specialize_main(path_ast, trajectory):
    return specialize(path_ast, trajectory, path_epsilon())

def test1():
    cg.clear()
    a = atom(match(srcip='10.0.0.1'))
    pkt = base_pkt.modifymany({'srcip': '10.0.0.1'})
    print specialize_main(a, [pkt])

def test2():
    cg.clear()
    a = atom(match(srcip='10.0.0.1'))
    pkt = base_pkt.modifymany({'srcip': '10.0.0.2'})
    print specialize_main(a, [pkt])

def test3():
    cg.clear()
    a = hook(match(srcip='10.0.0.1'), groupby=['dstip'])
    pkt = base_pkt.modifymany({'srcip': '10.0.0.1', 'dstip': '10.0.0.2'})
    print specialize_main(a, [pkt])

def test4():
    cg.clear()
    a = atom(match(srcip='10.0.0.1'))
    b = hook(match(srcip='10.0.0.1'), groupby=['dstip'])
    pkt1 = base_pkt.modifymany({'srcip': '10.0.0.1'})
    pkt2 = base_pkt.modifymany({'srcip': '10.0.0.1', 'dstip': '10.0.0.2'})
    print specialize_main(a ^ b, [pkt1, pkt2])

def test5():
    cg.clear()
    a = atom(match(srcip='10.0.0.1'))
    b = hook(match(srcip='10.0.0.1'), groupby=['dstip'])
    c = hook(match(srcip='10.0.0.1'), groupby=['srcip'])
    pkt1 = base_pkt.modifymany({'srcip': '10.0.0.1'})
    pkt2 = base_pkt.modifymany({'srcip': '10.0.0.1', 'dstip': '10.0.0.2'})
    pkt3 = base_pkt.modifymany({'srcip': '10.0.0.1'})
    print specialize_main(a ^ b ^ c, [pkt1, pkt2, pkt3])

def test6():
    cg.clear()
    print specialize_main(path_epsilon(), [base_pkt])

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
    print specialize_main(((a ^ b) | (c ^ d)) ^ e, [pkt1, pkt2, pkt3])

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
    print specialize_main(((a ^ b) | (c ^ d)) ^ e, [pkt1, pkt2, pkt3])

def test9():
    cg.clear()
    g = hook(match(srcip='10.0.0.1'), groupby=['switch'])
    a = atom(match(srcip='10.0.0.2'))
    pkt1 = base_pkt.modifymany({'srcip': '10.0.0.1', 'switch': 1})
    pkt2 = base_pkt.modifymany({'srcip': '10.0.0.1', 'switch': 2})
    pkt3 = base_pkt.modifymany({'srcip': '10.0.0.1', 'switch': 3})
    pkt4 = base_pkt.modifymany({'srcip': '10.0.0.1', 'switch': 4})
    pkt5 = base_pkt.modifymany({'srcip': '10.0.0.2'})
    print specialize_main(+g ^ a, [pkt1, pkt2, pkt3, pkt4, pkt5])

def test10():
    cg.clear()
    g = hook(match(srcip='10.0.0.1'), groupby=['switch'])
    a = atom(match(srcip='10.0.0.2'))
    pkt = base_pkt.modifymany({'srcip': '10.0.0.2'})
    print specialize_main(+g ^ a, [pkt])

def test11():
    cg.clear()
    g = hook(match(srcip='10.0.0.1'), groupby=['switch'])
    a = atom(match(srcip='10.0.0.3'))
    pkt1 = base_pkt.modifymany({'srcip': '10.0.0.1', 'switch':1})
    pkt2 = base_pkt.modifymany({'srcip': '10.0.0.2'})
    print specialize_main(+g ^ a, [pkt1, pkt2])

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
    print specialize_main(((+g ^ a) | (b ^ +h)) ^ c, 
                          [pkt1, pkt2, pkt3, pkt4, pkt5])

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
    print specialize_main(((+g ^ a) | (b ^ +h)) ^ c, 
                          [pkt1, pkt2, pkt3, pkt4, pkt5])

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
    print specialize_main(((+g ^ a) & (b ^ +h)) ^ c,
                          [pkt1, pkt2, pkt3, pkt4, pkt5])

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
    print specialize_main(((+g ^ a) & (b ^ +h)) ^ c,
                          [pkt1, pkt2, pkt3, pkt4, pkt5])

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
