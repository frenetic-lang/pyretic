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

def specialize(ast, trj, c_ast):
    if isinstance(ast, atom):
        if len(trj) == 0:
            return (False, None, [])
        else:
            first_pkt = trj[0]
            pred = ast.policy
            if len(pred.eval(first_pkt)) > 0:
                (matches, sp_ast, rem_trj) = __continuation__(c_ast, trj[1:])
                if matches:
                    return (True, ast ^ sp_ast, rem_trj)
                else:
                    return (False, None, [])
            else:
                return (False, None, [])

    elif isinstance(ast, hook):
        # check hook predicate, and specialize
        if len(trj) == 0:
            return (False, None, [])
        else:
            first_pkt = trj[0]
            pred = ast.policy
            if len(pred.eval(first_pkt)) > 0:
                (matches, sp_ast, rem_trj) = __continuation__(c_ast, trj[1:])
                if matches:
                    return (True, (__sp_group__(ast, first_pkt) ^
                                   sp_ast), rem_trj)
                else:
                    return (False, None, [])
            else:
                return (False, None, [])

    elif isinstance(ast, path_epsilon):
        return __continuation__(c_ast, trj)

    elif isinstance(ast, path_concat):
        paths = ast.paths
        assert len(paths) > 1
        p = paths[0]
        rem_ast = reduce(lambda a, x: a ^ x, paths[1:])
        (m,sp,rem_trj) = specialize(p, trj, rem_ast ^ c_ast)
        if m:
            return (True, sp, rem_trj)
        else:
            return (False, None, [])

    elif isinstance(ast, path_alternate):
        paths = ast.paths
        assert len(paths) > 1
        sp_paths = []
        final_trj = None
        matched = False
        for p in paths:
            (m, sp, rem_trj) = specialize(p, trj, c_ast)
            if m:
                matched = True
                sp_paths.append(sp)
                if final_trj:
                    if len(final_trj) < len(rem_trj):
                        final_trj = rem_trj
                else:
                    final_trj = rem_trj
            else:
                sp_paths.append(p ^ c_ast)
        final_sp_path = reduce(lambda a, x: a | x, sp_paths)
        if matched:
            return (True, final_sp_path, final_trj)
        else:
            return (False, None, [])

    elif isinstance(ast, path_star):
        assert len(ast.paths) == 1
        p = ast.paths[0]
        curr_path = path_epsilon()
        (match_only_curr,_,_) = specialize(curr_path, trj, path_epsilon())
        while match_only_curr:
            (match_cont, sp, rem_trj) = specialize(curr_path, trj, c_ast)
            if match_cont: # success!
                return (True, sp, rem_trj)
            else:
                curr_path = curr_path ^ p
                (match_only_curr,_,_) = specialize(curr_path, trj,
                                                   path_epsilon())
        assert not match_only_curr
        return (False, None, [])

    elif isinstance(ast, path_inters):
        raise NotImplementedError("Intersection not implemented yet.")

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

