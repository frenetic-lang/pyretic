for i in range(1,20):
    fname = "%d-%d"% (i, i)
    f = open(fname + "/regexes_to_dfa.profile")
    for line in f.readlines():
        if "total time" in line:
            print line[line.index(":") + 2:-1]
            break
