from pyretic.core.language import *
from pyretic.lib.path import *

#########################################
#####             Tests             #####
#########################################

def pred_trans_test():
    pred = match(switch = 2)
    fdd = FDDTranslator.translate(pred, 1)
    FDDTranslator.assign_path(fdd, ({},set()))
    print fdd
    
    pred = ~match(switch = 2)
    fdd = FDDTranslator.translate(pred, 2)
    FDDTranslator.assign_path(fdd, ({},set()))
    print fdd

    pred = match(switch = 2) | (~match(inport = 3) & match(outport = 2))
    fdd = FDDTranslator.translate(pred, 3)
    FDDTranslator.assign_path(fdd, ({},set()))
    print fdd
    
    return 
    pred = match(switch = 2, inport = 3) | (~match(switch = 3, outport = 4)) | match(inport = 5)
    fdd = FDDTranslator.translate(pred, 4)
    FDDTranslator.assign_path(fdd, ({},set()))
    print fdd

def merge_test():   
    base = match(switch = 2, inport = 3) | (~match(switch = 3, outport = 4)) | match(inport = 5)
    base_fdd = FDDTranslator.translate(base, 4)
    print base_fdd
    
    pred = match(srcip = "10.0.0.1")
    fdd = FDDTranslator.translate(pred, 3)
    print fdd

    res = FDDTranslator.merge(fdd, base_fdd, True)
    FDDTranslator.assign_path(res, ({},set()))
    print res
if __name__ == "__main__":
    pred_trans_test()
