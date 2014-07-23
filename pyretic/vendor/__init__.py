import os
import sys
import pyretic

VENDOR_LIBS = [ 'vendor/ryu', 'vendor/pydot' ]
PYRETIC_PATH = os.path.dirname(pyretic.__file__)

# Load the vendor libs
for lib in VENDOR_LIBS:
    sys.path.append(os.path.realpath(os.path.join(PYRETIC_PATH,lib)))
