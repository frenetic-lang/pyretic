=======
Pyretic
=======

The Pyretic platfrom - language & runtime system.
See http://frenetic-lang.org/pyretic/ for more info.

top-level structure:
- of_client:    Clients that run on a traditional OpenFlow controller
                effectively serving as a backend for Pyretic
- mininet:      Slightly modified version of mininet mn 
                and extra topologies used by Pyretic 
- mininet.sh:   A wrapper that starts up mininet for use w/ Pyretic
- pyretic:      Pyretic system proper 
- pyretic.py:   A wrapper that starts up Pyretic
                and optionally an OpenFlow client (see above)

