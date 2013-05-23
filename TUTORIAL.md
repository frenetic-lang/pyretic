========
Tutorial
========

Running examples is simple.  

Run "screen -S test" and ctrl-a ctrl-c to open a second screen (ctrl-a, ctrl-a toggles between the two).
In one screen run mininet, in the other run the pyretic. (TIP: start pyretic first for quicker hookup w/ mininet)
Each example file in pyretic/pyretic/examples contains instructions regarding mininet setup and testing.
Start with hub.py, mac_learner, virtualize, and then explore!

Via Command Line
----------------------------------------------------------
(pyretic_dir - the directory in which pyretic is installed)

- the module pyretic_dir/pyretic/pyretic/modules/mac_learner.py
$ pyretic.py pyretic.modules.mac_learner
- the example pyretic_dir/pyretic/pyretic/examples/kitchen_sink.py
$ pyretic.py pyretic.examples.kitchen_sink
- pyretic in interpreter mode (all packets go through controller)
$ pyretic.py -m i MODULE_NAME
- pyretic frontend and OF client backend seperately
(first start pyretic)
$ pyretic.py -f MODULE_NAME
(then, in another screen start OF client backend)
$ pox.py of_client.pox_client

