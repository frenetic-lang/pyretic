TUTORIAL

Running examples is simple.  
Run "screen -S test" and ctrl-a ctrl-c to open a second screen (ctrl-a, ctrl-a toggles between the two).
In one screen run mininet, in the other run the pyretic controller.
Each example file in pyretic/pyretic/examples contains instructions for running and testing.

Start with hub.py, then mac_learner, virtualize, and then explore!
=======
To run:
the module INSTALL_DIR/pyretic/pyretic/modules/mac_learner.py
$ pyretic.py pyretic.modules.mac_learner
the example INSTALL_DIR/pyretic/pyretic/examples/kitchen_sink.py
$ pyretic.py pyretic.examples.kitchen_sink

To run pyretic frontend and OF client backend seperately:
first start pyretic
$ pyretic.py -f MODULE_NAME
then, in another screen start OF client backend
$ pox.py of_client.pox_client

