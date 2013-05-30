==================
Installation/Setup
==================

Pyretic is self-contained and has relatively few dependencies
(most notably Python 2.7).

1) Clone the pyretic repository to your home directory   
> $ cd ~   
> $ git clone git://github.com/frenetic-lang/pyretic.git

2) Install bitarray (version 0.8.1)   
> $ sudo easy_install bitarray


And you are done w/ installing pyretic proper on your system 
(though life will be much easier if you set up your environment 
variables correctly - see below for info). Of course, you will 
need to run one of the OpenFlow client controllers available in 
pyretic/of_client in order to actually connect to 
OpenFlow-compatible switches.  Thus you'll need to have one on
your system (currently only a POX client controller is provided)

3) Install POX - see https://github.com/noxrepo/pox for instructions
   OR Update POX, if already installed   
(tested with commit d4b346c01b486d0610c12bc1e467f52261a16d17)   
> $ cd ~/pox   
> $ git pull   
> $ git checkout -b carp origin/carp   



You also may want to hook up your controller to an emulated
network - especially if you want to do our tutorial.  If, so
you will need Mininet.
4) Install Mininet - see http://mininet.org/ for instructions
   OR Update Mininet, if already installed    
(tested with commit e3d07bc1a0132feea8f356814ae4acbdea1d1d63)   
> $ cd ~/mininet    
> $ git pull   


Finally, set up your environment so you don't need to specify 
paths to pyretic.py and enable Python to find your 
pyretic/pox/mininet modules.

5) Setup your environment variables
add following lines to end of .profile:
> export PATH=$PATH:$HOME/pyretic:$HOME/pox   
> export PYTHONPATH=$HOME/pyretic:$HOME/mininet:$HOME/pox


Optional, but recommended:

6) add my helpful .screenrc   
> $ cd ~    
> $ wget http://frenetic-lang.org/pyretic/useful/.screenrc

7) install the i-python debugger (tested with 0.13.2)   
> $ sudo easy_install ipdb



