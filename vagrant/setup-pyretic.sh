#!/usr/bin/env bash

sudo apt-get install -y python-dev python-pip screen hping3
sudo pip install networkx bitarray netaddr ipaddr pytest ipdb 

wget https://raw.github.com/frenetic-lang/pyretic/master/pyretic/backend/patch/asynchat.py
sudo mv asynchat.py /usr/lib/python2.7/
sudo chown root:root /usr/lib/python2.7/asynchat.py 


git clone https://github.com/git/git.git
pushd git/contrib/subtree/
git checkout v1.8.4
make
sudo install -m 755 git-subtree /usr/lib/git-core
popd
rm -rf git

git clone git://github.com/frenetic-lang/pyretic.git

echo "export PATH=$PATH:$HOME/pyretic:$HOME/pox\
 export PYTHONPATH=$HOME/pyretic:$HOME/mininet:$HOME/pox" >> ~/.profile

wget http://frenetic-lang.org/pyretic/useful/.screenrc
