from pyretic.kinetic.apps.ids import ids
from pyretic.kinetic.apps.mac_learner import mac_learner

#####################################################################################################
# App launch
#  - pyretic.py pyretic.kinetic.apps.ids_and_mac_learner
#
# Mininet Generation
#  - sudo mn --controller=remote,ip=127.0.0.1 --mac --arp --switch ovsk --link=tc --topo=single,3
#
# Events to block traffic "h1 ping h2"
#  - python json_sender.py -n infected -l True --flow="{srcip=10.0.0.1}" -a 127.0.0.1 -p 50001
#
# Events to again allow traffic "h1 ping h2"
#  - python json_sender.py -n infected -l False --flow="{srcip=10.0.0.1}" -a 127.0.0.1 -p 50001
#####################################################################################################


def main():
    return ids() >> mac_learner()
