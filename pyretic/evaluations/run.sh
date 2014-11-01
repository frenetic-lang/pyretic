OLDIFS=$IFS 
IFS=','
for i in {30..40} 
do 
    sudo python mininet_setup.py -t path_packet_loss -targs $i -polargs n $i -profile -r ./Reports/$i 
done
IFS=$OLDIFS
