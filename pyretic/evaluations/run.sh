OLDIFS=$IFS 
IFS=','
#for i in {30..40}
for i in 1,1 1,2 1,3 2,2 2,3 2,4 2,5 3,3 3,4 3,5 4,5 5,5 
do 
    set $i
    sudo python eval_compilation.py -t congested_link -polargs n $1 m $2 -r ./offline_results/$1-$2
#    sudo python mininet_setup.py -t path_packet_loss -targs $i -polargs n $i -profile -r ./Reports/$i 
done
IFS=$OLDIFS
