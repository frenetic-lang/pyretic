OLDIFS=$IFS 
IFS=','
#for i in {260..460..50}
#do 
#    sudo python eval_compilation.py -d -u -r -i -t path_packet_loss -polargs n $i -f ./opt6_results/$i
#done


#for i in {10..200..10}
#do 
#   sudo python eval_compilation.py -d -u -r -i -t path_packet_loss -polargs n $i -f ./optall_results/$i
#
#done

for i in {24..25}
do 
    sudo python eval_compilation.py -d -u -r -i -t congested_link -polargs n $i m $i -f ./congested_link_final/optall_results/$i-$i

done

IFS=$OLDIFS
