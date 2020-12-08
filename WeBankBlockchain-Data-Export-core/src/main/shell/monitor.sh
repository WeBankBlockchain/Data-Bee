#!/bin/bash

ip=127.0.0.1
port=8082
threshold=20
warn_number=1

 alarm(){
    alert_ip=`/sbin/ifconfig eth0 | grep inet | awk '{print $2}'`
    time=`date "+%Y-%m-%d %H:%M:%S"`
    echo "$alert_ip $1"
}

 dirpath="$(cd "$(dirname "$0")" && pwd)"
cd $dirpath
height_file="$dirpath/.block_height"
done_file="$dirpath/.done_blocks"
a=-1
b=-1

 for((i=0;i<3;i++))
do
	if [ $a -le 0 ]
    then
    	block_height=$(curl -s http://$ip:$port/api/blockTaskPool/blockHeight/get)
    	echo "block height now is $block_height "
	    a=$(($block_height+1))
    fi
	if [ $a -le 0 ]
	then
		alarm "ERROR! Get block height error."
		continue;
	fi

 	if [ $b -le 0 ]
    then
    	done_blocks=$(curl -s http://$ip:$port/api/blockTaskPool/blocks/get)
    	echo "download number is $done_blocks "
    	b=$(($done_blocks)) 
    fi

 	if [ $b -le 0 ]
	then
		alarm "ERROR! Get done block count error."
		continue;
	fi

 	todo_blocks=$(($a-$b))
    echo "Now have $todo_blocks blocks to depot"

 	if [ $todo_blocks -gt $threshold ] 
	then
		alarm "ERROR! $todo_blocks:the block height is far behind."
	else
		echo "OK! to do blocks is lesss than $threshold"
	fi
    break;
done

prev_height=0
prev_done=0
[ -f $height_file ] && prev_height=$(cat $height_file)
[ -f $done_file ] && prev_done=$(cat $done_file)
tmp=$(($a-$warn_number))
if [  $prev_height -lt $tmp  -a  $prev_done -ge $b  ]
then 
    alarm "ERROR! Depot task stuck in trouble, done block is $prev_done to $b , but block height is from $prev_height to $a "
else
    echo "OK! done blocks from $prev_done to $b, and height is from $prev_height to $a "
fi


echo $a > $height_file
echo $b > $done_file