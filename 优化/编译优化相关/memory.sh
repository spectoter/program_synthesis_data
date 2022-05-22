#!/bin/sh
source /etc/profile

#define variable

psUser=$1
psProcess=$2
pid= `ps -ef | egrep ${psProcess} | egrep ${psUser} |  egrep -v "grep|vi|tail" | sed -n 1p | awk '{print $2}'`
echo ${pid}
if [ -z ${pid} ];then
	echo "The process does not exist."
	exit 1
fi   

MemUsage=`ps -p ${pid} -o vsz |egrep -v VSZ` 
 (( ${MemUsage} /= 1000)) 
echo ${MemUsage} 

if [ ${MemUsage} -ge 1600 ];
	then
		echo “The usage of memory is larger than 1.6G”
	else
	 	echo “The usage of memory is ok”
fi
