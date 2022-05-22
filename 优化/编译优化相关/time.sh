#!/bin/bash
t=$(date +%s.%N)  #当前时间  
echo "当前时间为: $t"   
  
###############################################################  
echo "计算指定程序的执行时间"  
echo "Please Enter a command: "  
read cmd  
  
start=$(date +%s)            #开始时间  
$cmd
end=$(date +%s)              #结束时间  
  
time=$(( $end - $start ))    #计算时间差  
echo "$time s"               #输出时间差  
  