#!/bin/bash

if [ ! -d log ]; then
	echo "";
	echo "# Creating \"log\" dir to store temp data ...";
	echo "";
	mkdir log;
fi

export NS_LOG=SIM_SUBNET_QUEUE=info
case $1 in
	1) #5
		../waf --run "buildsubnets --subnets=1 --apprate=1Mbps --queuesize=2000" --vis	;;
	2) #6
		../waf --run "buildsubnets --subnets=2 --apprate=1Mbps --queuesize=2000" --vis	;;
	3) #7
		../waf --run "buildsubnets --subnets=1 --apprate=1.5Mbps --queuesize=2000"		;;
	4) #9
		../waf --run "buildsubnets --subnets=1 --apprate=1.5Mbps --queuesize=3000"		;;
	**)
		echo ""
		echo "        Usage: sh $0 (1|2|3|4)" 
		echo "";;
esac


