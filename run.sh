#!/bin/sh
HOST=`hostname`
CUR="./"
ANO="./ano_data"

sudo apt install nlohmann-json-dev
g++ ip_route.cc -o ipr
g++ ip_6_route.cc -o ip6r
g++ ip_j_addr.cc -o ipa
mkdir ano_data
array=($(find ./ -type d))
for i in ${array[@]}
do
	if [[ "$i" == "$CUR" || "$i" == "$ANO" ]] ; then
		continue
	fi
	./ipr $i/ip_route.txt > ano_ip_route.txt
	./ip6r $i/ip_6_route.txt > ano_ip_6_route.txt
	./ipa $i/ip_j_addr.json > ano_ip_j_addr.json
	mkdir ano_data/$i/
	mv ano_ip_route.txt  ./ano_data/$i/
	mv ano_ip_6_route.txt  ./ano_data/$i/
	mv ano_ip_j_addr.json  ./ano_data/$i/
	cp $i/ip_vrf.txt ./ano_data/$i/
done
