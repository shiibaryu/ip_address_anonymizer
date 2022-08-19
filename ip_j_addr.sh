HOST=`hostname`
ip -j addr > if.json
g++ ip_j_addr.cc -o ipja
./ipja if.json > $HOST/ano_if.txt
