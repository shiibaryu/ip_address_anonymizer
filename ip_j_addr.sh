ip -j addr > if.json
g++ ip_j_addr.cc -o ipja
./ipja if.json > ano_data/ano_if.txt
