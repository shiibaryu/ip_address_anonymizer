HOST=`hostname`

sudo apt install nlohmann-json-dev
mkdir $HOST
bash ip_j_addr.sh
bash ip_route.sh
bash ip_6_route.sh
