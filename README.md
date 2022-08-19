# ip_address_anonymizer
<h4> ip address anonymizer only for our research usage (for linux, iproute2)

## ip_route.cc
<h4> Input: ip route, Output: anonymized_ip_address output_interface weight <br>

## ip_6_route.cc
<h4> Input: ip -6 route, Output: anonymized_ip_address output_interface weight <br>

## ip_j_addr.cc
<h4> Input: ip -j addr, Output: interface INET addr prefixlen scope <br>

## How to run
run "bash run.sh" <br>

## Requirement
Json library: https://nlohmann.github.io/json/ <br>
Install: https://www.howtoinstall.me/ubuntu/18-04/nlohmann-json-dev/

## How to anonymize
Applying XOR to ip address using randimized bit sequences (*only for our research usage, not generalized) # ip_address_anonymizer
