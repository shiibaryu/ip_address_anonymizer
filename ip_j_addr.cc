#include <iostream>
#include <bitset>
#include <vector>
#include <utility>
#include <arpa/inet.h>
#include <fstream>
#include <nlohmann/json.hpp>

using namespace std;
using json = nlohmann::json;

bool inet6_lnaof(struct in6_addr *dst, struct in6_addr *src, struct in6_addr *netmask)
{
        bool has_lna = false;

        for (unsigned i = 0; i < 16; i++) {
                dst->s6_addr[i] = src->s6_addr[i] & netmask->s6_addr[i];
                has_lna |= (0 != (src->s6_addr[i] & !netmask->s6_addr[i]));
        }

        return has_lna;
}

int convert_v6addr_to_uint(string addr,struct in6_addr *masked)
{
        int ret = 0;

        int i = addr.length();
	
        string str_prefix = addr;

        const char *prefix = str_prefix.c_str();

        int len = 0;
        for(int j=i+1;j<addr.length();j++){
                len++;
        }

        int k = 0;
        char prefix_array[len];
        for(int j=i+1;j<addr.length();j++){
                prefix_array[k] = addr[j];
                k++;
        }

        int prefix_len = atoi(prefix_array);
        if(prefix_len == 0){
                prefix_len = 128;
        }

        struct in6_addr res;
        ret = inet_pton(AF_INET6, prefix, &res);
        if(ret != 1){
                cout << addr << endl;
                cout << str_prefix << endl;
                perror("inet_pton: ");
                return -1;
        }

        /*
        for(i=0;i<16;i++){
                printf("%hhx",res.s6_addr[i]);
        }
        */

        struct sockaddr_in6 netmask;
        for (long i = prefix_len, j = 0; i > 0; i -= 8, ++j){
                netmask.sin6_addr.s6_addr[j] = i >= 8 ? 0xff : (uint64_t)(( 0xffU << ( 8 - i ) ) & 0xffU );
        }

        inet6_lnaof(masked,&res,&netmask.sin6_addr);

        return prefix_len;
}

int anonymize_ipv6_addr(int prefix_len, uint8_t *addr, string saddr)
{
        if(prefix_len == 0){
                return 1;
        }

        if(saddr == "::1"){
                return 1;
        }

        int bit1 = 0b01010101;
        int bit2 = 0b01010101;
        int bit3 = 0b10110101;
        int bit4 = 0b01101010;
        int bit5 = 0b10100010;
        int bit6 = 0b11111011;
        int bit7 = 0b10001010;
        int bit8 = 0b10101001;


        addr[0] = addr[0] ^ bit1;
        addr[1] = addr[1] ^ bit2;
        addr[2] = addr[2] ^ bit3;
        addr[3] = addr[3] ^ bit4;
        addr[4] = addr[4] ^ bit5;
        addr[5] = addr[5] ^ bit6;
        addr[6] = addr[6] ^ bit7;
        addr[7] = addr[7] ^ bit8;

        return 0;
}

unsigned int anonymize_ipv4_addr(int prefix_len, unsigned int addr)
{
	if(prefix_len == 0){
		return addr;
	}

	unsigned int bit1 = 0b111111111001010110110101;
	bit1 = bit1 << 8;

	return addr ^ bit1;
}


unsigned int get_uint_ipv4_addr(string addr)
{
	int i=0;
	struct sockaddr_in sa;

	while(i < addr.length()-1){
		if(addr[i] == '/'){
			break;
		}
		i++;
	}
	
	if(i == (addr.length()-1)){
		int ret = inet_pton(AF_INET, addr.c_str(), &(sa.sin_addr));	
		if(ret == -1){
			perror("inet_pton");
		}

		sa.sin_addr.s_addr = ntohl(sa.sin_addr.s_addr);
		return sa.sin_addr.s_addr;
	}
	else{
		string saddr = addr.substr(0,i);

		string prefix_len = addr.substr(i+1);
		int plen = stoi(prefix_len);


		unsigned int nmask = 0;

		for(int j=0;j<plen;j++){
			nmask = nmask << 1;
			nmask = nmask | 1;
		}

		nmask = nmask << (32-plen);

		int ret = inet_pton(AF_INET, saddr.c_str(), &(sa.sin_addr));	
		if(ret == -1){
			perror("inet_pton");
		}

		sa.sin_addr.s_addr = ntohl(sa.sin_addr.s_addr);

		
		return (sa.sin_addr.s_addr & nmask);
	}
}

void parse_ip_addr_json(string path)
{
        std::ifstream ifs(path);

        json jf;

        ifs >> jf;


        for(int i=0;i<jf.size();i++){
                int size = jf[i]["addr_info"].size();

		string ifname = jf[i]["ifname"];
		
		for(int j=0;j<size;j++){
                	string family = jf[i]["addr_info"][j]["family"];

			if(family == "inet"){
				string addr = jf[i]["addr_info"][j]["local"];
				int prefix_len = jf[i]["addr_info"][j]["prefixlen"];
				string scope = jf[i]["addr_info"][j]["scope"];
			
				unsigned int uaddr = get_uint_ipv4_addr(addr);
				unsigned int auaddr = anonymize_ipv4_addr(prefix_len,uaddr);

				cout << ifname;
				cout << " inet";
				cout << " " << bitset<32>(auaddr);
				cout << " " << prefix_len;
				cout << " " << scope << endl;
			
			}
			else if(family == "inet6"){
				string addr = jf[i]["addr_info"][j]["local"];
				int prefix_len = jf[i]["addr_info"][j]["prefixlen"];
				string scope = jf[i]["addr_info"][j]["scope"];
			
				struct in6_addr masked;

				if(convert_v6addr_to_uint(addr,&masked) == -1){
					continue;
				}
				
				if(prefix_len == 0){
                        		unsigned long dr = 0;

					cout << ifname;
					cout << " inet6";
                      	  		cout << " " << 0;
					cout << " " << prefix_len;
					cout << " " << scope << endl;
                        		continue;
                		}

           		     	int ret = anonymize_ipv6_addr(prefix_len, masked.s6_addr,addr);

				cout << ifname;
				cout << " inet6 ";

                		for(int i=0;i<8;i++){
                        		cout << bitset<16>((masked.s6_addr[i*2] << 8) |  masked.s6_addr[i*2+1]).to_string();
                		}

				cout << " " << prefix_len;
				cout << " " << scope << endl;

			}

        	}
        }
}

int main(int argc, char** argv)
{
	if(argc > 2){
		cout << "./main file" << endl;
	}

	string file_path = argv[1];	

	cout << "ifname inet addr prefixlen scope" << endl;
	parse_ip_addr_json(file_path);
		
	return 0;
}
