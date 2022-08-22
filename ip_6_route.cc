#include <iostream>
#include <bitset>
#include <vector>
#include <utility>
#include <fstream>
#include <unordered_map>
#include <arpa/inet.h>

using namespace std;

#define BIT_TEST(k, b)  (((uint8_t *)(k))[(b) >> 3] & (0x80 >> ((b) & 0x7)))}

unsigned int anonymize_ipv4_addr(int prefix_len, unsigned int addr)
{
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

	int i = 0;
	while(i < addr.length()){
		if(addr[i] == '/'){
			break;
		}
		i++;
	}
	
	string str_prefix = addr.substr(0,i);
	if(str_prefix == "default"){
		return 0;
	}

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

int anonymize_addr(int prefix_len, uint8_t *addr, string saddr)
{
	if(prefix_len == 0){
		return 1;
	}

	if(saddr == "::1"){
		return 1;
	}

	int bits[8] = {0b01010101, 0b01010101, 0b10110101, 0b01101010, 0b10100010,0b11111011,0b10001010,0b10101001};
	
	//cout << prefix_len << endl;
	
	for(int i=0;i<prefix_len/8 || i < 8;i++){
		addr[i] = addr[i] ^ bits[i]; 
	}

	return 0;
}

void extract_fib_line(string *elms, int size, string mult_path_addr)
{
        int prefix_len;
        struct in6_addr masked;

	string addr;
	vector<string> inf;
	string weight;

	char buf[1000];

        if(elms[1] == "via"){
                addr = elms[0];
                inf.push_back(elms[4]);

                prefix_len = convert_v6addr_to_uint(addr,&masked);
                if(prefix_len == -1){
                        return;
                }

		if(prefix_len == 0){
			unsigned long dr = 0;
		
			cout << 0;
			cout << " " << inf[0] << " " << weight << endl; 
			
			return;
		}

		int ret = anonymize_addr(prefix_len, masked.s6_addr,addr);
		
		for(int i=0;i<8;i++){
			cout << bitset<16>((masked.s6_addr[i*2] << 8) |  masked.s6_addr[i*2+1]).to_string();
		}
		//printf("\n");
		
		cout << " " << inf[0] << " " << weight << endl; 
        }
        else if(elms[1] == "dev"){
                addr = elms[0];
                inf.push_back(elms[2]);


                prefix_len = convert_v6addr_to_uint(addr,&masked);
                if(prefix_len == -1){
                        cout << "error at convert_v6addr_to_uint()" << endl;
                        return;
                }

		if(prefix_len == 0){
			unsigned long dr = 0;
		
			cout << 0;
			cout << " " << inf[0] << " " << weight << endl; 
			
			return;
		}
		int ret = anonymize_addr(prefix_len, masked.s6_addr,addr);

		for(int i=0;i<8;i++){
			cout << bitset<16>((masked.s6_addr[i*2] << 8) |  masked.s6_addr[i*2+1]).to_string();
		}
		cout << " " << inf[0] << " " << weight << endl; 
        }
        else if(elms[1] == "nexthop"){
                addr = mult_path_addr;
                inf.push_back(elms[5]);
		weight = elms[7];


                prefix_len = convert_v6addr_to_uint(addr,&masked);
                if(prefix_len == -1){
                        cout << "error at convert_v6addr_to_uint()" << endl;
                        return;
                }
		
		if(prefix_len == 0){
			unsigned long dr = 0;
		
			cout << 0;
			cout << " " << inf[0] << " " << weight << endl; 
			
			return;
		}

		int ret = anonymize_addr(prefix_len, masked.s6_addr,addr);

		for(int i=0;i<8;i++){
			cout << bitset<16>((masked.s6_addr[i*2] << 8) |  masked.s6_addr[i*2+1]).to_string();
		}

		cout << " " << inf[0] << " " << weight << endl; 

        }
        else if(elms[1] == "nhid"){
                addr = mult_path_addr;
                inf.push_back(elms[6]);

                prefix_len = convert_v6addr_to_uint(addr,&masked);
                if(prefix_len == -1){
                        cout << "error at convert_v6addr_to_uint()" << endl;
                        return;
                }

		if(prefix_len == 0){
			unsigned long dr = 0;
		
			cout << 0;
			cout << " " << inf[0] << " " << weight << endl; 
			
			return;
		}

		int ret = anonymize_addr(prefix_len, masked.s6_addr,addr);

		for(int i=0;i<8;i++){
			cout << bitset<16>((masked.s6_addr[i*2] << 8) |  masked.s6_addr[i*2+1]).to_string();
		}
		cout << " " << inf[0] << " " << weight << endl; 
        }
        else if(elms[0] == "local"){
		addr = elms[1];
		inf.push_back(elms[9]);

		string action = elms[5];
		string nh4 = elms[7];

                prefix_len = convert_v6addr_to_uint(addr,&masked);
                if(prefix_len == -1){
                        cout << "error at convert_v6addr_to_uint()" << endl;
                        return;
                }

		if(prefix_len == 0){
			unsigned long dr = 0;
		
			cout << 0;
			cout << " " << inf[0] << " " << weight << endl; 
			
			return;
		}

		int ret = anonymize_addr(prefix_len, masked.s6_addr,addr);

		for(int i=0;i<8;i++){
			cout << bitset<16>((masked.s6_addr[i*2] << 8) |  masked.s6_addr[i*2+1]).to_string();
		}

		unsigned int saddr = get_uint_ipv4_addr(nh4);
		saddr = anonymize_ipv4_addr(32, saddr);

		cout << " " << inf[0];
		cout << " " << action;
		cout << " " << bitset<32>(saddr) << endl;
		
        }
}

void read_linux_fib(string path)
{
        int i = 0;
        int cur_idx = 0;
        int prev_idx = 0;
        string line;
        string cur_val;
        string mult_path_addr;

        ifstream read_file;
        read_file.open(path, ios::in);

        while(getline(read_file,line)){
                string iptable_elms[30];

                while(cur_idx <= line.length()){
                        while(!isspace(line[cur_idx]) && cur_idx < line.length()){
                                cur_idx++;
                        }

                        cur_val = line.substr(prev_idx,cur_idx - prev_idx);

                        iptable_elms[i] = cur_val;

                        i++;
                        cur_idx += 2;
                        prev_idx = cur_idx-1;
                }

                if(iptable_elms[1] == "proto" || iptable_elms[1] == "nhid" || iptable_elms[1] == "metric"){
                        mult_path_addr = iptable_elms[0];
                }

                extract_fib_line(iptable_elms,i-1,mult_path_addr);

                i = 0;
                cur_idx = 0;
                prev_idx = 0;
        }
}

int main(int argc, char** argv)
{
	if(argc > 2){
		cout << "./main file" << endl;
	}

	string file_path = argv[1];	
	cout << "anonymised_ipv6_addr  output_interface  weight (execption srv6 rule)" << endl;
	read_linux_fib(file_path);	

	return 0;
}
