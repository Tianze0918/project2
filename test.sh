./helper compile
./helper test test_server_hello 

code ./results/test_server_hello_refclient.out
code ./results/test_server_hello_yourserver.out
#code ./results/test_self_yourserver.out  
# open -n -a "Visual Studio Code" ./results/test_self_yourclient.out
# open -n -a "Visual Studio Code" ./results/test_client_refserver.out




# uint8_t serialized[1024];
# uint16_t serialized_len = serialize_tlv(serialized, client_hello);
# print_tlv_bytes(serialized, serialized_len);