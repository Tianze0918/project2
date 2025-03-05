./helper compile
./helper test test_client_hello 

code ./results/test_client_hello_refserver.out
code ./results/test_client_hello_yourclient.out 
#code ./results/test_self_yourserver.out  
# open -n -a "Visual Studio Code" ./results/test_self_yourclient.out
# open -n -a "Visual Studio Code" ./results/test_client_refserver.out




# uint8_t serialized[1024];
# uint16_t serialized_len = serialize_tlv(serialized, client_hello);
# print_tlv_bytes(serialized, serialized_len);