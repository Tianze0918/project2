./helper compile
./helper test test_encrypt_and_mac_server 

code ./results/test_encrypt_and_mac_client_refclient.out 
code ./results/test_encrypt_and_mac_client_yourserver.out
# code ./results/test_encrypt_and_mac_client_yourclient.out 
#code ./results/test_self_yourserver.out  
# open -n -a "Visual Studio Code" ./results/test_self_yourclient.out
# open -n -a "Visual Studio Code" ./results/test_client_refserver.out




# uint8_t serialized[1024];
# uint16_t serialized_len = serialize_tlv(serialized, client_hello);
# print_tlv_bytes(serialized, serialized_len);