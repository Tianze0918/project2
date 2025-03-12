#include "consts.h"
#include "io.h"
#include "libsecurity.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


// ssize_t input_sec(uint8_t* buf, size_t max_length) {
//     return input_io(buf, max_length);
// }

// void output_sec(uint8_t* buf, size_t length){
//     output_io(buf, length);
// }

// void init_sec(int type, char* host) {
//     init_io();
// }



typedef struct Packet{
    uint16_t seq;               //input_buffer
    uint16_t ack;
    uint16_t length;            //input_buffer
    uint16_t window;
    uint16_t flags; 
    uint16_t unused;
    uint8_t payload[0];         //input_buffer
} Packet;

typedef enum{
    BEFORE_CLIENT_HELLO,
    WAITING_SERVER_HELLO,
    CLIENT_FINISHED,
    CLIENT_DATA_STAGE
} client_state;

typedef enum{
    WAITING,
    CLIENT_HELLO_RECEIVED,          //Used in input_sec to send server_hello
    WAITING_CLIENT_FINISHED,
    SERVER_DATA_STAGE
} server_state;

typedef struct context{
    uint16_t type;
    union{
        client_state c_state;
        server_state s_state;
    }state;
    char DNS[MAX_DNS_LENGTH];
} context;



context p_context;
uint8_t* client_hello_message=NULL;
size_t client_hello_message_len = 0; 

uint8_t* server_hello_message=NULL;
size_t server_hello_message_len = 0;




void generate_keys(){
    //Deriving Diffie-Hellman Secret
    derive_secret();


    //Deriving ENC and MAC keys
    uint16_t salt_len=client_hello_message_len+server_hello_message_len;
    uint8_t* salt=malloc(salt_len);
    uint8_t* q = salt;
    memcpy(q, client_hello_message, client_hello_message_len);
    q += client_hello_message_len;
    memcpy(q, server_hello_message, server_hello_message_len);
    
    derive_keys(salt, salt_len);
    free(salt);
}




uint16_t send_finished(uint8_t* buf){
    tlv* transcript = create_tlv(TRANSCRIPT);


    uint8_t HMAC_digest[MAC_SIZE];
    uint16_t data_len=server_hello_message_len+client_hello_message_len;
    uint8_t data[data_len];
    memcpy(data, client_hello_message, client_hello_message_len);
    memcpy(data+client_hello_message_len, server_hello_message, server_hello_message_len);

    hmac(HMAC_digest, data, data_len);
    add_val(transcript, HMAC_digest, MAC_SIZE);


    tlv* finished = create_tlv(FINISHED);
    add_tlv(finished, transcript);
    uint8_t serialized[1024];
    uint16_t serialized_len = serialize_tlv(serialized, finished);
    memcpy(buf, serialized, serialized_len);

    print_tlv_bytes(serialized, serialized_len);

    free_tlv(finished);
     
    p_context.state.c_state=CLIENT_DATA_STAGE;

    fprintf(stderr, "send finished\n");
    fprintf(stderr, "length is %u\n", client_hello_message_len+server_hello_message_len);

    return serialized_len;
}


void verify_transcript(tlv* message){
    // fprintf(stderr, "Inside verify_transcript\n");
    tlv* transcript = get_tlv(message, TRANSCRIPT);


    uint8_t HMAC_digest[MAC_SIZE];
    uint16_t data_len=server_hello_message_len+client_hello_message_len;
    uint8_t data[data_len];
    memcpy(data, client_hello_message, client_hello_message_len);
    memcpy(data+client_hello_message_len, server_hello_message, server_hello_message_len);

    hmac(HMAC_digest, data, data_len);

    fprintf(stderr, "length is %u\n", client_hello_message_len+server_hello_message_len);

   
    // Server own transcript
    tlv* new_transcript = create_tlv(TRANSCRIPT);
    add_val(new_transcript, HMAC_digest, MAC_SIZE);
    tlv* finished = create_tlv(FINISHED);
    add_tlv(finished, new_transcript);
    uint8_t serialized[1024];
    uint16_t serialized_len = serialize_tlv(serialized, finished);
    print_tlv_bytes(serialized, serialized_len);

    // Client transcript
    uint8_t serialized_t[1024];
    uint16_t serialized_t_len = serialize_tlv(serialized_t, message);
    print_tlv_bytes(serialized_t, serialized_t_len);

    if (memcmp(HMAC_digest, transcript->val, transcript->length)!=0){
        fprintf(stderr, "Server client HMAC doesn't match\n");
        exit(4);
    }
    p_context.state.s_state=SERVER_DATA_STAGE;
}




void create_hmac_digest(uint8_t* hmac_digest, tlv* iv, tlv* ciphertext){
    uint16_t iv_serail_size=1000;
    uint8_t iv_buf[iv_serail_size];
    uint16_t iv_len=serialize_tlv(iv_buf, iv);

    uint8_t ciphertext_buf[1000];
    uint16_t ciphertext_len=serialize_tlv(ciphertext_buf, ciphertext);
    
    uint16_t data_len=iv_len+ciphertext_len;
    uint8_t data[data_len];
    uint8_t* p=data;
    memcpy(p, iv_buf, iv_len); 
    p+=iv_len;
    memcpy(p, ciphertext_buf, ciphertext_len);

    hmac(hmac_digest, data, data_len);
}

void data_decryption(tlv* iv, tlv* ciphertext, tlv* mac){
    uint8_t hmac_digest[1000];
    create_hmac_digest(hmac_digest, iv, ciphertext);
    if (memcmp(hmac_digest, mac->val, mac->length)!=0){
        fprintf(stderr, "HMAC digest doesn't match MAC code\n");
        exit(5);
    }

    uint8_t buf[1000];
    ssize_t len = decrypt_cipher(buf, ciphertext->val, ciphertext->length, iv->val);

    output_io(buf, len);
}

uint16_t data_encryption(uint8_t* buf, size_t max_length){
    fprintf(stderr, "entered encryption\n");
    size_t plain_txt_size=0;

    if (max_length < (60+16)) {
        return 0;
    }
    // Integer division in C for size_t (unsigned) is effectively floor(...)
    size_t quotient = (max_length - 60) / 16;
    plain_txt_size = quotient * 16 - 1;


    uint8_t iv_buf[IV_SIZE];
    uint8_t ciphertext_buf[1000];
    uint8_t plain_txt[plain_txt_size];
    ssize_t read_len=input_io(plain_txt, plain_txt_size);
    uint8_t mac_buf[MAC_SIZE];

    ssize_t ciphertext_len=encrypt_data(iv_buf, ciphertext_buf, plain_txt, read_len);


    tlv* iv=create_tlv(IV);
    add_val(iv, iv_buf, IV_SIZE);
    // iv->length=htons(iv->length);

    tlv* ciphertext=create_tlv(CIPHERTEXT);
    add_val(ciphertext, ciphertext_buf, ciphertext_len);
    // ciphertext->length=htons(ciphertext->length);

    tlv* mac=create_tlv(MAC);
    create_hmac_digest(mac_buf, iv, ciphertext);
    add_val(mac, mac_buf, MAC_SIZE);
    // mac->length=htons(mac->length);



    tlv* data=create_tlv(DATA);
    add_tlv(data, iv);
    add_tlv(data, ciphertext);
    add_tlv(data, mac);

    uint16_t len = serialize_tlv(buf, data);
    free_tlv(data);

    return len;
}

void client_add_nonce(tlv* client_hello){
    tlv* client_nonce = create_tlv(NONCE);
    uint8_t nonce[NONCE_SIZE];
    generate_nonce(nonce, NONCE_SIZE);            //generate nonce
    add_val(client_nonce, nonce, NONCE_SIZE);     //fill client_nonce
    // fprintf(stderr, "client_nonce->type is %u\n", client_nonce->type);
    // client_nonce->length=htons(client_nonce->length);
    add_tlv(client_hello, client_nonce);          //add nonce object into client_hello tlv object
}

void client_add_public_key(tlv* client_hello){
    tlv* client_public_key = create_tlv(PUBLIC_KEY);
    generate_private_key();                       //generate public/private key pair
    derive_public_key();                          //fill client public key
    add_val(client_public_key, public_key, pub_key_size);
    // client_public_key->length=htons(client_public_key->length);
    add_tlv(client_hello, client_public_key);
}

void server_add_nonce(tlv* server_hello){
    tlv* server_nonce = create_tlv(NONCE);
    uint8_t nonce[NONCE_SIZE];
    generate_nonce(nonce, NONCE_SIZE);            //generate nonce
    add_val(server_nonce, nonce, NONCE_SIZE);
    // server_nonce->length=htons(server_nonce->length);
    add_tlv(server_hello, server_nonce);
}

void server_add_certificate(tlv* server_hello){
    tlv* server_certificate = create_tlv(CERTIFICATE);
    // Fill in certificate
    char *cwd = getcwd(NULL, 0);
    if (cwd == NULL) {
        fprintf(stderr, "getcwd error\n");
        exit(10);
    }

    uint16_t path_max=strlen(cwd)+17;
    char full_path[path_max];
    size_t len = strlen(cwd);
    if (cwd[len - 1] == '/') {
        snprintf(full_path, sizeof(full_path), "%sserver_cert.bin", cwd);
    } else {
        snprintf(full_path, sizeof(full_path), "%s/server_cert.bin", cwd);
    }

    load_certificate(full_path);
    add_val(server_certificate, certificate, cert_size);
    // server_certificate->length=htons(server_certificate->length);
    add_tlv(server_hello, server_certificate);
}

void load_pri_key(){
    // Get the server private key
    char *cwd = getcwd(NULL, 0);
    if (cwd == NULL) {
        fprintf(stderr, "getcwd error\n");
        exit(10);
    }

    uint16_t path_max=strlen(cwd)+17;
    char full_path[path_max];
    size_t len = strlen(cwd);
    if (cwd[len - 1] == '/') {
        snprintf(full_path, sizeof(full_path), "%sserver_key.bin", cwd);
    } else {
        snprintf(full_path, sizeof(full_path), "%s/server_key.bin", cwd);
    }
    // fprintf(stderr, "full path: %s\n", full_path);
    load_private_key(full_path);
}

void server_add_public_key(tlv* server_hello){
    tlv* server_public_key = create_tlv(PUBLIC_KEY);
    // Certificate public key
    load_pri_key();                 // Load server private key
    derive_public_key();            // Using loaded private key, fill public_key with its public key

    // Ephemeral public key
    // generate_private_key();
    // derive_public_key();

    add_val(server_public_key, public_key, pub_key_size);
    // server_public_key->length=htons(server_public_key->length);
    add_tlv(server_hello, server_public_key);
    // load_pri_key(); 
}

void server_add_handshake_signature(tlv* server_hello){
    tlv* server_signature = create_tlv(HANDSHAKE_SIGNATURE);
    // Fill in signature
    uint16_t data_size = 1024;
    uint8_t data[data_size];
    uint8_t* p = data;

    memcpy(p, client_hello_message, client_hello_message_len);
    p += client_hello_message_len;


    tlv* nonce=get_tlv(server_hello, NONCE);
    uint8_t serialized_nonce[1024];    
    uint16_t serialized_nonce_len = serialize_tlv(serialized_nonce, nonce);
    memcpy(p, serialized_nonce, serialized_nonce_len);
    p +=serialized_nonce_len;
    


    tlv* certificate=get_tlv(server_hello, CERTIFICATE);
    uint8_t serialized_certificate[1024];
    uint16_t serialized_certificate_len = serialize_tlv(serialized_certificate, certificate);
    memcpy(p, serialized_certificate, serialized_certificate_len);
    p += serialized_certificate_len;

    

    tlv* public_key=get_tlv(server_hello, PUBLIC_KEY);
    uint8_t serialized_public_key[1024];
    uint16_t serialized_public_key_len = serialize_tlv(serialized_public_key, public_key);
    memcpy(p, serialized_public_key, serialized_public_key_len);
    p += serialized_public_key_len;

   
    data_size = client_hello_message_len + 
                serialized_nonce_len + 
                serialized_certificate_len + 
                serialized_public_key_len;


    uint8_t signature[1000];
    size_t sig_len = sign(signature, data, data_size);
    add_val(server_signature, signature, sig_len);
    // server_signature->length=htons(server_signature->length);
    // fprintf(stderr, "signature->length is %u\n", server_signature->length);
    add_tlv(server_hello, server_signature);


    
    // uint8_t serialized[1024];
    // uint16_t serialized_len = serialize_tlv(serialized, server_hello);
    // print_tlv_bytes(serialized, serialized_len);

}

void verify_handshake_signature(tlv* hello_message){
    tlv* server_signature = create_tlv(HANDSHAKE_SIGNATURE);
    // Fill in signature
    uint16_t data_size = 1024;
    uint8_t data[data_size];
    uint8_t* p = data;

    memcpy(p, client_hello_message, client_hello_message_len);
    p += client_hello_message_len;


    tlv* nonce=get_tlv(hello_message, NONCE);
    uint8_t serialized_nonce[1024];    
    uint16_t serialized_nonce_len = serialize_tlv(serialized_nonce, nonce);
    memcpy(p, serialized_nonce, serialized_nonce_len);
    p +=serialized_nonce_len;
    


    tlv* certificate=get_tlv(hello_message, CERTIFICATE);
    uint8_t serialized_certificate[1024];
    uint16_t serialized_certificate_len = serialize_tlv(serialized_certificate, certificate);
    memcpy(p, serialized_certificate, serialized_certificate_len);
    p += serialized_certificate_len;

    

    tlv* public_key=get_tlv(hello_message, PUBLIC_KEY);
    uint8_t serialized_public_key[1024];
    uint16_t serialized_public_key_len = serialize_tlv(serialized_public_key, public_key);
    memcpy(p, serialized_public_key, serialized_public_key_len);
    p += serialized_public_key_len;

   
    data_size = client_hello_message_len + 
                serialized_nonce_len + 
                serialized_certificate_len + 
                serialized_public_key_len;


    
    tlv* hand_shake_sig = get_tlv(hello_message, HANDSHAKE_SIGNATURE);
    uint8_t serialized_hs[1024];    
    uint16_t serialized_hs_len = serialize_tlv(serialized_hs, hand_shake_sig);


    // load_peer_public_key(public_key->val, public_key->length);
    tlv* cert_pub_key = get_tlv(certificate, PUBLIC_KEY);
    load_peer_public_key(cert_pub_key->val, cert_pub_key->length);


    // int hand_shake_result = verify(serialized_hs, serialized_hs_len, data, data_size, ec_peer_public_key);
    int hand_shake_result = verify(hand_shake_sig->val, hand_shake_sig->length, data, data_size, ec_peer_public_key);
    fprintf(stderr, "signature result %u\n", hand_shake_result);
    if (hand_shake_result!=1){
        fprintf(stderr, "handshake_signature verification failed\n");
        exit(3);
    }

    load_peer_public_key(public_key->val, public_key->length);
}

uint16_t client_finished(tlv* message,  uint8_t* buf){
    tlv* server_hello = get_tlv(message, SERVER_HELLO);
    if (server_hello==NULL){
        fprintf(stderr, "Expecting server_hello, received something else\n");
        exit(6);
    }

    // Get the CA public key
    char *cwd = getcwd(NULL, 0);
    if (cwd == NULL) {
        fprintf(stderr, "getcwd error\n");
        exit(10);
    }

    uint16_t path_max=strlen(cwd)+19;
    char full_path[path_max];
    size_t len = strlen(cwd);
    if (cwd[len - 1] == '/') {
        snprintf(full_path, sizeof(full_path), "%sca_public_key.bin", cwd);
    } else {
        snprintf(full_path, sizeof(full_path), "%s/ca_public_key.bin", cwd);
    }
    load_ca_public_key(full_path);

    // Load server_hello certificate signature and DNS/Public_key in the same signature
    tlv* certificate=get_tlv(server_hello, CERTIFICATE);
    tlv* DNS=get_tlv(certificate, DNS_NAME);
    tlv* public_key=get_tlv(certificate, PUBLIC_KEY);
    tlv* certificate_signature=get_tlv(certificate, SIGNATURE);



    uint8_t serialized_dns[1024];
    uint16_t serialized_dns_len = serialize_tlv(serialized_dns, DNS);

    uint8_t serialized_public_key[1024];
    uint16_t serialized_public_key_len = serialize_tlv(serialized_public_key, public_key);

    uint8_t serialized_signature[1024];
    uint16_t serialized_signature_len = serialize_tlv(serialized_signature, certificate_signature);

    uint16_t DNS_key_length=serialized_dns_len+serialized_public_key_len;

    uint8_t DNS_key[DNS_key_length];
    uint8_t* p=DNS_key;
    memcpy(p, serialized_dns, serialized_dns_len);
    p+=serialized_dns_len;
    memcpy(p, serialized_public_key, serialized_public_key_len);


    // Verify certificate signature
    int certi_sig_result=verify(certificate_signature->val, certificate_signature->length, DNS_key, DNS_key_length, ec_ca_public_key);
    if (certi_sig_result!=1){
        fprintf(stderr, "Certificate signature failed\n");
        exit(1);
    }
   
    
    // Verify dns name
    if (memcmp(p_context.DNS, DNS->val, DNS->length)!=0){
        fprintf(stderr, "Bad DNS name\n");
        exit(2);
    }
    

    // Verify handhsake-signature
    verify_handshake_signature(server_hello);
    

    // Derive shared secret, ENC, MAC keys
    generate_keys();
    // fprintf(stderr, "generate keys\n");

    // Generate & send transcript
    uint16_t finished_len = send_finished(buf);

    return finished_len;
}   

void init_sec(int type, char* host) {
    // fprintf(stderr, "Entered init\n");
    init_io();
    if (type==SERVER){
        p_context.type=SERVER;
        p_context.state.s_state = WAITING;
    }else{
        p_context.type=CLIENT;
        p_context.state.c_state = BEFORE_CLIENT_HELLO;
        ssize_t host_len=strlen(host);
        strncpy(p_context.DNS, host, host_len);
        p_context.DNS[host_len] = '\0';
    }
}

ssize_t input_sec(uint8_t* buf, size_t max_length) {
    if (p_context.type==CLIENT){               
        if (p_context.state.c_state==BEFORE_CLIENT_HELLO){       //Client_hello

            // fprintf(stderr, "Entered input_sec\n");

            tlv* client_hello = create_tlv(CLIENT_HELLO);       //Create client_hello tlv object
            client_add_nonce(client_hello);
            client_add_public_key(client_hello);

        
            // fprintf(stderr, "Client_hello filled\n");
            //Client side client_hello
            client_hello_message = malloc(client_hello->length);
            if (client_hello_message == NULL) {
                fprintf(stderr, "Memory allocation failed for server_hello_message\n");
                exit(1);
            }
            // fprintf(stderr, "client_hello->val is %s, client_hello->length is %u\n", client_hello->val, client_hello->length);

            uint8_t serialized[1024];
            uint16_t serialized_len = serialize_tlv(serialized, client_hello);
            memcpy(client_hello_message, serialized, serialized_len);
            client_hello_message_len = serialized_len;
            

            
            memcpy(buf, client_hello_message, client_hello_message_len);
            uint16_t len = serialized_len;
            free_tlv(client_hello);

            // fprintf(stderr, "Client_hello serialized\n");


            p_context.state.c_state =  WAITING_SERVER_HELLO;
            return len;
        }else if (p_context.state.c_state==WAITING_SERVER_HELLO){
            return 0;       //Shouldn't input anything to security layer when still waiting for server hello
        }else if (p_context.state.c_state==CLIENT_FINISHED){
            tlv* message = deserialize_tlv(server_hello_message, server_hello_message_len);
            uint16_t len = client_finished(message, buf);

            // fprintf(stderr, "Buf content: \n");
            tlv* finished = deserialize_tlv(buf, len);
            // print_tlv_bytes(buf, len);


            return len;
        }
        else{   //Client input Data stage
            uint16_t len=data_encryption(buf, max_length);
            return len;
        }
    }else{
        if (p_context.state.s_state==CLIENT_HELLO_RECEIVED){
            tlv* server_hello = create_tlv(SERVER_HELLO);

            server_add_nonce(server_hello);
            server_add_certificate(server_hello);
            server_add_public_key(server_hello);
            server_add_handshake_signature(server_hello);
        
            // server_hello->length=htons(server_hello->length);
            uint16_t len = serialize_tlv(buf, server_hello);
            // server_hello->length=ntohs(server_hello->length);



            server_hello_message = malloc(server_hello->length);
            if (server_hello_message == NULL) {
                fprintf(stderr, "Memory allocation failed for server_hello_message\n");
                exit(1);
            }
            uint8_t serialized[1024];
            uint16_t serialized_len = serialize_tlv(serialized, server_hello);
            memcpy(server_hello_message, serialized, serialized_len);
            server_hello_message_len = serialized_len;
            // print_tlv_bytes(server_hello_message, server_hello_message_len);

            //Deriving Diffie-Hellman Secret and ENC and MAC keys
            generate_keys(buf, len);

            free_tlv(server_hello);
            


            // Transition to next state (modify as appropriate)
            p_context.state.s_state = WAITING_CLIENT_FINISHED;
            return len;
        }else if  (p_context.state.s_state==SERVER_DATA_STAGE){
            uint16_t len=data_encryption(buf, max_length);
            return len;
        }else{
            return 0; // If sever waiting for client_hello, do nothing
            // If sever WAITING_CLIENT_FINISHED, do nothing
        }
    }
}

void output_sec(uint8_t* buf, size_t length) {
    tlv* message = deserialize_tlv(buf, length);
    if (message==NULL){
        fprintf(stderr, "Received message not a valid TLV packet\n");
        exit(1);
    }

    if (p_context.type==SERVER){
        if (p_context.state.s_state==WAITING){
            tlv* client_hello = get_tlv(message, CLIENT_HELLO);
            if (client_hello==NULL){
                fprintf(stderr, "Expecting client_hello, received something else\n");
                exit(6);
            }
            // client_hello->length=ntohs(client_hello->length);

            // getting public keys from other side
            tlv* public_key=get_tlv(message, PUBLIC_KEY);
            // fprintf(stderr, "peer public key %p\n", ec_peer_public_key);
            load_peer_public_key(public_key->val, public_key->length);
            // fprintf(stderr, "peer public key %p\n", ec_peer_public_key);
            
            // Server storing client_hello
            client_hello_message = malloc(client_hello->length);
            if (client_hello_message == NULL) {
                fprintf(stderr, "Memory allocation for client_hello_message failed\n");
                exit(1);
            }
            uint8_t serialized[1024];
            uint16_t serialized_len = serialize_tlv(serialized, client_hello);
            memcpy(client_hello_message, serialized, serialized_len);
            client_hello_message_len = serialized_len;

            free_tlv(client_hello);


            p_context.state.s_state=CLIENT_HELLO_RECEIVED;
        }else if (p_context.state.s_state==WAITING_CLIENT_FINISHED){
            tlv* transcript = get_tlv(message, TRANSCRIPT);
            if (transcript==NULL){
                fprintf(stderr, "Expecting transcript, received something else\n");
                exit(6);
            }
            // transcript->length=ntohs(transcript->length);
            verify_transcript(message);
        }else if (p_context.state.s_state==SERVER_DATA_STAGE){          //Server output
            tlv* iv = get_tlv(message, IV);
            tlv* ciphertext = get_tlv(message, CIPHERTEXT);
            tlv* mac = get_tlv(message, MAC);
            data_decryption(iv, ciphertext, mac);           //Client data_encryption
        }else{          //CLIENT_HELLO_RECEIVED
            return;
        }
    }else{
        if (p_context.state.c_state==WAITING_SERVER_HELLO){
            // message->length=ntohs(message->length);

            // Client storing server_hello
            uint8_t serialized[1024];
            uint16_t serialized_len = serialize_tlv(serialized, message);
            server_hello_message = malloc(serialized_len);
            if (server_hello_message == NULL) {
                fprintf(stderr, "Memory allocation for server_hello_message failed\n");
                exit(1);
            }
            memcpy(server_hello_message, serialized, serialized_len);
            server_hello_message_len = serialized_len;

            p_context.state.c_state=CLIENT_FINISHED;
        }else if (p_context.state.c_state==CLIENT_DATA_STAGE){
            tlv* iv = get_tlv(message, IV);
            tlv* ciphertext = get_tlv(message, CIPHERTEXT);
            tlv* mac = get_tlv(message, MAC);
            data_decryption(iv, ciphertext, mac);
        }
        else{
            return;     //BEFORE_CLIENT_HELLO, shouldn't output anything
        }
    }


}


// Under what circumstances are input_sec and output_sec invoked? 
// Are we suppose to read from std in from input_sec and parse it and encrypt it after handshake?
// Does input_sec and ouput_sec buf the payload of packet or the entire packet itself?