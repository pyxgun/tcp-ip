#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include "genrand.h"
#include "ip_header.h"
#include "tcp_header.h"
#include "tls_header.h"


uint32_t get_unix_time(void) {
    time_t t = time(NULL);
    return (uint32_t)t;
}

void get_random_byte(uint8_t *bytes) {
    srand((unsigned int)time(NULL) + rand());
    for (int i = 0; i < 28; i++) {
        bytes[i] = random_byte();
    }
}

void get_session_id(uint8_t *sessionid) {
    srand((unsigned int)time(NULL) + rand());
    for (int i = 0; i < 32; i++) {
        sessionid[i] = random_byte();
    }
}

void create_hello_req(char *p) {
    struct tls_client_hello *client_hello = (struct tls_client_hello *)p;
    //client_hello = (struct tls_client_hello *)malloc(sizeof(struct tls_client_hello));

    client_hello->content_type                              = TLS_CNT_HANDSHAKE;
    client_hello->tls_version                               = TLS_VERSION_1_0;
    client_hello->total_len                                 = sizeof(struct hello_request);
    client_hello->client_hello.hs_type                      = HSPROTO_CLIENT_HELLO;
    client_hello->client_hello.hello_req_len                = sizeof(struct hello_request) - (sizeof(uint32_t));
    client_hello->client_hello.version.major                = PROTO_TLS1;
    client_hello->client_hello.version.minor                = TLS_1;
    client_hello->client_hello.random.gmt_unix_time         = get_unix_time();
    get_random_byte(client_hello->client_hello.random.random_byte);
    client_hello->client_hello.sessionid_len                = sizeof(client_hello->client_hello.sessionid);
    get_session_id(client_hello->client_hello.sessionid.session_id);

    client_hello->client_hello.cipher_len                   = sizeof((client_hello->client_hello.cipher_suite->cipher_suite) * 3);
    client_hello->client_hello.cipher_suite[0].cipher_suite = TLS_RSA_WITH_3DES_EDE_CBC_SHA;
    client_hello->client_hello.cipher_suite[1].cipher_suite = TLS_RSA_WITH_AES_128_CBC_SHA;
    client_hello->client_hello.cipher_suite[2].cipher_suite = TLS_RSA_WITH_AES_256_CBC_SHA;

    client_hello->client_hello.compress_len                 = sizeof(client_hello->client_hello.compress_method);
    client_hello->client_hello.compress_method.comp_method  = 0;
    client_hello->client_hello.extension_len                = sizeof(client_hello->client_hello.ext_sup_ver);
    client_hello->client_hello.ext_sup_ver.type             = EXT_SUPPORT_VERSION;
    client_hello->client_hello.ext_sup_ver.len              = 3;
    client_hello->client_hello.ext_sup_ver.sup_ver_len      = client_hello->client_hello.ext_sup_ver.len - 1;
    client_hello->client_hello.ext_sup_ver.support_version  = SUP_VER_TLS1_2;

    //memcpy(p, client_hello, sizeof(struct tls_client_hello) + sizeof(struct hello_request));


    FILE *fp = fopen("sample.bin", "wb");
    fwrite(client_hello, sizeof(char) * 517, 1, fp);
    fclose(fp);
    
}
