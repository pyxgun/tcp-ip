#ifndef _TLS_HEADER
#define _TLS_HEADER 1

#include <stdint.h>

/*
 *  Client Hello
 *
 *     enum { null(0), (255) } CompressionMethod;
 *       
 *     struct {
 *         ProtocolVersion client_version;
 *         Random random;
 *         SessionID session_id;
 *         CipherSuite cipher_suites<2..2^16-2>;
 *         CompressionMethod compression_methods<1..2^8-1>;
 *         select (extensions_present) {
 *             case false:
 *                 struct {};
 *             case true:
 *                 Extension extensions<0..2^16-1>;
 *         };
 *     } ClientHello;
 * 
 */


struct protocol_version {
    uint8_t major;
#define PROTO_TLS1  0x03
    uint8_t minor;
#define TLS_0       0x01
#define TLS_1       0x02
#define TLS_2       0x03
};

struct random {
    uint32_t    gmt_unix_time;      /* gmt unix time */
    uint8_t     random_byte[28];    /* randome bytes */
};

struct sessionid {
    uint8_t session_id[32];          /* session id */
};

struct cipher_suite {
    uint16_t cipher_suite;          /* cipher suite */
#define TLS_RSA_WITH_3DES_EDE_CBC_SHA   0x000A
#define TLS_RSA_WITH_AES_128_CBC_SHA    0x002F
#define TLS_RSA_WITH_AES_256_CBC_SHA    0x0035
};

struct compress_method {
    uint8_t comp_method;            /* compression method */
};

struct ext_sup_version {
    uint16_t    type;
#define EXT_SUPPORT_VERSION 0x002b
    uint16_t    len;
    uint8_t     sup_ver_len;
    uint16_t    support_version;
#define SUP_VER_TSL1_0  0x0301
#define SUP_VER_TSL1_1  0x0302
#define SUP_VER_TLS1_2  0x0303
};

struct hello_request {
    uint8_t                 hs_type;            /* handshake type */
    uint32_t                hello_req_len:24;   /* hello request length */
    struct protocol_version version;            /* protocol version */
    struct random           random;             /* random */
    uint8_t                 sessionid_len;      /* session id length */
    struct sessionid        sessionid;          /* session id */
    uint16_t                cipher_len;         /* cipher suite length */
    struct cipher_suite     cipher_suite[3];    /* cipher suite */
    uint8_t                 compress_len;       /* compression method length */
    struct compress_method  compress_method;    /* compression method */
    uint16_t                extension_len;      /* extension length */
    struct ext_sup_version  ext_sup_ver;        /* extension : supported version */
};

/*
 *  Handshake Protocol Structure
 *
 *  struct {
 *      HandshakeType msg_type;
 *      uint24 length;
 *      select (HandshakeType) {
 *          case hello_request:       HelloRequest;
 *          case client_hello:        ClientHello;
 *          case server_hello:        ServerHello;
 *          case certificate:         Certificate;
 *          case server_key_exchange: ServerKeyExchange;
 *          case certificate_request: CertificateRequest;
 *          case server_hello_done:   ServerHelloDone;
 *          case certificate_verify:  CertificateVerify;
 *          case client_key_exchange: ClientKeyExchange;
 *          case finished:            Finished;
 *      } body;
 *  } Handshake;
 * 
 */

struct tls_client_hello {
    uint8_t     msg_type;                   /* message type */
    uint16_t    tls_version;                /* tls version */
    uint16_t    total_len;                  /* total length */
    struct hello_request    client_hello;   /* hello request */
};


/* handshake protocol */
#define HSPROTO_HELLO_REQUEST           0
#define HSPROTO_CLIENT_HELLO            1
#define HSPROTO_SERVER_HELLO            2
#define HSPROTO_CERTIFICATE             11
#define HSPROTO_SERVER_KEY_EXCHANGE     12
#define HSPROTO_CERTIFICATE_REQUEST     13
#define HSPROTO_SERVER_HELLO_DONE       14
#define HSPROTO_CERTIFICATE_VERIFY      15
#define HSPROTO_CLIENT_KEY_EXCHANGE     16
#define HSPROTO_FINISHED                20

#endif