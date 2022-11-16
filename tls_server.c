#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <fcntl.h>
#include <liburing/io_uring.h>
#include <liburing.h>
#include <sys/mman.h>

#define ENTRIES 32

#define BUFFER_SIZE 2048

#define NCQES ENTRIES * 4
#define MAX_CONNS 16
#define NBUFFERS MAX_CONNS * 2


SSL_CTX* ssl_ctx = NULL;

struct ssl_conn {
    int fd;
    SSL *ssl;
    char* host_name;
};

static struct ssl_conn CONNECTIONS[MAX_CONNS];

struct uring_user_data {
    __u16 conn_idx;
    __u8 req_type
};

enum {
    CONNECT = 1,
    HANDSHAKE_WRITE,
    HANDSHAKE_READ
};

struct read_buff_pool {
    unsigned int nbuffers;
    unsigned int buff_size;
    struct io_uring_buf_ring* buff_ring;
};

static void* write_buff_pool = NULL;
static struct read_buff_pool READ_BUFFER_POOL;

unsigned char* buffer_pool_get(struct read_buff_pool* pool, unsigned int idx) {
    unsigned char *buff_base = (unsigned char *) pool->buff_ring +
                               sizeof(struct io_uring_buf) * pool->nbuffers;
    return buff_base + (idx * pool->buff_size);
}

void buffer_pool_release(struct read_buff_pool *buff_pool, unsigned short idx) {
    void *buffer = buffer_pool_get(buff_pool, idx); //base address of buffer at idx
    int mask = io_uring_buf_ring_mask(buff_pool->nbuffers);
    io_uring_buf_ring_add(buff_pool->buff_ring, buffer, buff_pool->buff_size, idx, mask, 0 );
    io_uring_buf_ring_advance(buff_pool->buff_ring, 1);
}


/**buffer pool for reads
 *
 * @param uring
 * @param buff_pool
 * @return
 */
int setup_pooled_buffers(struct io_uring *uring, struct read_buff_pool* buff_pool) {

    const unsigned int buffer_size = BUFFER_SIZE;
    const unsigned int nbuffers = NBUFFERS;
    const size_t size = (sizeof(struct io_uring_buf) + buffer_size) * nbuffers;
    void *mem = mmap(NULL, size, PROT_WRITE | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);

    if (mem == MAP_FAILED) {
        fprintf(stderr, "failed to allocate buffers \n");
        return -1;
    }
    struct io_uring_buf_ring *buff_ring = (struct io_uring_buf_ring *) mem;
    io_uring_buf_ring_init(buff_ring);
    struct io_uring_buf_reg buf_reg = {
            .ring_addr = (unsigned long) buff_ring,
            .bgid = 0,
            .ring_entries = nbuffers
    };
    int result = io_uring_register_buf_ring(uring, &buf_reg, 0);
    if (result) {
        fprintf(stderr, "failed to register_buf_ring %s \n", strerror(-result));
        return result;
    }
    unsigned char *buffers_base = (unsigned char *) buff_ring + (sizeof(struct io_uring_buf) * nbuffers);
    for(unsigned int i = 0; i < nbuffers; i++) {
        void *buffer_i = buffers_base + (buffer_size * i);
        io_uring_buf_ring_add(buff_ring, buffer_i, buffer_size, i, io_uring_buf_ring_mask(nbuffers), i);
    }
    io_uring_buf_ring_advance(buff_ring, nbuffers);
    buff_pool->buff_ring = buff_ring;
    buff_pool->nbuffers = nbuffers;
    buff_pool->buff_size = buffer_size;
    return 0;
}


void *setup_fixed_buffers(struct io_uring *uring) {

    const size_t size = BUFFER_SIZE * NBUFFERS;
    void *mem = mmap(NULL, size, PROT_WRITE | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);

    if (mem == MAP_FAILED) {
        fprintf(stderr, "failed to allocate buffers \n");
        return NULL;
    }
    struct iovec iov[NBUFFERS];
    for(int i = 0; i < NBUFFERS; i++) {
        iov[i].iov_base = mem + (i * BUFFER_SIZE);
        iov[i].iov_len = BUFFER_SIZE;
        memset(iov[i].iov_base, 0, BUFFER_SIZE);
    }
    int ret = io_uring_register_buffers(uring, iov, NBUFFERS);
    if(ret) {
        fprintf(stderr, "Error registering buffers: %s", strerror(-ret));
        return NULL;
    }
    return mem;
}


int setup_iouring(struct io_uring* ring) {
    struct io_uring_params params;
    memset(&params, 0, sizeof(params));

    params.cq_entries = NCQES;
    params.flags =
            IORING_SETUP_COOP_TASKRUN  //ensure kernel doesnt interrup user thread, use this in single thread mode
            | IORING_SETUP_SUBMIT_ALL  // dont stop submit entries when error
            | IORING_SETUP_CQSIZE; // pre-fill a buffer for cqe(s)
    int result = io_uring_queue_init_params(ENTRIES, ring, &params);
    return result;
}

static void *get_buffer(void *mem, __u16 idx) {
    void *buff = mem + (idx * BUFFER_SIZE);
    return buff;
}

void prep_write(int fd, struct io_uring* ring, __u16 idx, int type, const void *buffer,
                int size) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_write_fixed(sqe, fd, buffer, size, 0, idx);
    struct uring_user_data tag = {
        .conn_idx = idx,
        .req_type = type
    };
    memset(&sqe->user_data, 0, sizeof(tag));
    memcpy(&sqe->user_data, &tag, sizeof(tag));

}

void prep_read(int fd, struct io_uring *ring, int type, __u16 conn_idx) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);

    io_uring_prep_recv(sqe, fd, NULL, BUFFER_SIZE, 0);
    sqe->flags |= IOSQE_BUFFER_SELECT;
    sqe->buf_group = 0;
    struct uring_user_data tag = {
            .conn_idx = conn_idx,
            .req_type = type
    };
    memset(&sqe->user_data, 0, sizeof(tag));
    memcpy(&sqe->user_data, &tag, sizeof(tag));
}

int do_ssl_handshake(struct io_uring_cqe *cqe, struct io_uring* ring) {
    struct uring_user_data tag;
    memcpy(&tag, &cqe->user_data, sizeof(tag));
    __u16 conn_idx = tag.conn_idx;
    struct ssl_conn *conn = &CONNECTIONS[conn_idx];
    assert(conn->fd > 0);
    SSL *ssl = conn->ssl;
    assert(ssl && "ssl not setup for connection");
    if (SSL_is_init_finished(ssl)) {
        return 0;
    }
    if (tag.req_type == HANDSHAKE_READ) {
        const unsigned short buf_idx = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
        void *buffer = buffer_pool_get(&READ_BUFFER_POOL, buf_idx);

        BIO *read_bio = SSL_get_rbio(ssl);
        int read_bytes = cqe->res;
        int written = BIO_write(read_bio, buffer, read_bytes);
        assert(written > 0 && "write bytes");
        buffer_pool_release(&READ_BUFFER_POOL, buf_idx);
    }

    int ret = SSL_connect(ssl);
    int ssl_err = SSL_get_error(ssl, ret);
    BIO *write_bio = SSL_get_wbio(ssl);
    if (BIO_pending(write_bio)) {
        int pending_bytes = BIO_pending(write_bio);
        void *buffer = get_buffer(write_buff_pool, conn_idx);
        int n = BIO_read(write_bio, buffer, BUFFER_SIZE);
        prep_write(conn->fd, ring, conn_idx, HANDSHAKE_WRITE, buffer, n);
    }
    if (ssl_err == SSL_ERROR_WANT_READ) {
        prep_read(conn->fd, ring, HANDSHAKE_READ, conn_idx);
    }
    return 1;
}
//            || ssl_err == SSL_ERROR_WANT_WRITE
//            || ssl_pending_write(&conn)) {
//            BIO *write_bio = SSL_get_wbio(ssl);
//            int pending_bytes = BIO_pending(write_bio);
//            fprintf(stderr, "pending_bytes %d \n", pending_bytes);
//            char buff[2048];
//            int n = BIO_read(write_bio, buff, sizeof(buff));
//
//            send(sock_fd, buff, n, 0);
//            fprintf(stderr, "sent %d bytes \n", n);
//            if (SSL_want_read(ssl)) {
// s           int read_bytes = recv(sock_fd, buff, sizeof(buff), 0);
//            fprintf(stderr, "received %d bytes \n", read_bytes);
//            if (read_bytes > 0) {
//                BIO *read_bio = SSL_get_rbio(ssl);
//                BIO_write(read_bio, buff, read_bytes);
//            }
//            }
//        }
//        else {
//            fprintf(stderr, "ssl state %s ssl_want_read=%d\n", SSL_state_string_long(ssl), SSL_want_read(ssl));
//            ERR_print_errors_fp(stderr);
    
//}

int setup_socket(char *host_ip, int port, struct sockaddr_in *addr) {
    int  fd;
    if (0 > (fd = socket(AF_INET,
                         SOCK_STREAM , //|  SOCK_NONBLOCK,
                         0))) {
        return -1;
    }
    memset(addr, 0, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    if (host_ip && (1 != inet_pton(AF_INET, host_ip, &addr->sin_addr))) {
        return -1;
    }

    return fd;
}

SSL* setup_tls_client(SSL_CTX *ssl_ctx, char *hostname) {
    BIO *read_bio = BIO_new(BIO_s_mem());
    assert(read_bio);
    BIO *write_bio = BIO_new(BIO_s_mem());
    assert(write_bio);
    BIO_set_mem_eof_return(read_bio, -1);
    BIO_set_mem_eof_return(write_bio, -1);
    SSL *ssl = SSL_new(ssl_ctx);
    assert(ssl && "ssl-not-created");
    SSL_set_bio(ssl, read_bio, write_bio);

    long result = SSL_set_tlsext_host_name(ssl, hostname);
    assert(result == 1);
    result = SSL_set1_host(ssl, hostname); //set host-name for cert verification
    assert(result == 1);

    return ssl;
}

int init_ssl_ctx(const char *ca_file) {
    ERR_clear_error();
    ssl_ctx = SSL_CTX_new(TLS_client_method());
    assert(ssl_ctx);


    int ctx_err = SSL_CTX_load_verify_file(ssl_ctx, ca_file);
    if (ctx_err <= 0) {
        return -1;
    }
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
    return ctx_err;
}

void io_uring_add_connect(int fd, struct sockaddr *sockaddr, size_t len, struct io_uring *ring, uint16_t conn_idx) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_connect(sqe, fd, sockaddr, len);
    io_uring_sqe_set_flags(sqe, 0);
    memset(&sqe->user_data, 0, sizeof(sqe->user_data));
    struct uring_user_data data = {
            .conn_idx = conn_idx,
            .req_type = CONNECT
    };
    memcpy(&sqe->user_data, &data, sizeof(data));
    struct ssl_conn* conn = &CONNECTIONS[conn_idx];
    conn->fd = fd;
    conn->ssl = NULL;
}

void process_cqe(struct io_uring_cqe *cqe, struct io_uring *ring) {
    struct uring_user_data  tag;
    memcpy(&tag, &cqe->user_data, sizeof(tag));
    __s32 res = cqe->res;
    if (res < 0) {
        fprintf(stderr, "error cqe res=%s tag.conn_id=%d tag.type =%d", strerror(res), tag.conn_idx, tag.req_type);
    }
    else {
        switch (tag.req_type) {
            case CONNECT: {
                struct ssl_conn *conn = &CONNECTIONS[tag.conn_idx];
                SSL *ssl = setup_tls_client(ssl_ctx, conn->host_name);
                conn->ssl = ssl;
                assert(conn->ssl && "could not create ssl");
                fprintf(stderr, "tcp connected %d %d \n", tag.conn_idx, tag.req_type);
                do_ssl_handshake(cqe, ring);
                break;
            }
            case HANDSHAKE_WRITE:
            case HANDSHAKE_READ: {
                int res = do_ssl_handshake(cqe, ring);
                if (res == 0) {
                    fprintf(stderr, "handshake competed \n");
                }
                break;
            }
            default: {
                fprintf(stderr, "unhandled event type %d , idx=%d \n", tag.req_type, tag.conn_idx);
            }

        }
    }

}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage %s HOST-ip PORT ca-certs-filename\n", argv[0]);
        return 1;
    }
    char *host_ip = argv[1];
    int port = atoi(argv[2]);
    const char *ca_file = argv[3];
    struct ssl_conn conn;

    int ctx_err = init_ssl_ctx(ca_file);

    if (ctx_err <= 0 ) {
        fprintf(stderr, "could not load trusted certs from %s\n", ca_file);
        return 1;
    }

    struct io_uring ring;
    memset(&ring, 0, sizeof(ring));
    int ret = setup_iouring(&ring);
    if (ret < 0 ) {
        fprintf(stderr, "unable to setup io uring \n");
        exit(1);
    }
    write_buff_pool = setup_fixed_buffers(&ring);
    setup_pooled_buffers(&ring, &READ_BUFFER_POOL);
    if (!write_buff_pool) {
        fprintf(stderr, "unable to setup fixed buffers \n");
        exit(1);
    }
    struct sockaddr_in addr_in;
    int sock_fd = setup_socket(host_ip, port, &addr_in);
    if (sock_fd < 0) {
        fprintf(stderr, "unable to create socket %s %d", host_ip, port);
        exit(1);
    }

    CONNECTIONS[1].fd = sock_fd;
    CONNECTIONS[1].host_name = "google.com";
    io_uring_add_connect(sock_fd, (struct sockaddr *) &addr_in, sizeof(addr_in), &ring, 1);
//    int connect_ret = connect(sock_fd, (struct sockaddr *) &addr_in, sizeof(addr_in));
//    if (connect_ret < 0 && errno != EINPROGRESS) {
//        fprintf(stderr, "Failed to connect socket %s %d err=%d", host_ip, port, connect_ret);
//        exit(1);
//    }

    struct io_uring_cqe *cqes[NCQES];
    while(1) {
        int ret = io_uring_submit_and_wait(&ring, 1);
        if (-EINTR == ret) continue;
        if (ret < 0) {
            fprintf(stderr, "error submit_wait failed %d\n", ret);
            break;
        }
        const int count = io_uring_peek_batch_cqe(&ring, &cqes[0], NCQES);
        for (int i = 0; i < count; i++) {
            struct io_uring_cqe *cqe = cqes[i];
            process_cqe(cqe, &ring);
        }
        io_uring_cq_advance(&ring, count);
    }
//    const SSL *ssl = conn.ssl;
//    while (!SSL_is_init_finished(ssl)) {
//        int ret = SSL_connect(ssl);
//        int ssl_err = SSL_get_error(ssl, ret);
//        if (ssl_err == SSL_ERROR_WANT_READ
//            || ssl_err == SSL_ERROR_WANT_WRITE
//            || ssl_pending_write(&conn)) {
//            BIO *write_bio = SSL_get_wbio(ssl);
//            int pending_bytes = BIO_pending(write_bio);
//            fprintf(stderr, "pending_bytes %d \n", pending_bytes);
//            char buff[2048];
//            int n = BIO_read(write_bio, buff, sizeof(buff));
//
//            send(sock_fd, buff, n, 0);
//            fprintf(stderr, "sent %d bytes \n", n);
//            if (SSL_want_read(ssl)) {
//            int read_bytes = recv(sock_fd, buff, sizeof(buff), 0);
//            fprintf(stderr, "received %d bytes \n", read_bytes);
//            if (read_bytes > 0) {
//                BIO *read_bio = SSL_get_rbio(ssl);
//                BIO_write(read_bio, buff, read_bytes);
//            }
//            }
//        }
//        else {
//            fprintf(stderr, "ssl state %s ssl_want_read=%d\n", SSL_state_string_long(ssl), SSL_want_read(ssl));
//            ERR_print_errors_fp(stderr);
//            break;
//        }
//        const char * current_state = SSL_state_string_long(ssl);
//        fprintf(stderr, "ssl state %s ssl_want_read=%d\n", current_state, SSL_want_read(ssl));
//    }
//    fprintf(stderr, "ssl state %s ssl_want_read=%d\n", SSL_state_string_long(ssl), SSL_want_read(ssl));


}