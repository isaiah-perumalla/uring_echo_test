//
// Created by isaiahp on 11/18/22.
//

#ifndef URING_ECHO_TEST_URING_TLS_H
#define URING_ECHO_TEST_URING_TLS_H

#include <netinet/udp.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <liburing.h>
#include <liburing/io_uring.h>
#include <fcntl.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#define ENTRIES 1024
#define BUFFER_SIZE 2048
#define NCQES (ENTRIES * 4)
#define MAX_CONNS 16
#define NBUFFERS 16

SSL_CTX* ssl_ctx = NULL;

struct uring_user_data {
    __u16 conn_idx;
    __u8 req_type;
};

enum {
    CONNECT = 1,
    HANDSHAKE_WRITE,
    HANDSHAKE_READ,
    DATA_WRITE,
    DATA_READ,
    CONNECTION_CLOSED
};


struct ssl_conn {
    int fd;
    SSL *ssl;
    char* host_name;
};

struct read_buff_pool {
    unsigned int nbuffers;
    unsigned int buff_size;
    struct io_uring_buf_ring* buff_ring;
};


static struct ssl_conn CONNECTIONS[MAX_CONNS];


static struct read_buff_pool READ_BUFFER_POOL;
static void* WRITE_BUFFER_POOL = NULL;

static void *get_buffer(void *mem, __u16 idx) {
    void *buff = mem + (idx * BUFFER_SIZE);
    return buff;
}


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

SSL* setup_tls_client(SSL_CTX *ctx, char *hostname) {
    BIO *read_bio = BIO_new(BIO_s_mem());
    assert(read_bio);
    BIO *write_bio = BIO_new(BIO_s_mem());
    assert(write_bio);
    BIO_set_mem_eof_return(read_bio, -1);
    BIO_set_mem_eof_return(write_bio, -1);
    SSL *ssl = SSL_new(ctx);
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



void on_tls_handshake_complete(struct io_uring *uring, struct uring_user_data data);

void on_tls_handshake_failed(struct io_uring *ring, struct uring_user_data tag);

void on_data_recv(struct io_uring *uring, struct io_uring_cqe *cqe);

void on_tcp_connect_failed(struct io_uring_cqe *cqe, struct io_uring *ring);

void on_tcp_connect(struct io_uring_cqe *cqe, struct io_uring *ring);

void on_tcp_close(struct io_uring* ring, struct uring_user_data *tag);

void prep_connect(int fd, struct sockaddr *sockaddr, size_t len, struct io_uring *ring, uint16_t conn_idx) {
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
        int read_bytes = cqe->res;
        const unsigned short buf_idx = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
        void *buffer = buffer_pool_get(&READ_BUFFER_POOL, buf_idx);
        BIO *read_bio = SSL_get_rbio(ssl);

        int written = BIO_write(read_bio, buffer, read_bytes);
        assert(written > 0 && "write bytes");
        buffer_pool_release(&READ_BUFFER_POOL, buf_idx);
    }

    int ret = SSL_connect(ssl);
    int ssl_err = SSL_get_error(ssl, ret);
    BIO *write_bio = SSL_get_wbio(ssl);
    if (ssl_err == SSL_ERROR_WANT_WRITE || ssl_err == SSL_ERROR_WANT_READ
        || BIO_pending(write_bio)) {
        const int pending_bytes = BIO_pending(write_bio);
        if (pending_bytes > 0) {
            assert(pending_bytes > 0 && "pending bytes 0");
            void *buffer = get_buffer(WRITE_BUFFER_POOL, conn_idx);
            int n = BIO_read(write_bio, buffer, BUFFER_SIZE);
            prep_write(conn->fd, ring, conn_idx, HANDSHAKE_WRITE, buffer, n);
        }
        else if (ssl_err == SSL_ERROR_WANT_READ) {
            prep_read(conn->fd, ring, HANDSHAKE_READ, conn_idx);
        }
    }
    else {
        fprintf(stderr, "ssl_err=%d, ssl state %s ssl_want_read=%d\n",
                ssl_err, SSL_state_string_long(ssl),
                SSL_want_read(ssl));
        return -1;
    }
    return 1;
}

void submit_close_fd(struct io_uring* ring, int conn_idx) {
    struct ssl_conn *conn = &CONNECTIONS[conn_idx];
    struct io_uring_sqe *close_sqe = io_uring_get_sqe(ring);
    struct uring_user_data user_data = {
            .conn_idx = conn_idx,
            .req_type = CONNECTION_CLOSED
    };
    memcpy(&close_sqe->user_data, &user_data, sizeof(user_data));
    io_uring_prep_close(close_sqe, conn->fd);
    io_uring_submit(ring);
}


void clean_up_connection(struct io_uring* ring, int conn_idx) {
    struct ssl_conn *conn = &CONNECTIONS[conn_idx];
    if (conn->ssl) {
        SSL_free(conn->ssl);
        conn->ssl = NULL;
    }
    submit_close_fd(ring, conn_idx);

}


int setup_iouring(struct io_uring *ring) {
    struct io_uring_params params;
    memset(&params, 0, sizeof(params));
    memset(ring, 0, sizeof((*ring)));
    params.cq_entries = NCQES;
    params.flags = IORING_SETUP_COOP_TASKRUN  //ensure kernel doesnt interrup user thread, use this in single thread mode
                   | IORING_SETUP_SUBMIT_ALL  // dont stop submit entries when error
                   | IORING_SETUP_CQSIZE; // pre-fill a buffer for cqe(s)
    int result = io_uring_queue_init_params(ENTRIES, ring, &params);
    return result;
}

void process_cqe(struct io_uring_cqe *cqe, struct io_uring *ring) {
    struct uring_user_data  tag;
    memcpy(&tag, &cqe->user_data, sizeof(tag));
    __s32 res = cqe->res;

    switch (tag.req_type) {
        case CONNECT: {

            if (res < 0) {
                on_tcp_connect_failed(cqe, ring);
            }
            else {
                on_tcp_connect(cqe, ring);
            }
            break;
        }
        case HANDSHAKE_WRITE:
        case HANDSHAKE_READ: {
            int ret = do_ssl_handshake(cqe, ring);
            if (ret == 0) {
                fprintf(stderr, "handshake competed \n");
                on_tls_handshake_complete(ring, tag);
            }
            if (ret == -1) {
                on_tls_handshake_failed(ring, tag);
                //handshake failed;
            }
            break;
        }
        case DATA_READ: {
            on_data_recv(ring, cqe);
            break;
        }
        case CONNECTION_CLOSED: {
            on_tcp_close(ring, &tag);
            break;
        }
        default: {
            fprintf(stderr, "unhandled event type %d , idx=%d \n", tag.req_type, tag.conn_idx);
        }
    }
}




#endif //URING_ECHO_TEST_URING_TLS_H
