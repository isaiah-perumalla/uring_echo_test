#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <liburing/io_uring.h>
#include <liburing.h>
#include "uring_tls.h"


void prep_http_get(struct io_uring *uring, struct uring_user_data *data, struct ssl_conn *conn) {
    char *hostname = conn->host_name;
    char out_buf[512];
    snprintf(
            out_buf,
            512,
            "GET / HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Connection: close\r\n"
            "User-Agent: Example TLS client\r\n"
            "\r\n",
            hostname);
    int request_length = strlen(out_buf);
    int n = SSL_write(conn->ssl, out_buf, request_length);
    assert(n == request_length);
    void *buffer = get_buffer(WRITE_BUFFER_POOL, (*data).conn_idx);
    BIO *write_bio = SSL_get_wbio(conn->ssl);
    int read_bytes = BIO_read(write_bio, buffer, BUFFER_SIZE);
    prep_write(conn->fd, uring, (*data).conn_idx, DATA_WRITE, buffer, read_bytes);
}


void on_tls_handshake_complete(struct io_uring *uring, struct uring_user_data data) {
    struct ssl_conn *conn = &CONNECTIONS[data.conn_idx];
    prep_http_get(uring, &data, conn);
    prep_read(conn->fd, uring, DATA_READ, data.conn_idx);

}

void on_tls_handshake_failed(struct io_uring *ring, struct uring_user_data tag) {
    ERR_print_errors_fp(stderr);
    clean_up_connection(ring, (tag).conn_idx);
}

void on_data_recv(struct io_uring *uring, struct io_uring_cqe *cqe) {
    struct uring_user_data  data;
    memcpy(&data, &cqe->user_data, sizeof(data));
    struct ssl_conn *conn = &CONNECTIONS[data.conn_idx];
    int read_bytes = cqe->res;
    const unsigned short buf_idx = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
    void *buffer = buffer_pool_get(&READ_BUFFER_POOL, buf_idx);
    BIO *read_bio = SSL_get_rbio(conn->ssl);
    int written = BIO_write(read_bio, buffer, read_bytes);
    char out_buff[1024];
    for(int i = 0; i < written;) {
        int read = SSL_read(conn->ssl, out_buff, sizeof(out_buff)-1);

        if (read <= 0) {
            //ssl  record needs more data before decrypt so schedule another read
            prep_read(conn->fd, uring, DATA_READ, data.conn_idx);
            break;
        }
        out_buff[read] = '\0';
        i += read;
        fprintf(stderr, "%s", out_buff);
    }

}

void on_tcp_connect_failed(struct io_uring_cqe *cqe, struct io_uring *ring) {
    struct uring_user_data  tag;
    memcpy(&tag, &cqe->user_data, sizeof(tag));
    __s32 res = cqe->res;
    struct ssl_conn *conn = &CONNECTIONS[tag.conn_idx];
    fprintf(stderr, "TCP-CONNECT host_name=%s, error=[%s], [cqe res=%d tag.conn_idx=%d] \n",
            conn->host_name,
            strerror(res),
            cqe->res,
            tag.conn_idx);
}

void on_tcp_connect(struct io_uring_cqe *cqe, struct io_uring *ring) {
    struct uring_user_data  tag;
    memcpy(&tag, &cqe->user_data, sizeof(tag));
    struct ssl_conn *conn = &CONNECTIONS[tag.conn_idx];
    SSL *ssl = setup_tls_client(ssl_ctx, conn->host_name);
    conn->ssl = ssl;
    assert(conn->ssl && "could not create ssl");
    fprintf(stderr, "tcp connected %d %d \n", tag.conn_idx, tag.req_type);
    int ret = do_ssl_handshake(cqe, ring);
    if (ret == -1) {
        on_tls_handshake_failed(ring, tag);
        //handshake failed;
    }
}

void on_tcp_close(struct io_uring* ring, struct uring_user_data *tag) {
    struct ssl_conn *conn = &CONNECTIONS[(*tag).conn_idx];
    fprintf(stderr, "connection closed %d\n", conn->fd);
    conn->fd = -1;
}


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



int main(int argc, char* argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage %s HOST-ip PORT ca-certs-filename\n", argv[0]);
        return 1;
    }
    char *host_ip = argv[1];
    int port = atoi(argv[2]);
    const char *ca_file = argv[3];

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
    WRITE_BUFFER_POOL = setup_fixed_buffers(&ring);
    setup_pooled_buffers(&ring, &READ_BUFFER_POOL);
    if (!WRITE_BUFFER_POOL) {
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
    prep_connect(sock_fd, (struct sockaddr *) &addr_in, sizeof(addr_in), &ring, 1);

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

}