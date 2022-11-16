
#include <stdio.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <liburing.h>
#include <assert.h>

#define ENTRIES 1024

#define NO_FLAGS 0
#define BUFFERS_COUNT 16
#define MAX_MESSAGE_LEN 8

char buffers[BUFFERS_COUNT][MAX_MESSAGE_LEN] = {0};
int buffer_grp_id = 1337;
static struct io_uring ring;


int setup_listening_socket(int server);

static void add_read_sqe(int fd);


void submit_close_fd(struct io_uring* ring_ptr, int fd);

void set_user_data(int fd, int type, int buffer_id, struct io_uring_sqe *sqe);

void add_write(int fd, int nbytes, int buffer_id);

enum {
    ACCEPT = 1,
    READ,
    WRITE,
    PROV_BUF,
    CLOSED
};


typedef struct conn_info {
    __u32 fd;
    __u8 type;
    __u8 buffer_id;
} conn_info;


void sigint_handler(int signo) {
    printf("closing server.... %d\n", signo);
    io_uring_queue_exit(&ring);
    exit(0);
}
void add_accept_request(int fd,
                        struct sockaddr *sockaddr,
                        socklen_t *sockaddr_len) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_accept(sqe,
                         fd,
                         sockaddr,
                         sockaddr_len,
                         0);
    io_uring_sqe_set_flags(sqe, NO_FLAGS);
    // userdata to differentiate between accept CQEs and others
    conn_info conn_i = {
            .fd = fd,
            .type = ACCEPT,
    };
    memcpy(&sqe->user_data, &conn_i, sizeof(conn_i));

}

void server_loop(int server_socket) {
    struct io_uring_cqe *cqe;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_provide_buffers(sqe, buffers, MAX_MESSAGE_LEN, BUFFERS_COUNT, buffer_grp_id, 0);

    io_uring_submit(&ring);
    io_uring_wait_cqe(&ring, &cqe);
    if (cqe->res < 0) {
        printf("buffers not submitted, cqe->res = %d\n", cqe->res);
        exit(1);
    }
    io_uring_cqe_seen(&ring, cqe);

    // initial accept call
    add_accept_request(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);

    while(1) {
        fflush(stdout);
        fflush(stderr);
        printf("\nsubmit & wait \n");
        fflush(stdout);
        io_uring_submit_and_wait(&ring, 1);

        unsigned head;
        unsigned count = 0;

        io_uring_for_each_cqe(&ring, head, cqe) {
            ++count;
            struct conn_info conn_i;
            memcpy(&conn_i, &cqe->user_data, sizeof(conn_i));
            __s32 result = cqe->res;
            assert(cqe->user_data != 0);
            if (result == -ENOBUFS) {
                fprintf(stdout, "buffer error no usable buffers ...\n");
                fflush(stdout);
                exit(1);
            }
            if (result < 0) {
                fprintf( stderr,"fd=%d, type=%d, cqe error %d \n", conn_i.fd, conn_i.type, result);
                fflush(stderr);
                exit(1);
            }
            switch (conn_i.type) {
                case ACCEPT: {
                    int sock_conn_fd = result;
                    // only read when there is no error, > 0
                    if (sock_conn_fd >= 0) {
                        printf("\nsocket conn accepted fd=%d \n", sock_conn_fd);
                        sqe = io_uring_get_sqe(&ring);
                        strcpy((char*)&buffers[0], "hello");
                        io_uring_prep_send(sqe, sock_conn_fd, &buffers[0], 6, NO_FLAGS);
                        io_uring_sqe_set_flags(sqe, NO_FLAGS);
                        conn_info con = {
                                .fd = sock_conn_fd,
                                .type = WRITE,
                                .buffer_id = 0
                        };
                        memcpy(&sqe->user_data, &con, sizeof(con));
                    }
                    // new connected client; read data from socket and re-add accept to monitor for new connections
                    add_accept_request(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);
                    break;
                }
                case READ: {
                    int bytes_read = result;
                    int buffer_id = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
                    if (bytes_read > 0) {
                        //write back buffer
                        add_write(conn_i.fd, bytes_read, buffer_id);

                    } else {
                        //read failed close conn
                        struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
                        io_uring_prep_provide_buffers(sqe, buffers[buffer_id], MAX_MESSAGE_LEN, 1,
                                                      buffer_grp_id, buffer_id);
                        set_user_data(conn_i.fd, PROV_BUF, buffer_id, sqe);
                        submit_close_fd(&ring, conn_i.fd);

                        printf("read request, failed closing connection fd=%d, current_cqe->res=%d \n", conn_i.fd, result);
                        fflush(stdout);
                    }
                    printf("READ");
                    break;
                }
                case WRITE: {
                    //write completed
                    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
                    __u16 buffer_id = conn_i.buffer_id;
                    io_uring_prep_provide_buffers(sqe, buffers[buffer_id], MAX_MESSAGE_LEN, 1,
                                                  buffer_grp_id, buffer_id);
                    io_uring_sqe_set_flags(sqe, 0);
                    conn_info info = {
                            .fd = conn_i.fd,
                            .type = PROV_BUF
                    };
                    memcpy(&sqe->user_data, &info, sizeof(info));
                    printf("returning provide buffer_id=%d after write -> fd=%d\n", buffer_id, conn_i.fd);
                    add_read_sqe(conn_i.fd);

                    printf("WRITE");
                    break;
                }
                case PROV_BUF: {
                    if (result < 0) {
                        fprintf(stderr, "PROV_BUF current_cqe->res=%d", result);
                        fflush(stderr);
                        exit(1);
                    }
                    printf("PROV_BUF buffer_id=%d, for fd=%d \n", conn_i.buffer_id, conn_i.fd);
                    printf("PROV");
                    break;
                }
                case CLOSED: {
                    printf("closed fd=%d", conn_i.fd);
                    printf("CLOSED");
                    break;
                }
                default: {
                    fprintf(stderr, "unknow cqe %d", conn_i.fd);
                    fflush(stderr);
                    printf("default");
                }
            }
        }
        io_uring_cq_advance(&ring, count);
    }
}

void add_write(int fd, int nbytes, int buffer_id) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_send(sqe, fd, &buffers[buffer_id], nbytes, 0);
    io_uring_sqe_set_flags(sqe, 0);

    conn_info conn_i = {
            .fd = fd,
            .type = WRITE,
            .buffer_id = buffer_id,
    };
    memcpy(&sqe->user_data, &conn_i, sizeof(conn_i));

}

void set_user_data(int fd, int type, int buffer_id, struct io_uring_sqe *sqe) {
    conn_info info = {
            .fd = fd,
            .type = type,
            .buffer_id = buffer_id
    };
    size_t n = sizeof(info);
    assert(n <= 8);
    memcpy(&sqe->user_data, &info, n);
}

void submit_close_fd(struct io_uring* ring, int fd) {
    struct io_uring_sqe *close_sqe = io_uring_get_sqe(ring);
    set_user_data(fd, CLOSED, 0, close_sqe);
    io_uring_prep_close(close_sqe, fd);
    io_uring_submit(ring);
}

static void add_read_sqe(int fd) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_recv(sqe, fd, NULL, MAX_MESSAGE_LEN, 0);
    io_uring_sqe_set_flags(sqe, IOSQE_BUFFER_SELECT);
    sqe->buf_group = buffer_grp_id;

    conn_info conn_i = {
            .fd = fd,
            .type = READ,
    };
    memcpy(&sqe->user_data, &conn_i, sizeof(conn_i));
    assert(sizeof(conn_i) <= 8);
    printf("added read sqe fd=%d", fd);
    fflush(stdout);

}


int main(){
    struct io_uring_params params;
    int server_socket;



    memset(&params, 0, sizeof(params));
//    params.flags |= IORING_SETUP_SQPOLL;
    params.sq_thread_idle = 120000; // 2 minutes in ms

    io_uring_queue_init_params(ENTRIES, &ring, &params);

    if (!(params.features & IORING_FEAT_FAST_POLL)) {
        printf("IORING_FEAT_FAST_POLL not available in the kernel, quiting...\n");
        exit(0);
    }
    signal(SIGINT, sigint_handler);
    int port = 8001;
    printf("server starting on port %d", port);
    server_socket = setup_listening_socket(port);
    printf("server listening on port %d server_socket_fd=%d", port, server_socket);
    fflush(stdout);
    // check if buffer selection is supported
    struct io_uring_probe *probe;
    probe = io_uring_get_probe_ring(&ring);
    if (!probe || !io_uring_opcode_supported(probe, IORING_OP_PROVIDE_BUFFERS)) {
        printf("Buffer select not supported, skipping...\n");
        exit(0);
    }
    free(probe);

    server_loop(server_socket);
}

int setup_listening_socket(int port) {
    // setup socket
    int sock_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    const int val = 1;
    setsockopt(sock_listen_fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    serv_addr.sin_addr.s_addr = INADDR_ANY;

    // bind and listen
    if (bind(sock_listen_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Error binding socket...\n");
        exit(1);
    }
    if (listen(sock_listen_fd, 32) < 0) {
        perror("Error listening on socket...\n");
        exit(1);
    }
    return sock_listen_fd;
}