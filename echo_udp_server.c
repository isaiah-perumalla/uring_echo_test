//
// Created by isaiahp on 10/24/22.
//
#include <stdio.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <liburing.h>
#include <assert.h>
#include <sys/mman.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#define ENTRIES 32
#define NBUFFERS 16
#define BUFFER_SIZE 2048

#define NCQES ENTRIES * 4

struct sendmsg_ctx {
    struct msghdr msg;
    struct iovec iov;
};
struct buffer_pool {
    unsigned int nbuffers;
    unsigned int buff_size;
    struct io_uring_buf_ring* buff_ring;
};

struct sendmsg_ctx SEND_BUFFERS_CTX[NBUFFERS];

//register usespace buffers into the kernel
int setup_pooled_buffers(struct io_uring *pUring, struct buffer_pool* buff_pool) {

    const unsigned int buffer_size = buff_pool->buff_size;
    const unsigned int nbuffers = buff_pool->nbuffers;
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
    int result = io_uring_register_buf_ring(pUring, &buf_reg, 0);
    if (result) {
        fprintf(stderr, "failed to register_buf_ring %s \n", strerror(-result));
        return result;
    }
    unsigned char *buffers_base = (unsigned char *) buff_ring + (sizeof(struct io_uring_buf) * nbuffers);
    for(unsigned int i = 0; i < nbuffers; i++) {
        void *buffer_i = buffers_base + (buffer_size * i);
        io_uring_buf_ring_add(buff_ring, buffer_i, buffer_size, i, io_uring_buf_ring_mask(nbuffers), i);
//        io_uring_buf_ring_add()
    }
    io_uring_buf_ring_advance(buff_ring, nbuffers);
    buff_pool->buff_ring = buff_ring;
    return 0;
}

//create udp sock and bind to @port
static int setup_sock(int port) {
    if (port <= 0) {
        fprintf(stderr, "invalid port %d \n", port);
        return -1;
    }
    //port in network byte order
    uint16_t  nport = htons(port);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        fprintf(stderr, "unable to create socket on port %d\n", port);
        return -1;
    }
    struct sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_port = nport,
            .sin_addr = {INADDR_ANY}
    };
    int err = bind(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (err) {
        fprintf(stderr, "cannot bind socket errno=%s\n", strerror(errno));
        return -1;
    }
    return fd;
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

struct request_data {
    __u32 fd_idx;
    __u16 buf_idx;
    __u8 type;
};
enum {
    RECV = 1,
    SEND
};

int add_recv_sqe(struct io_uring *pUring, unsigned int fd_idx, struct msghdr* msg) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(pUring);
    if (!sqe) {
        return -1;
    }
    io_uring_prep_recvmsg_multishot(sqe, fd_idx, msg, MSG_TRUNC);
    sqe->flags = IOSQE_FIXED_FILE | IOSQE_BUFFER_SELECT;
    sqe->buf_group = 0;
    struct request_data req = {
            .fd_idx = fd_idx,
            .type = RECV
    };
    memcpy(&sqe->user_data, &req, sizeof(req));
    return 0;
}
static unsigned char* buffer_pool_get(struct buffer_pool* pool, unsigned int idx) {
    unsigned char *buff_base = (unsigned char *) pool->buff_ring +
                               sizeof(struct io_uring_buf) * pool->nbuffers;
    return buff_base + (idx * pool->buff_size);
}

static void init_msg_hdr(struct msghdr* msg) {
    memset(msg, 0, sizeof(*msg));
    msg->msg_namelen = sizeof(struct sockaddr_storage);
    msg->msg_controllen = 0;
}

void buffer_pool_release(struct buffer_pool *pPool, unsigned short idx) {
    void *buffer = buffer_pool_get(pPool, idx); //base address of buffer at idx
    int mask = io_uring_buf_ring_mask(pPool->nbuffers);
    io_uring_buf_ring_add(pPool->buff_ring, buffer, pPool->buff_size, idx, mask, 0 );
    io_uring_buf_ring_advance(pPool->buff_ring, 1);
}

int process_recv_msg(struct io_uring_cqe *cqe, struct io_uring *uring, unsigned int fd_idx, struct buffer_pool *buf_pool) {
    __u32 flags = cqe->flags;
    if ((flags & IORING_CQE_F_BUFFER) == 0) {
        //buffer-id not preset
        fprintf(stderr, "IORING_CQE_F_BUFFER not set check kernel version >= 6.0 \n");
        return -1;
    }
    if (!(cqe->flags & IORING_CQE_F_MORE)) {
        struct msghdr msg;
        init_msg_hdr(&msg);
        int err = add_recv_sqe(uring, fd_idx, &msg);
        if (err) {
            return -1;
        }
    }
    unsigned short buf_idx = flags >> 16;
    void *buffer = buffer_pool_get(buf_pool, buf_idx);
    struct msghdr msg_hdr;
    init_msg_hdr(&msg_hdr);
    struct io_uring_recvmsg_out *out = io_uring_recvmsg_validate(buffer, cqe->res, &msg_hdr);
    if (!out) {
        fprintf(stderr, "invalid recvmsg \n");
        return -1;
    }
    if (out->namelen > msg_hdr.msg_namelen) {
        fprintf(stderr, "truncated name msg_hdr hdr \n");
        buffer_pool_release(buf_pool, buf_idx);
        return 0;
    }
    char char_buff[INET6_ADDRSTRLEN + 1];
    struct sockaddr_in *addr = io_uring_recvmsg_name(out);
    const char *name = inet_ntop(AF_INET, addr, char_buff, sizeof(char_buff));
    unsigned int bytes_read = io_uring_recvmsg_payload_length(out, cqe->res, &msg_hdr);
    printf("received %u bytes from %s port:%d\n", bytes_read, name, ntohs(addr->sin_port));
    fflush(stdout);
    struct io_uring_sqe *sqe = io_uring_get_sqe(uring);
    if (!sqe) {

    }
    struct sendmsg_ctx sendmsg_buf_ctx = SEND_BUFFERS_CTX[buf_idx];
    sendmsg_buf_ctx.iov = (struct iovec) {
        .iov_base = io_uring_recvmsg_payload(out, &msg_hdr),
        .iov_len = bytes_read
    };
    sendmsg_buf_ctx.msg = (struct msghdr) {
        .msg_namelen = out->namelen,
        .msg_name = io_uring_recvmsg_name(out),
        .msg_control = NULL,
        .msg_controllen = 0,
        .msg_iov = &sendmsg_buf_ctx.iov,
        .msg_iovlen = 1
    };

    io_uring_prep_sendmsg(sqe, fd_idx, &sendmsg_buf_ctx.msg, 0);
    struct request_data req = {
            .fd_idx = fd_idx,
            .buf_idx = buf_idx,
            .type = SEND
    };
    memcpy(&sqe->user_data, &req, sizeof(req));
    sqe->flags = IOSQE_FIXED_FILE;

    return 0;
}


int main(int argc, char* argv[]) {

    if (argc != 2) {
        fprintf(stderr, "provide port number \n");
        exit(1);
    }
    int port = atoi(argv[1]);
    int sockfd = setup_sock(port);
    if (sockfd < 0) {
        fprintf(stderr, "couldnt create socket on port %d \n", port);
        exit(1);
    }
    struct io_uring ring;
    int result = setup_iouring(&ring);

    if (result < 0) {
        fprintf(stderr, "io_uring init failed %s \n", strerror(-result));
        close(sockfd);
        exit(1);
    }
    struct buffer_pool buf_pool = {
            .nbuffers = NBUFFERS,
            .buff_size = BUFFER_SIZE,
            .buff_ring = NULL
    };
    if (setup_pooled_buffers(&ring, &buf_pool)) {
        fprintf(stderr, "failed to init pooled buffers \n");
    }
    assert(buf_pool.buff_ring != NULL);
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_namelen = sizeof(struct sockaddr_storage);
    msg.msg_controllen = 0;

    int err = io_uring_register_files(&ring, &sockfd, 1); // pre-register the udp sock fd
    if (err) {
        fprintf(stderr, "io_uring_register_files failed sockfd=%d err=%s", sockfd, strerror(result));
        exit(1);
    }

    result = add_recv_sqe(&ring, 0, &msg);
    if (result) {
        fprintf(stderr, "failed to send recv from socket \n");
        exit(1);
    }

    struct io_uring_cqe *cqes[NCQES];
    while(1) {
        int ret = io_uring_submit_and_wait(&ring, 1);
        if (-EINTR == ret) continue;

        if (ret < 0) {
            fprintf(stderr, "error submit_wait failed %d\n", ret);
            break;
        }
        const int count = io_uring_peek_batch_cqe(&ring, &cqes[0], NCQES);

        for(int i =0; i < count; i++) {
            struct io_uring_cqe *cqe = cqes[i];
            if (cqe->res == -ENOBUFS) {
                fprintf(stderr, "NO BUFFS NOBUFS\n");
                continue;
            }
            if (cqe->res < 0) {
                fprintf(stderr, "error cqe->res = %s\n", strerror(cqe->res));
                continue;
            }
            struct request_data req_data;
            memcpy(&req_data, &cqe->user_data,  sizeof(req_data));
            switch (req_data.type) {
                case RECV: {
                    process_recv_msg(cqe, &ring, 0, &buf_pool);
                    break;
                }
                case SEND: {
                    //send completed release buffer back to pool
//                    printf("send completed on buffer=%d\n", req_data.buf_idx);
//                    fflush(stdout);
                    buffer_pool_release(&buf_pool, req_data.buf_idx);
                    break;
                }

                default: {
                    printf("received type %d \n", req_data.type);
                    fflush(stdout);
                }
            }
        }
        io_uring_cq_advance(&ring, count);
    }
    printf("sockfd=%d \n", sockfd);
    close(sockfd);
}


