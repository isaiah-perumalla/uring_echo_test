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

#define ENTRIES 32
#define NBUFFERS ENTRIES
#define BUFFER_SIZE 1024

struct buffer_pool {
    unsigned int nbuffers;
    unsigned int buff_size;
    struct io_uring_buf_ring* buff_ring;
};



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
    for(int i = 0; i < nbuffers; i++) {
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
    struct io_uring_cqe *cqes[ENTRIES * 4];
    params.cq_entries = ENTRIES * 4;
    params.flags = IORING_SETUP_COOP_TASKRUN  //ensure kernel doesnt interrup user thread, use this in single thread mode
                   | IORING_SETUP_SUBMIT_ALL  // dont stop submit entries when error
                   | IORING_SETUP_CQSIZE; // pre-fill a buffer for cqe(s)
    int result = io_uring_queue_init_params(ENTRIES, ring, &params);
    return result;
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
    printf("sockfd=%d \n", sockfd);
    struct buffer_pool buf_pool = {
            .nbuffers = NBUFFERS,
            .buff_size = BUFFER_SIZE,
            .buff_ring = NULL
    };
    if (setup_pooled_buffers(&ring, &buf_pool)) {
        fprintf(stderr, "failed to init pooled buffers \n");
    }
    assert(buf_pool.buff_ring != NULL);

}


