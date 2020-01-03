
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include <netdb.h>
#include <fcntl.h>

/**
 * 与 socket_event.cpp 和 socket_server.cpp 一起进行调度测试
 */

int main()
{
    int cfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (cfd == -1) {
        printf("CHILD: socket failed(%d): %s\n", errno, strerror(errno));
        return -1;
    }
        
    struct sockaddr_in ssai, csai;
    char ip[32] = { 0 };
    memset(&ssai, 0, sizeof(ssai));
    ssai.sin_port = htons(8070);
    ssai.sin_addr.s_addr = inet_addr("10.0.80.121");
    ssai.sin_family = AF_INET;
        
    while (connect(cfd, (struct sockaddr*)&ssai, sizeof(struct sockaddr_in)) == -1 && errno != EISCONN) {
        if (errno != EINTR) {
            perror("connect");
            return -1;
        }
    }
    
    int on = 1;
    if (ioctl(cfd, FIONBIO, (const char *)&on) == -1) {
        close(cfd);
        return -1;
    }
    
    char buf[1024];
    int n, nbytes;
    int count = 5;
    
    sleep(2);
    
    return 0;
    
    for ( ; count--; ) {
        memset(buf, 0, sizeof(buf));
        n = snprintf(buf, 1024, "++++++++++ hello world from TCP-CLIENT %d ++++++++++", count);
        printf("send %d bytes: %s\n", n, buf);
        nbytes = send(cfd, buf, n, 0);
        if (nbytes == n) {
            printf("send %d bytes success\n", n);
        } else {
            continue;
        }
        
        // sleep(5);
    }
    
    return 0;
}