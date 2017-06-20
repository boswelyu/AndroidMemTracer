#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <utils/logger.h>

#define MYPORT 7788
char* SERVERIP = "127.0.0.1";

int main(void)
{
    int sock;
    if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
    {
    	LOGE("Create Socket Failed!");
    	return -1;
    }
        

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(MYPORT);
    servaddr.sin_addr.s_addr = inet_addr(SERVERIP);

    int ret;
    char sendbuf[256] = {0};
    char recvbuf[1024] = {0};
    while (fgets(sendbuf, sizeof(sendbuf), stdin) != NULL)
    {
        sendto(sock, sendbuf, strlen(sendbuf), 0, (struct sockaddr *)&servaddr, sizeof(servaddr));

        //ret = recvfrom(sock, recvbuf, sizeof(recvbuf), 0, NULL, NULL);
        //if (ret == -1)
        //{
        //    if (errno == EINTR)
        //        continue;
        //    ERR_EXIT("recvfrom");
        //}
        //printf("Received from server: %s\n",recvbuf);

        memset(sendbuf, 0, sizeof(sendbuf));
        //memset(recvbuf, 0, sizeof(recvbuf));
    }

    close(sock);

    return 0;
}

