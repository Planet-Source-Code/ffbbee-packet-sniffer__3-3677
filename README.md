<div align="center">

## Packet sniffer


</div>

### Description

This code shows the source ip and port the flags of the packet and the sequence number
 
### More Info
 


<span>             |<span>
---                |---
**Submitted On**   |
**By**             |[ffbbee](https://github.com/Planet-Source-Code/PSCIndex/blob/master/ByAuthor/ffbbee.md)
**Level**          |Beginner
**User Rating**    |3.7 (11 globes from 3 users)
**Compatibility**  |C
**Category**       |[Internet/ Browsers/ HTML](https://github.com/Planet-Source-Code/PSCIndex/blob/master/ByCategory/internet-browsers-html__3-9.md)
**World**          |[C / C\+\+](https://github.com/Planet-Source-Code/PSCIndex/blob/master/ByWorld/c-c.md)
**Archive File**   |[](https://github.com/Planet-Source-Code/ffbbee-packet-sniffer__3-3677/archive/master.zip)





### Source Code

```

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
int main(int argc, char *argv[])
{
    int s, bytes,a=0,sy=0,f=0,r=0,u=0,p=0;
	int     ac=0,syc=0,fc=0,rc=0;
    struct tcphdr *tcp;
    struct iphdr  *ip;
    struct in_addr addr;
    char      buffer[4000];
    s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (s == -1)
    {
        perror("socket() failed");
        return 1;
    }
    ip = (struct iphdr*) buffer;
    tcp = (struct tcphdr*) (buffer + sizeof(struct iphdr));
    while( (bytes = recv(s, buffer, sizeof(buffer), 0)) > 0)
    {
        addr.s_addr = ip->saddr;
		a=ntohs(tcp->ack);
		sy=ntohs(tcp->syn);
		r=ntohs(tcp->rst);
		f=ntohs(tcp->fin);
		p=ntohs(tcp->psh);
		u=ntohs(tcp->urg);
	if (ip->saddr!=inet_addr("192.168.0.113"))
	{
	printf("Packet from source:%s\nwith flags ->",inet_ntoa(addr));
	if(a==256)
	{
	printf("Ack ");
	}
	if ( sy==256)
	{printf("Syn ");
	;}
	if (f==256)
	{
	printf("Fin ");
	}
	if (r==256)
	{
	printf("Rst ");
	}
	if (p==256)
	{
	printf("Psh ");
	}
	if (u==256)
	{
	printf("Urg");
	}
	printf("\n");
	printf("With the sequence number of ->%i\n",ntohl(tcp->seq));
	printf("From port->%i\n\n",ntohs(tcp->source));
	}
    }
    if (bytes == -1)
    {
        perror("recv() failed");
        return 2;
    }
    return 0;
}
```

