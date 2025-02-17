//netlink知识整理。

#include <linux/module.h>#include <linux/kernel.h>#include <linux/init.h>#include <net/sock.h>#include <asm/types.h>#include <linux/netlink.h>#include <linux/skbuff.h>
#define NETLINK_XUX           31       /* testing */  
static struct sock *ycp_sock = NULL;
 
// 接收消息的回调函数，接收参数是 sk_buff
static void recv_netlink(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    nlh = nlmsg_hdr(skb); // 取得消息体 通过nlmsg_hdr 将skb中的nlh对应的消息取出来。
    printk("receive data from user process: %s", (char *)NLMSG_DATA(nlh)); // 打印接收的数据内容
 
    ...
}
 
int __init init_link(void)
{
    struct netlink_kernel_cfg cfg = {
		.input = recv_netlink,
	};
    ycp_sock = netlink_kernel_create(&init_net, NETLINK_XUX, &cfg); // 创建内核 socket NETLINK_XUX是自己定义的NETLINK协议号。
    if (!ycp_sock){
        printk("cannot initialize netlink socket");
        return -1;
    }
    
    printk("Init OK!\n");
    return 0;
}


... // 上面的就省了
#define NETLINK_USER 31  //self defined
#define MAX_PAYLOAD 1024 /* maximum payload size*/
struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh = NULL;
struct msghdr msg;
struct iovec iov;
int sock_fd;
 
int main(int args, char *argv[])
{
    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER); // 建立 socket//与内核协议号一致
 
    if(sock_fd < 0)
        return -1;
 
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;//固定netlink协议
    src_addr.nl_pid = getpid(); /* 当前进程的 pid */
 
    if(bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr))){ // 和指定协议进行 socket 绑定
        perror("bind() error\n");
        close(skfd);
        return -1;
    }
 
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;       /* For Linux Kernel */
    dest_addr.nl_groups = 0;    /* unicast */// 1 为broadcast地址
 
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid();  //self pid用户态的pid号
    nlh->nlmsg_flags = 0;
    // 拷贝信息到发送缓冲中
    strcpy(NLMSG_DATA(nlh), "Hello this is a msg from userspace");//NLMSG是一个函数获取nlh数据指针。
    // 构造发送消息体
    iov.iov_base = (void *)nlh;         //iov -> nlh
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;  // iov 中存放 netlink 消息头和消息数据
    msg.msg_iovlen = 1;
 
    printf("Sending message to kernel\n");
 
    int ret = sendmsg(sock_fd, &msg, 0);  // 发送消息到内核
    printf("send ret: %d\n", ret);
 
    printf("Waiting for message from kernel\n");
 
    /* 从内核接收消息 */
    recvmsg(sock_fd, &msg, 0);
    printf("Received message payload: %s\n", NLMSG_DATA(nlh));  // 打印接收到的消息
 
    close(sock_fd);
    return 0;
}