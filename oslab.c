#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

unsigned char sipbytes[4];
unsigned char dipbytes[4];

#define cvrt_ip(ip, byte)   bytes[0] = ip & 0xFF;\
                            bytes[1] = (ip >> 8) & 0xFF;\
                            bytes[2] = (ip >> 16) & 0xFF;\
                            bytes[3] = (ip >> 24) & 0xFF;  


/*hooking function*/
static unsigned int my_hook_fn_pre(void *priv,
                                    struct sk_buff *skb,
                                    const struct nf_hook_state *state) {
    struct iphdr *ih = ip_hdr(skb);
    struct tcphdr *th = tcp_hdr(skb);

    cvrt_ip(ih->saddr, sipbyte);
    cvrt_ip(ih->daddr, dipbyte);

    printk("PRE_ROUTING(%d:%hu:%hu:%d.%d.%d.%d:%d.%d.%d.%d)", ih->protocol, th->source, th->dest, 
                sipbytes[3], sipbytes[2], sipbytes[1], sipbytes[0], 
                dipbytes[3], dipbytes[2], dipbytes[1], dipbytes[0]);

    return NF_ACCEPT;
}

//after manipulating routing table...
static unsigned int my_hook_fn_forward(void *priv,
                                    struct sk_buff *skb,
                                    const struct nf_hook_state *state) {
    struct tcphdr *th = tcp_hdr(skb);
    struct iphdr *ih = ip_hdr(skb);
    if (th->source == 33333) {
        th->source = 7777;
        th->dest = 7777;

        cvrt_ip(ih->saddr, sipbyte);
        cvrt_ip(ih->daddr, dipbyte);

        printk("FORWARD_ROUTING(%d:%hu:%hu:%d.%d.%d.%d:%d.%d.%d.%d)", ih->protocol, th->source, th->dest, 
                    sipbytes[3], sipbytes[2], sipbytes[1], sipbytes[0], 
                    dipbytes[3], dipbytes[2], dipbytes[1], dipbytes[0]);


        return NF_ACCEPT;
    }
    else
        return NF_DROP;
}

static unsigned int my_hook_fn_post(void *priv,
                                    struct sk_buff *skb,
                                    const struct nf_hook_state *state) {
    struct iphdr *ih = ip_hdr(skb);
    struct tcphdr *th = tcp_hdr(skb);

    cvrt_ip(ih->saddr, sipbyte);
    cvrt_ip(ih->daddr, dipbyte);

    printk("POST_ROUTING(%d:%hu:%hu:%d.%d.%d.%d:%d.%d.%d.%d)", ih->protocol, th->source, th->dest, 
                sipbytes[3], sipbytes[2], sipbytes[1], sipbytes[0], 
                dipbytes[3], dipbytes[2], dipbytes[1], dipbytes[0]);

    return NF_ACCEPT;
}

/*hooking struct*/
static struct nf_hook_ops my_nf_ops_pre = {
    .hook = my_hook_fn_pre,
    .pf = PF_INET,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST
};

static struct nf_hook_ops my_nf_ops_forward = {
    .hook = my_hook_fn_forward,
    .pf = PF_INET,
    .hooknum = NF_INET_FORWARD,
    .priority = NF_IP_PRI_FIRST
};

static struct nf_hook_ops my_nf_ops_post = {
    .hook = my_hook_fn_post,
    .pf = PF_INET,
    .hooknum = NF_INET_POST_ROUTING,
    .priority = NF_IP_PRI_FIRST
};

/*init routine of module*/
static int __init init_mymodule(void) {
    nf_register_hook(&my_nf_ops_pre);
    nf_register_hook(&my_nf_ops_forward);
    nf_register_hook(&my_nf_ops_post);

    return 0;
}

static void __exit exit_mymodule(void) {
    nf_unregister_hook(&my_nf_ops_pre);
    nf_unregister_hook(&my_nf_ops_forward);
    nf_unregister_hook(&my_nf_ops_post);
}
module_init(init_mymodule);
module_exit(exit_mymodule);


MODULE_AUTHOR("sp11");
MODULE_DESCRIPTION("os netfilter packet forwarding");
MODULE_LICENSE("GPL");
MODULE_VERSION("NEW");
