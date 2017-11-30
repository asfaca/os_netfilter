#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>

/*hooking function*/
static unsigned int my_hook_fn_pre(void *priv,
                                    struct sk_buff *skb,
                                    const struct nf_hook_state *state) {
    struct iphdr *ih = ip_hdr(skb);
    struct tcphdr *th = tcp_hdr(skb);
    __u8 prot = ih->Protocol;   //__u8 = unsigned char
    __be32 sip = ih->saddr;     //__be32 = unsigned int
    __be32 dip = ih->daddr;
    __be16 sport = th->source;  //__be16 = unsigned short
    __be16 dport = th->dest;

    printk("PRE_ROUTING(%c:%hd:%hd:%u:%u)", prot, sport, dport, sip, dip);

    return NF_ACCEPT;
}

//after manipulating routing table...
static unsigned int my_hook_fn_forward(void *priv,
                                    struct sk_buff *skb,
                                    const struct nf_hook_state *state) {
    struct tcphdr *th = tcp_hdr(skb);
    if (th->source == 33333) {
        th->source = 7777;
        th->dest = 7777;

        struct iphdr *ih = ip_hdr(skb);
        __u8 prot = ih->Protocol;   //__u8 = unsigned char
        __be32 sip = ih->saddr;     //__be32 = unsigned int
        __be32 dip = ih->daddr;
        __be16 sport = th->source;  //__be16 = unsigned short
        __be16 dport = th->dest;

        printk("FORWARD_ROUTING(%c:%hd:%hd:%u:%u)", prot, sport, dport, sip, dip);

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
    __u8 prot = ih->Protocol;   //__u8 = unsigned char
    __be32 sip = ih->saddr;     //__be32 = unsigned int
    __be32 dip = ih->daddr;
    __be16 sport = th->source;  //__be16 = unsigned short
    __be16 dport = th->dest;

    printk("POST_ROUTING(%c:%hd:%hd:%u:%u)", prot, sport, dport, sip, dip);

    return NF_ACCEPT;
}

/*hooking struct*/
static struct nf_hook_ops my_nf_ops_pre {
    .hook = my_hook_fn_pre,
    .pf = PF_INET,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST
};

static struct nf_hook_ops my_nf_ops_forward {
    .hook = my_hook_fn_forward,
    .pf = PF_INET,
    .hooknum = NF_INET_FORWARD,
    .priority = NF_IP_PRI_FIRST
};

static struct nf_hook_ops my_nf_ops_post {
    .hook = my_hook_fn_post,
    .pf = PF_INET,
    .hooknum = NF_INET_POST_ROUTING,
    .priority = 9999
};

/*init routine of module*/
static int __init init_mymodule(void) {
    nf_register_hook(&my_nf_ops_pre);
    nf_register_hook(&my_nf_ops_forward);
    nf_register_hook(&my_nf_ops_post);
}

static int __exit exit_mymodule(void) {
    nf_unregister_hook(&my_nf_ops_pre);
    nf_unregister_hook(&my_nf_ops_forward);
    nf_unregister_hook(&my_nf_ops_post);
}
