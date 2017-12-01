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

    printk("PRE_ROUTING(%c:%hd:%hd:%u:%u)", ih->protocol, th->source, th->dest, ih->saddr, ih->daddr);

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
        printk("FORWARD_ROUTING(%c:%hd:%hd:%u:%u)", ih->protocol, th->source, th->dest, ih->saddr, ih->daddr);

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
    printk("POST_ROUTING(%c:%hd:%hd:%u:%u)", ih->protocol, th->source, th->dest, ih->saddr, ih->daddr);

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
    .priority = NF_IP_PRI_FIRST
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

MODULE_AUTHOR("sp11");
MODULE_DESCRIPTION("os netfilter packet forwarding");
MODULE_LICENSE("GPL");
MODULE_VERSION("NEW");
