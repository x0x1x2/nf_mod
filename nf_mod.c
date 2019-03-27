#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/ip.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("YS");
MODULE_DESCRIPTION("NF ex");
MODULE_VERSION("0.1"); 

/*  
 *  This module uses /dev/testdevice.  The MODULE_SUPPORTED_DEVICE macro might
 *  be used in the future to help automatic configuration of modules, but is 
 *  currently unused other than for documentation purposes.
 */
MODULE_SUPPORTED_DEVICE("testdevice");


unsigned int  my_http_helper (unsigned char *pdata, int data_len);


static struct nf_hook_ops nfho;

unsigned int hook_func(
	void *priv,
	struct sk_buff *skb,
	const struct nf_hook_state *state) 
{
    struct iphdr    * iph;
    struct tcphdr   * tcph;
    unsigned char* pdata;
    int data_len;
    if (skb) {
        iph = ip_hdr(skb);

        if (iph && iph->protocol && (iph->protocol == IPPROTO_TCP)) {
            tcph = (struct tcphdr *)((__u32 *)iph + iph->ihl);
            
            if(skb_linearize(skb)<0){
		printk("[YS] Not Linearizable \n");
		return NF_ACCEPT;	
	    }
           
            data_len = ntohs(iph->tot_len)-ip_hdrlen(skb)-(tcph->doff * 4);
            pdata = (unsigned char *)tcph + (tcph->doff * 4);
	    if (data_len > 0 )
	    {
	      printk("[YS] len = %d \n",data_len);
	      return my_http_helper(pdata, data_len); 
	    }
	    
        }
    }

    return NF_ACCEPT;
}

int init_module() {
    int result;

    nfho.hook   = (nf_hookfn *) hook_func;
    nfho.hooknum    = NF_INET_LOCAL_OUT; /* Packets coming from a local process. */
    //nfho.hooknum    = NF_INET_POST_ROUTING; /* Packets about to hit the wire. */

    
    nfho.pf     = PF_INET;
    nfho.priority   = NF_IP_PRI_FIRST;

    result = nf_register_net_hook(&init_net, &nfho);

    if(result) {
        printk(KERN_DEBUG "[YS] Error!\n");
        return 1;
    }

    printk(KERN_DEBUG "[YS] Module inserted!\n");

    return 0;
}

void cleanup_module() {
  
    nf_unregister_net_hook(&init_net, &nfho);
    printk(KERN_DEBUG "[YS] Module removed!\n");
}
