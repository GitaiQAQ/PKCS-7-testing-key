/*
 * @Author: Gitai<i@gitai.me>
 * @Date: 2020-05-06 20:44:02
 * @LastEditors: Gitai
 * @LastEditTime: 2020-06-22 10:01:09
 * @FilePath: /pkcs7test/main.c
 */ 
#include <linux/key.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/verification.h>
#include <linux/cred.h>
#include <crypto/pkcs7.h>
#include <linux/key-type.h>
#include <keys/user-type.h>
#include "pkcs7_parser.h"

extern __initconst const u8 system_certificate_list[];
extern __initconst const unsigned long system_certificate_list_size;

extern __initconst const u8 data[];
extern __initconst const unsigned long data_size;

extern __initconst const u8 sign[];
extern __initconst const unsigned long sign_size;

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("PKCS#7 testing key type");
MODULE_AUTHOR("Gitai");

static unsigned pkcs7_usage;

module_param_named(usage, pkcs7_usage, uint, S_IWUSR | S_IRUGO);
MODULE_PARM_DESC(pkcs7_usage,
                 "Usage to specify when verifying the PKCS#7 message");

static struct key *builtin_trusted_keys;

int rt;

/*
 * Create the trusted keyrings
 */
static __init int system_trusted_keyring_init(void)
{
	printk("Initialise system trusted keyrings\n");

	builtin_trusted_keys =
		keyring_alloc(".builtin_trusted_keys",
			      KUIDT_INIT(0), KGIDT_INIT(0), current_cred(),
			      ((KEY_POS_ALL & ~KEY_POS_SETATTR) |
			      KEY_USR_VIEW | KEY_USR_READ | KEY_USR_SEARCH),
			      KEY_ALLOC_NOT_IN_QUOTA,
			      NULL, NULL);
	if (IS_ERR(builtin_trusted_keys))
		panic("Can't allocate builtin trusted keyring\n");

	return 0;
}

static __init int load_system_certificate_list(void)
{
	key_ref_t key;
	const u8 *p, *end;
	size_t plen;

	pr_notice("Loading compiled-in X.509 certificates\n");

	p = system_certificate_list;
	end = p + system_certificate_list_size;
	while (p < end) {
		/* Each cert begins with an ASN.1 SEQUENCE tag and must be more
		 * than 256 bytes in size.
		 */
		if (end - p < 4)
			goto dodgy_cert;
		if (p[0] != 0x30 &&
		    p[1] != 0x82)
			goto dodgy_cert;
		plen = (p[2] << 8) | p[3];
		plen += 4;
		if (plen > end - p)
			goto dodgy_cert;

		key = key_create_or_update(make_key_ref(builtin_trusted_keys, 1),
					   "asymmetric",
					   NULL,
					   p,
					   plen,
					   ((KEY_POS_ALL & ~KEY_POS_SETATTR) |
					   KEY_USR_VIEW | KEY_USR_READ),
					   KEY_ALLOC_NOT_IN_QUOTA |
					   KEY_ALLOC_BUILT_IN |
					   KEY_ALLOC_BYPASS_RESTRICTION);
		if (IS_ERR(key)) {
			pr_err("Problem loading in-kernel X.509 certificate (%ld)\n",
			       PTR_ERR(key));
		} else {
			pr_notice("Loaded X.509 cert '%s'\n",
				  key_ref_to_ptr(key)->description);
			key_ref_put(key);
		}
		p += plen;
	}

	return 0;

dodgy_cert:
	pr_err("Problem parsing in-kernel X.509 certificate list\n");
	return 0;
}

// cat 1.der | keyctl padd pkcs7_test kkdk @u
/*
 * Module stuff
 */
static int __init pkcs7_key_init(void)
{
    system_trusted_keyring_init();

    load_system_certificate_list();

    struct pkcs7_message *pkcs7;
	struct pkcs7_signed_info *sinfo;
    struct x509_certificate *x509;
	pkcs7 = pkcs7_parse_message(sign, sign_size);
    for (sinfo = pkcs7->signed_infos; sinfo; sinfo = sinfo->next) {
        printk("sinfo index: %d\n", sinfo->index);
		// 爲什麼這個 signer 是空指針
        for (x509 = sinfo->signer; x509; x509 = x509->signer) {
            printk("x509 id: %d\n", x509->id->len);
            printk("x509 skid: %d\n", x509->skid->len);
        }
        printk("sinfo auth_ids: %d", sinfo->sig->auth_ids[0]->len);
	}

    rt = verify_pkcs7_signature(data, data_size,
                                sign, sign_size,
                                builtin_trusted_keys, VERIFYING_UNSPECIFIED_SIGNATURE,
                                NULL, NULL);

    printk("rt: %d\n", rt);
    if (rt)
    {
        return rt;
    }
    return 0;
}

static void __exit pkcs7_key_cleanup(void)
{
    
}

module_init(pkcs7_key_init);
module_exit(pkcs7_key_cleanup);