#include <linux/key.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/verification.h>
#include <linux/cred.h>
#include <crypto/pkcs7.h>
#include <linux/key-type.h>
#include <keys/user-type.h>

extern __initconst const unsigned int system_certificate_list[];
extern __initconst const unsigned long system_certificate_list_size;

extern __initconst const unsigned int data[];
extern __initconst const unsigned long data_size;

extern __initconst const unsigned int sign[];
extern __initconst const unsigned long sign_size;

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("PKCS#7 testing key type");
MODULE_AUTHOR("Gitai");

static unsigned pkcs7_usage;

module_param_named(usage, pkcs7_usage, uint, S_IWUSR | S_IRUGO);
MODULE_PARM_DESC(pkcs7_usage,
                 "Usage to specify when verifying the PKCS#7 message");

static int pkcs7_preparse(struct key_preparsed_payload *prep);

/*
 * Retrieve the PKCS#7 message content.
 */
static int pkcs7_view_content(void *ctx, const void *data, size_t len,
                              size_t asn1hdrlen)
{
    struct key_preparsed_payload *prep = ctx;
    const void *saved_prep_data;
    size_t saved_prep_datalen;
    int ret;
    saved_prep_data = prep->data;
    saved_prep_datalen = prep->datalen;
    prep->data = data;
    prep->datalen = len;
    ret = user_preparse(prep);
    prep->data = saved_prep_data;
    prep->datalen = saved_prep_datalen;
    return ret;
}

static struct key *builtin_trusted_keys;

/*
 * user defined keys take an arbitrary string as the description and an
 * arbitrary blob of data as the payload
 */
static struct key_type key_type_pkcs7 = {
    .name = "pkcs7_test",
    .preparse = pkcs7_preparse,
    .free_preparse = user_free_preparse,
    .instantiate = generic_key_instantiate,
    .revoke = user_revoke,
    .destroy = user_destroy,
    .describe = user_describe,
    .read = user_read,
};

/*
 * Preparse a PKCS#7 wrapped and validated data blob.
 */
static int pkcs7_preparse(struct key_preparsed_payload *prep)
{
    printk("pkcs7_preparse");
    enum key_being_used_for usage = pkcs7_usage;
    if (usage >= NR__KEY_BEING_USED_FOR)
    {
        pr_err("Invalid usage type %d\n", usage);
        return -EINVAL;
    }

    return verify_pkcs7_signature(prep->data, prep->datalen,
                                  sign, sign_size,
                                  builtin_trusted_keys, VERIFYING_MODULE_SIGNATURE,
                                  NULL, NULL);
}

int rt;

// cat 1.der | keyctl padd pkcs7_test kkdk @u
/*
 * Module stuff
 */
static int __init pkcs7_key_init(void)
{
    uint8_t sha256test[] = "HelloWorld\n";
    builtin_trusted_keys = keyring_alloc(".builtin_trusted_keys",
                                         KUIDT_INIT(0), KGIDT_INIT(0), current_cred(),
                                         ((KEY_POS_ALL & ~KEY_POS_SETATTR) |
                                          KEY_USR_VIEW | KEY_USR_READ | KEY_USR_SEARCH),
                                         KEY_ALLOC_NOT_IN_QUOTA,
                                         NULL, NULL);

    if (IS_ERR(builtin_trusted_keys))
        panic("Can't allocate builtin trusted keyring\n");

    key_create_or_update(make_key_ref(builtin_trusted_keys, 1),
                         "asymmetric",
                         NULL,
                         system_certificate_list,
                         system_certificate_list_size,
                         ((KEY_POS_ALL & ~KEY_POS_SETATTR) |
                          KEY_USR_VIEW | KEY_USR_READ),
                         KEY_ALLOC_NOT_IN_QUOTA |
                             KEY_ALLOC_BUILT_IN |
                             KEY_ALLOC_BYPASS_RESTRICTION);

    rt = verify_pkcs7_signature(data, data_size,
                                sign, sign_size,
                                builtin_trusted_keys, VERIFYING_MODULE_SIGNATURE,
                                NULL, NULL);

    printk("rt: %d\n", rt);
    if (rt)
    {
        return rt;
    }
    return register_key_type(&key_type_pkcs7);
}

static void __exit pkcs7_key_cleanup(void)
{
    if (!rt)
        unregister_key_type(&key_type_pkcs7);
}

module_init(pkcs7_key_init);
module_exit(pkcs7_key_cleanup);