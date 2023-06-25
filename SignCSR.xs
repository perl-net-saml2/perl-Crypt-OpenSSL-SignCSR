#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <stdio.h>
#include <stdlib.h>

#include "ppport.h"

#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/safestack.h>
#include <openssl/pkcs12.h>
#include <openssl/bn.h>

# define OPT_FMT_PEM             (1L <<  1)
# define CHECK_OPEN_SSL(p_result) if (!(p_result)) croakSsl(__FILE__, __LINE__);
# define EXT_COPY_NONE   0
# define EXT_COPY_ADD    1
# define EXT_COPY_ALL    2
# define EXT_COPY_UNSET -1
# define SERIAL_RAND_BITS 159

BIO *bio_err;
#if OPENSSL_API_COMPAT >= 30101
OSSL_LIB_CTX *libctx = NULL;
static const char *propq = NULL;
#endif
static unsigned long nmflag = 0;
static char nmflag_set = 0;

// Taken from p5-Git-Raw
STATIC HV *ensure_hv(SV *sv, const char *identifier) {
    if (!SvROK(sv) || SvTYPE(SvRV(sv)) != SVt_PVHV)
    croak("Invalid type for '%s', expected a hash", identifier);

    return (HV *) SvRV(sv);
}

int rand_serial(BIGNUM *b, ASN1_INTEGER *ai)
{
    BIGNUM *btmp;
    int ret = 0;

    btmp = b == NULL ? BN_new() : b;
    if (btmp == NULL)
        return 0;

    if (!BN_rand(btmp, SERIAL_RAND_BITS, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
        goto error;
    if (ai && !BN_to_ASN1_INTEGER(btmp, ai))
        goto error;

    ret = 1;

 error:

    if (btmp != b)
        BN_free(btmp);

    return ret;
}

int set_cert_times(X509 *x, const char *startdate, const char *enddate,
                   int days)
{
    if (startdate == NULL || strcmp(startdate, "today") == 0) {
        if (X509_gmtime_adj(X509_getm_notBefore(x), 0) == NULL)
            return 0;
    } else {
#if OPENSSL_API_COMPAT >= 10101
        if (!ASN1_TIME_set_string_X509(X509_getm_notBefore(x), startdate))
#else        
        if (!ASN1_TIME_set_string(X509_getm_notBefore(x), startdate))
#endif
            return 0;
    }
    if (enddate == NULL) {
        if (X509_time_adj_ex(X509_getm_notAfter(x), days, 0, NULL)
            == NULL)
            return 0;
#if OPENSSL_API_COMPAT >= 10100
    } else if (!ASN1_TIME_set_string_X509(X509_getm_notAfter(x), enddate)) {
#else        
    } else if (!ASN1_TIME_set_string(X509_getm_notAfter(x), enddate)) {
#endif
        return 0;
    }
    return 1;
}

int copy_extensions(X509 *x, X509_REQ *req, int copy_type)
{
    STACK_OF(X509_EXTENSION) *exts;
    int i, ret = 0;

    if (x == NULL || req == NULL)
        return 0;
    if (copy_type == EXT_COPY_NONE)
        return 1;
    exts = X509_REQ_get_extensions(req);

    for (i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
        X509_EXTENSION *ext = sk_X509_EXTENSION_value(exts, i);
        ASN1_OBJECT *obj = X509_EXTENSION_get_object(ext);
        int idx = X509_get_ext_by_OBJ(x, obj, -1);

        /* Does extension exist in target? */
        if (idx != -1) {
            /* If normal copy don't override existing extension */
            if (copy_type == EXT_COPY_ADD)
                continue;
            /* Delete all extensions of same type */
            do {
                X509_EXTENSION_free(X509_delete_ext(x, idx));
                idx = X509_get_ext_by_OBJ(x, obj, -1);
            } while (idx != -1);
        }
        if (!X509_add_ext(x, ext, -1))
            goto end;
    }
    ret = 1;

 end:
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    return ret;
}

int cert_matches_key(const X509 *cert, const EVP_PKEY *pkey)
{
    int match;

    ERR_set_mark();
    match = X509_check_private_key(cert, pkey);
    ERR_pop_to_mark();
    return match;
}

static int do_x509_req_init(X509_REQ *x, STACK_OF(OPENSSL_STRING) *opts)
{
    //int i;

    opts = NULL;
    if (opts == NULL)
        return 1;

    //for (i = 0; i < sk_OPENSSL_STRING_num(opts); i++) {
    //    char *opt = sk_OPENSSL_STRING_value(opts, i);

    //    if (x509_req_ctrl_string(x, opt) <= 0) {
    //        croak("parameter error "); //$, n", opt);
    //        ERR_print_errors(bio_err);
    //        return 0;
    //    }
    //}

    return 1;
}

/*
 * do_X509_REQ_verify returns 1 if the signature is valid,
 * 0 if the signature check fails, or -1 if error occurs.
 */
int do_X509_REQ_verify(X509_REQ *x, EVP_PKEY *pkey, STACK_OF(OPENSSL_STRING) *vfyopts)
{
    int rv = 0;

    if (do_x509_req_init(x, vfyopts) > 0){
#if OPENSSL_API_COMPAT >= 30101
        rv = X509_REQ_verify_ex(x, pkey, libctx, propq);
#else
        rv = X509_REQ_verify(x, pkey);
#endif
    }
    else
        rv = -1;
    return rv;
}

void croakSsl(char* p_file, int p_line)
{
    const char* errorReason;
    /* Just return the top error on the stack */
    errorReason = ERR_reason_error_string(ERR_get_error());
    ERR_clear_error();
    croak("%s:%d: OpenSSL error: %s", p_file, p_line, errorReason);
}

SV* extractBioString(BIO* p_stringBio)
{
    SV* sv;
    BUF_MEM* bptr;

    CHECK_OPEN_SSL(BIO_flush(p_stringBio) == 1);
    BIO_get_mem_ptr(p_stringBio, &bptr);
    sv = newSVpv(bptr->data, bptr->length);

    CHECK_OPEN_SSL(BIO_set_close(p_stringBio, BIO_CLOSE) == 1);
    BIO_free(p_stringBio);
    return sv;
}

int pkey_ctrl_string(EVP_PKEY_CTX *ctx, const char *value)
{
    int rv = 0;
    char *stmp, *vtmp = NULL;

    stmp = OPENSSL_strdup(value);
    if (stmp == NULL)
        return -1;
    vtmp = strchr(stmp, ':');
    if (vtmp == NULL)
        goto err;

    *vtmp = 0;
    vtmp++;
    rv = EVP_PKEY_CTX_ctrl_str(ctx, stmp, vtmp);

 err:
    OPENSSL_free(stmp);
    return rv;
}

static int do_pkey_ctx_init(EVP_PKEY_CTX *pkctx, STACK_OF(OPENSSL_STRING) *opts)
{
    int i;

    if (opts == NULL)
        return 1;

    for (i = 0; i < sk_OPENSSL_STRING_num(opts); i++) {
        char *opt = sk_OPENSSL_STRING_value(opts, i);

        if (pkey_ctrl_string(pkctx, opt) <= 0) {
            BIO_printf(bio_err, "parameter error \"%s\"\n", opt);
            ERR_print_errors(bio_err);
            return 0;
        }
    }

    return 1;
}

unsigned long get_nameopt(void)
{
    return
        nmflag_set ? nmflag : XN_FLAG_SEP_CPLUS_SPC | ASN1_STRFLGS_UTF8_CONVERT;
}

#if OPENSSL_API_COMPAT >= 30101
static int do_sign_init(EVP_MD_CTX *ctx, EVP_PKEY *pkey, const char *md, STACK_OF(OPENSSL_STRING) *sigopts)
#else
static int do_sign_init(EVP_MD_CTX *ctx, EVP_PKEY *pkey, const EVP_MD *md, STACK_OF(OPENSSL_STRING) *sigopts)
#endif
{
    EVP_PKEY_CTX *pkctx = NULL;
#if OPENSSL_API_COMPAT >= 30101
    char def_md[80];
#else
    int def_nid;
#endif

    if (ctx == NULL)
        return 0;
    /*
     * EVP_PKEY_get_default_digest_name() returns 2 if the digest is mandatory
     * for this algorithm.
     */
#if OPENSSL_API_COMPAT >= 30101
    if (EVP_PKEY_get_default_digest_name(pkey, def_md, sizeof(def_md)) == 2
            && strcmp(def_md, "UNDEF") == 0) {
#else
    if (EVP_PKEY_get_default_digest_nid(pkey, &def_nid) == 2
        && def_nid == NID_undef) {
#endif
        /* The signing algorithm requires there to be no digest */
        md = NULL;
    }

#if OPENSSL_API_COMPAT >= 30101
    int val = EVP_DigestSignInit_ex(ctx, &pkctx, md, libctx,
                                 propq, pkey, NULL);
#else
    int val = EVP_DigestSignInit(ctx, &pkctx, md, NULL, pkey);
#endif
    return val
        && do_pkey_ctx_init(pkctx, sigopts);
}

static int key_destroy(pTHX_ SV* var, MAGIC* magic) {
    EVP_PKEY * key;

    key = (EVP_PKEY *) magic->mg_ptr;
    if (!key)
        return 0;

    EVP_PKEY_free(key);
    return 1;
}

static const MGVTBL key_magic = { NULL, NULL, NULL, NULL, key_destroy };


MODULE = Crypt::OpenSSL::SignCSR		PACKAGE = Crypt::OpenSSL::SignCSR

PROTOTYPES: DISABLE

SV * new(class, ...)
    const char * class

    PREINIT:
        SV * private_key = NULL;
        HV * options = newHV();

    CODE:
        STRLEN keyStringLength;
        char* keyString;
        BIO *bio;
        SV * key = newSV(0);

        if (items > 1) {
            if (ST(1) != NULL) {
                // TODO: ensure_string_sv
                private_key = ST(1);
                if (strlen(SvPV_nolen(private_key)) == 0) {
                    private_key = NULL;
                }
            }

            if (items > 2)
                options = ensure_hv(ST(2), "options");
        }

        // Get the private key and save it in memory
        keyString = SvPV(private_key, keyStringLength);
        bio = BIO_new_mem_buf(keyString, keyStringLength);
        if (bio == NULL) {
            croak ("Bio is null **** \n");
        }

        // Create the PrivateKey as EVP_PKEY
        EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, 0, NULL);
        if (pkey == NULL) {
            croak("Failed operation error code %d\n", errno);
        }

        // This uses "Magic" to hold the private key object
        // so it can be accessed later
        HV * attributes = newHV();

        SV *const self = newRV_noinc( (SV *)attributes );

        sv_magicext(key, NULL, PERL_MAGIC_ext,
            &key_magic, (const char *)pkey, 0);

        if((hv_store(attributes, "KEY", 3, key, 0)) == NULL)
            croak("unable to init key store");

        RETVAL = sv_bless( self, gv_stashpv( class, 0 ) );

    OUTPUT:

        RETVAL

SV * sign(self, request_SV, days, name_SV, text, sigopts)
    HV * self;
    SV * request_SV;
    IV days;
    SV * name_SV;
    IV text;

    PREINIT:
        EVP_MD_CTX *mctx;
        STACK_OF(OPENSSL_STRING) *sigopts = NULL;

    CODE:

        SV **svp;
        MAGIC* mg;
        EVP_PKEY *private_key;
        X509_REQ * csr;
        int rv = 0;
        STRLEN request_length;
        unsigned char* request;
        //BIO *bio;
        BIO *csrbio;
        char * digestname;
        STRLEN digestname_length;

        // FIXME: This reads the key that was passed into the new
        // function.  Its probably better to pass the key directly
        // to the sign function so that we can avoid haing the key
        // in memory too long.
        if (!hv_exists(self, "KEY", strlen("KEY")))
            croak("KEY not found in self!\n");

        svp = hv_fetch(self, "KEY", strlen("KEY"), 0);

        if (!SvMAGICAL(*svp) || (mg = mg_findext(*svp, PERL_MAGIC_ext, &key_magic)) == NULL)
            croak("KEY is invalid");

        private_key = (EVP_PKEY *) mg->mg_ptr;

        // Get the request that was passed into the sign function
        request = (unsigned char*) SvPV(request_SV, request_length);

        // Create the X509_REQ from the request
        csrbio = BIO_new_mem_buf(request, request_length);
        if (csrbio == NULL) {
            croak ("Bio for CRS Request is null **** \n");
        }
        csr = PEM_read_bio_X509_REQ(csrbio, NULL, NULL, NULL);

        if (csr == NULL) {
            croak ("PEM_read_bio_X509_REQ failed **** \n");
        }

        // Verify the CSR is properly signed
        EVP_PKEY *pkey;
        if (csr != NULL) {
            pkey = X509_REQ_get0_pubkey(csr);

            int ret = do_X509_REQ_verify(csr, pkey, NULL);
            if (pkey == NULL || ret < 0)
                croak ("Warning: error while verifying CSR self-signature\n");
            if (ret == 0)
                croak ("Verification of CSR failed\n");
        }
        else
            croak("Unable to properly parse the Certificate Signing Request\n");

        // Create a new certificate store
        X509 * x;
#if OPENSSL_API_COMPAT >= 30101
        if ((x = X509_new_ex(libctx, propq)) == NULL)
#else
        if ((x = X509_new()) == NULL)
#endif
            croak("X509_new_ex failed ...\n");

        // FIXME need to look at this
        int ext_copy = EXT_COPY_UNSET;
        if (!copy_extensions(x, csr, ext_copy))
            croak("Unable to copy extensions\n");

        // Update the certificate with the CSR's subject name
        if (!X509_set_subject_name(x, X509_REQ_get_subject_name(csr)))
            croak("X509_set_subject_name cannot set subject name\n");

        // Update the certificate with the CSR's public key
        if (!X509_set_pubkey(x, X509_REQ_get0_pubkey(csr)))
            croak("X509_set_pubkey cannot set public key\n");

        // FIXME need to look at this
        //for (int i = X509_get_ext_count(x) - 1; i >= 0; i--) {
        //    X509_EXTENSION *ex = X509_get_ext(x, i);
        //    const char *sn = OBJ_nid2sn(OBJ_obj2nid(X509_EXTENSION_get_object(ex)));

        //    if (clrext || (ext_names != NULL && strstr(ext_names, sn) == NULL))
        //        X509_EXTENSION_free(X509_delete_ext(x, i));
        //}

        // FIXME - this may need to change to support signing by different certificates
        if (private_key != NULL && !cert_matches_key(x, private_key))
            croak("cert_matches_key: signature key and public key of cert do not match\n");

        // Generate a serial number and update the certificate
        ASN1_INTEGER *sno = ASN1_INTEGER_new();
        if (sno == NULL || !rand_serial(NULL, sno))
            croak ("Unable to get ASN1INTEGER or random_serial\n");

        if (sno != NULL && !X509_set_serialNumber(x, sno))
            croak("X509_set_serialNumber cannot set serial number\n");

        set_cert_times(x, NULL, NULL, (int) days);

        // Set the certificate's issuer based on the issuer's certificate
        // In self-signed certificates it is the same issuer
        // FIXME this needs to be fixed to support non-self-signed certificate
        X509 * issuer_cert = x;
        if (!X509_set_issuer_name(x, X509_get_subject_name(issuer_cert)))
            croak("X509_set_issuer_name cannot set issuer name\n");

        // Create the X509 v3 extensions for the certificate
        X509V3_CTX ext_ctx;

        // Set the certificate issuer from the private key
#if OPENSSL_API_COMPAT >= 30000
        X509V3_set_ctx(&ext_ctx, issuer_cert, x, NULL, NULL, X509V3_CTX_REPLACE);
        if (!X509V3_set_issuer_pkey(&ext_ctx, private_key))
            croak("X509V3_set_issuer_pkey cannot set issuer private key\n");
#else
        X509V3_set_ctx(&ext_ctx, issuer_cert, x, csr, NULL, X509V3_CTX_REPLACE);
#endif

        // Set the X509 version of the certificate
#if OPENSSL_API_COMPAT >= 30000
        if (!X509_set_version(x, X509_VERSION_3))
#else
        if (!X509_set_version(x, 2))
#endif
            croak("X509_set_version cannot set version 3\n");

        // Get digestname parameter - verify that it is valid
#if OPENSSL_API_COMPAT >= 30101
        const EVP_MD *dgst;
#else
        EVP_MD * md;
#endif
        digestname = (unsigned char*) SvPV(name_SV, digestname_length);
        md = (EVP_MD *)EVP_get_digestbyname(digestname);
        if (md != NULL)
            digestname = digestname;
        else
            digestname = NULL;

        // Allocate and a new digest context for certificate signing
        mctx = EVP_MD_CTX_new();

        // Sign the new certificate
#if OPENSSL_API_COMPAT >= 30101
        if (mctx != NULL && do_sign_init(mctx, private_key, digestname, sigopts) > 0)
#else
        if (mctx != NULL && do_sign_init(mctx, private_key, md, sigopts) > 0)
#endif
            rv = (X509_sign_ctx(x, mctx) > 0);

        if (rv == 0)
            croak("X509_sign_ctx cannot sign the new certificate\n");

        // Prepare to output new certificate
        BIO * out = BIO_new(BIO_s_mem());

        int i;
        if (!text)
            // Output the PEM encoded certificate
            i = PEM_write_bio_X509(out, x);
        else
            // Output the text format of the certificate
            i = X509_print_ex(out, x, get_nameopt(), 0);

        if (!i)
            croak("unable to output certificate data\n");

        RETVAL = extractBioString(out);

    OUTPUT:

        RETVAL

