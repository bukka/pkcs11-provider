/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/store.h>
#include <sys/wait.h>
#include "util.h"

static void sign_op(EVP_PKEY *key, pid_t pid)
{
    size_t size = EVP_PKEY_get_size(key);
    unsigned char sig[size];
    const char *data = "Sign Me!";
    EVP_MD_CTX *sign_md;
    int ret;

    sign_md = EVP_MD_CTX_new();
    ret = EVP_DigestSignInit_ex(sign_md, NULL, "SHA256", NULL, NULL, key, NULL);
    if (ret != 1) {
        PRINTERROSSL("Failed to init EVP_DigestSign (pid = %d)\n", pid);
        exit(EXIT_FAILURE);
    }

    ret = EVP_DigestSignUpdate(sign_md, data, sizeof(data));
    if (ret != 1) {
        PRINTERROSSL("Failed to EVP_DigestSignUpdate (pid = %d)\n", pid);
        exit(EXIT_FAILURE);
    }

    ret = EVP_DigestSignFinal(sign_md, sig, &size);
    if (ret != 1) {
        PRINTERROSSL("Failed to EVP_DigestSignFinal-ize (pid = %d)\n", pid);
        exit(EXIT_FAILURE);
    }
    EVP_MD_CTX_free(sign_md);

    if (pid == 0) {
        EVP_PKEY_free(key);
        PRINTERR("Child Done\n");
        exit(EXIT_SUCCESS);
    }
}

/* forks in the middle of an op to check the child one fails */
static void fork_sign_op(EVP_PKEY *key)
{
    size_t size = EVP_PKEY_get_size(key);
    unsigned char sig[size];
    const char *data = "Sign Me!";
    EVP_MD_CTX *sign_md;
    pid_t pid;
    int ret;

    sign_md = EVP_MD_CTX_new();
    ret = EVP_DigestSignInit_ex(sign_md, NULL, "SHA256", NULL, NULL, key, NULL);
    if (ret != 1) {
        PRINTERROSSL("Failed to init EVP_DigestSign\n");
        exit(EXIT_FAILURE);
    }

    ret = EVP_DigestSignUpdate(sign_md, data, sizeof(data));
    if (ret != 1) {
        PRINTERROSSL("Failed to EVP_DigestSignUpdate\n");
        exit(EXIT_FAILURE);
    }

    pid = fork();
    if (pid == -1) {
        PRINTERR("Fork failed");
        exit(EXIT_FAILURE);
    }

    ret = EVP_DigestSignFinal(sign_md, sig, &size);
    EVP_MD_CTX_free(sign_md);

    if (pid == 0) {
        /* child */
        if (ret != 0) {
            /* should have returned error in the child */
            PRINTERR("Child failed to fail!\n");
            exit(EXIT_FAILURE);
        }
        EVP_PKEY_free(key);
        PRINTERR("Child Done\n");
        fflush(stderr);
        exit(EXIT_SUCCESS);
    } else {
        int status;

        EVP_PKEY_free(key);
        /* parent */
        if (ret != 1) {
            PRINTERROSSL("Failed to EVP_DigestSignFinal-ize\n");
            exit(EXIT_FAILURE);
        }

        waitpid(pid, &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            PRINTERR("Child failure\n");
            exit(EXIT_FAILURE);
        }
    }
}

/* Import public key by URI - this triggers provider import dispatch */
static EVP_PKEY *import_public_key_by_uri(const char *uri)
{
    OSSL_STORE_CTX *store_ctx;
    OSSL_STORE_INFO *store_info;
    EVP_PKEY *imported_key = NULL;
    char *public_uri;
    int ret;

    /* Modify URI to specifically request public key */
    ret = asprintf(&public_uri, "%s;type=public", uri);
    if (ret == -1) {
        fprintf(stderr, "Failed to allocate public key URI\n");
        return NULL;
    }

    store_ctx = OSSL_STORE_open_ex(public_uri, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    if (store_ctx == NULL) {
        PRINTERROSSL("Failed to open OSSL_STORE for public key URI: %s\n", public_uri);
        free(public_uri);
        return NULL;
    }

     /* Load the public key - this triggers the provider import */
    while ((store_info = OSSL_STORE_load(store_ctx)) != NULL) {
        if (OSSL_STORE_INFO_get_type(store_info) == OSSL_STORE_INFO_PKEY) {
            EVP_PKEY *key = OSSL_STORE_INFO_get1_PKEY(store_info);
            if (key != NULL) {
                /* Verify this is a public key using EVP_PKEY_CTX */
                EVP_PKEY_CTX *check_ctx = EVP_PKEY_CTX_new(key, NULL);
                if (check_ctx != NULL) {
                    int is_public = EVP_PKEY_public_check(check_ctx);
                    EVP_PKEY_CTX_free(check_ctx);
                    
                    if (is_public == 1) {
                        imported_key = key;
                        OSSL_STORE_INFO_free(store_info);
                        break;
                    }
                }
                EVP_PKEY_free(key);
            }
        }
        OSSL_STORE_INFO_free(store_info);
    }

    OSSL_STORE_close(store_ctx);
    free(public_uri);

    if (imported_key == NULL) {
        PRINTERROSSL("Failed to load public key from store\n");
    }

    return imported_key;
}

/* Create signature for verification test */
static int create_signature(EVP_PKEY *key, const char *data, unsigned char **sig_out, size_t *sig_len)
{
    EVP_MD_CTX *sign_md;
    size_t sig_size;
    unsigned char *signature;
    int ret;

    sig_size = EVP_PKEY_get_size(key);
    signature = malloc(sig_size);
    if (!signature) {
        fprintf(stderr, "Failed to allocate signature buffer\n");
        return 0;
    }

    sign_md = EVP_MD_CTX_new();
    if (!sign_md) {
        free(signature);
        return 0;
    }

    ret = EVP_DigestSignInit_ex(sign_md, NULL, "SHA256", NULL, NULL, key, NULL);
    if (ret != 1) {
        PRINTERROSSL("Failed to init EVP_DigestSign\n");
        EVP_MD_CTX_free(sign_md);
        free(signature);
        return 0;
    }

    ret = EVP_DigestSignUpdate(sign_md, data, strlen(data));
    if (ret != 1) {
        PRINTERROSSL("Failed to EVP_DigestSignUpdate\n");
        EVP_MD_CTX_free(sign_md);
        free(signature);
        return 0;
    }

    *sig_len = sig_size;
    ret = EVP_DigestSignFinal(sign_md, signature, sig_len);
    if (ret != 1) {
        PRINTERROSSL("Failed to EVP_DigestSignFinal\n");
        EVP_MD_CTX_free(sign_md);
        free(signature);
        return 0;
    }

    EVP_MD_CTX_free(sign_md);
    *sig_out = signature;
    return 1;
}

/* Verify signature - this exercises the imported key */
static int verify_signature(EVP_PKEY *key, const char *data, unsigned char *sig, size_t sig_len, const char *context)
{
    EVP_MD_CTX *verify_md;
    int ret;

    verify_md = EVP_MD_CTX_new();
    if (!verify_md) {
        return 0;
    }

    ret = EVP_DigestVerifyInit_ex(verify_md, NULL, "SHA256", NULL, NULL, key, NULL);
    if (ret != 1) {
        PRINTERROSSL("%s: Failed to init EVP_DigestVerify\n", context);
        EVP_MD_CTX_free(verify_md);
        return 0;
    }

    ret = EVP_DigestVerifyUpdate(verify_md, data, strlen(data));
    if (ret != 1) {
        PRINTERROSSL("%s: Failed to EVP_DigestVerifyUpdate\n", context);
        EVP_MD_CTX_free(verify_md);
        return 0;
    }

    ret = EVP_DigestVerifyFinal(verify_md, sig, sig_len);
    if (ret != 1) {
        PRINTERROSSL("%s: Failed to EVP_DigestVerifyFinal\n", context);
        EVP_MD_CTX_free(verify_md);
        return 0;
    }

    EVP_MD_CTX_free(verify_md);
    PRINTERR("%s: Signature verification successful\n", context);
    return 1;
}

/* Test basic fork operations with generated key */
static void test_basic_fork_operations(EVP_PKEY *key)
{
    pid_t pid;
    int status;

    PRINTERR("=== Testing basic fork operations ===\n");

    /* test a simple op first */
    sign_op(key, -1);

    /* now fork and see if operations keep succeeding on both sides */
    pid = fork();
    if (pid == -1) {
        PRINTERR("Fork failed\n");
        exit(EXIT_FAILURE);
    }

    /* child just exits in sign_op */
    sign_op(key, pid);

    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        PRINTERR("Child failure\n");
        exit(EXIT_FAILURE);
    }

    fork_sign_op(key);
    PRINTERR("=== Basic fork operations completed ===\n");
}

/* Test generate key, sign before fork, import and verify after fork */
static void test_sign_before_verify_after_fork(const char *label)
{
    EVP_PKEY *generated_key = NULL;
    EVP_PKEY *imported_key = NULL;
    char *uri = NULL;
    unsigned char *signature = NULL;
    size_t sig_len;
    const char *test_data = "Test data for sign-before-verify-after pattern";
    pid_t pid;
    int ret;

    PRINTERR("=== Testing sign before fork, verify after fork ===\n");

    PRINTERR("Parent: Generating key with URI\n");
    generated_key = util_gen_key_ex(label, &uri);
    if (generated_key == NULL || uri == NULL) {
        PRINTERR("Parent: Failed to generate key with URI\n");
        exit(EXIT_FAILURE);
    }

    PRINTERR("Parent: Generated key with URI: %s\n", uri);

    PRINTERR("Parent: Creating signature before fork\n");
    ret = create_signature(generated_key, test_data, &signature, &sig_len);
    if (!ret) {
        PRINTERR("Parent: Failed to create signature\n");
        EVP_PKEY_free(generated_key);
        free(uri);
        exit(EXIT_FAILURE);
    }

    pid = fork();
    if (pid == -1) {
        PRINTERR("Fork failed\n");
        EVP_PKEY_free(generated_key);
        free(signature);
        free(uri);
        exit(EXIT_FAILURE);
    }

    if (pid == 0) {
        /* Child process */
        PRINTERR("Child: Importing key after fork\n");
        
        /* Import public key in child after fork - this triggers provider import */
        imported_key = import_public_key_by_uri(uri);
        if (imported_key == NULL) {
            PRINTERR("Child: Failed to import public key after fork\n");
            EVP_PKEY_free(generated_key);
            free(signature);
            free(uri);
            exit(EXIT_FAILURE);
        }

        /* Verify signature with imported public key AFTER fork */
        ret = verify_signature(imported_key, test_data, signature, sig_len, "Child (imported public key)");
        if (!ret) {
            PRINTERR("Child: Verification failed with imported public key\n");
            EVP_PKEY_free(generated_key);
            EVP_PKEY_free(imported_key);
            free(signature);
            free(uri);
            exit(EXIT_FAILURE);
        }

        /* Test duplication of imported public key */
        EVP_PKEY *duplicated_key = EVP_PKEY_dup(imported_key);
        if (duplicated_key == NULL) {
            PRINTERROSSL("Child: Failed to duplicate imported public key\n");
            EVP_PKEY_free(generated_key);
            EVP_PKEY_free(imported_key);
            free(signature);
            free(uri);
            exit(EXIT_FAILURE);
        }

        /* Verify with duplicated public key */
        ret = verify_signature(duplicated_key, test_data, signature, sig_len, "Child (duplicated public key)");
        if (!ret) {
            PRINTERR("Child: Verification failed with duplicated public key\n");
            EVP_PKEY_free(generated_key);
            EVP_PKEY_free(imported_key);
            EVP_PKEY_free(duplicated_key);
            free(signature);
            free(uri);
            exit(EXIT_FAILURE);
        }

        PRINTERR("Child: All post-fork public key import and verification tests passed\n");
        
        /* Cleanup and exit */
        EVP_PKEY_free(generated_key);
        EVP_PKEY_free(imported_key);
        EVP_PKEY_free(duplicated_key);
        free(signature);
        free(uri);
        exit(EXIT_SUCCESS);
        
    } else {
        /* Parent process */
        int status;
        
        PRINTERR("Parent: Waiting for child to complete import and verify test\n");
        
        waitpid(pid, &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            PRINTERR("Child import and verify test failed\n");
            EVP_PKEY_free(generated_key);
            free(signature);
            free(uri);
            exit(EXIT_FAILURE);
        }
        
        PRINTERR("Parent: Child import and verify test succeeded\n");
    }

    /* Cleanup parent */
    EVP_PKEY_free(generated_key);
    free(signature);
    free(uri);
    PRINTERR("=== Sign before fork, verify after fork test completed ===\n");
}

/* Modified main function */
int main(int argc, char *argv[])
{
    EVP_PKEY *key;
    const char *test_label = "Fork-Test";

    /* Generate a key first using original function */
    key = util_gen_key(test_label);

    /* T1: Basic fork operations with generated key */
    test_basic_fork_operations(key);

    /* T2: Generate key, sign before fork, import and verify after fork */
    test_sign_before_verify_after_fork("Fork-Import-Test");

    EVP_PKEY_free(key);
    PRINTERR("ALL TESTS COMPLETED SUCCESSFULLY!\n");
    exit(EXIT_SUCCESS);
}