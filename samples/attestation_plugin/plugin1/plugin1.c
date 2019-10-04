// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifdef OE_BUILD_ENCLAVE
#include <mbedtls/sha256.h>
#include <openenclave/enclave.h>
#else
#include <openenclave/host.h>
#endif

#include <openenclave/bits/defs.h>
#include <openenclave/bits/safemath.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "plugin1.h"

// This plugin emulates the functionality of `oe_get_report` and
// `oe_verify_report`  for remote attestation reports through
// the plugin interface.
static int plugin1_on_register(
    oe_quote_customization_plugin_context_t* plugin_context,
    const void* config_data,
    size_t config_data_size)
{
    OE_UNUSED(plugin_context);
    OE_UNUSED(config_data);
    OE_UNUSED(config_data_size);
    return 0;
}

static int plugin1_on_unregister(
    oe_quote_customization_plugin_context_t* plugin_context)
{
    OE_UNUSED(plugin_context);
    return 0;
}

#ifdef OE_BUILD_ENCLAVE
static int _calc_sha256(
    const uint8_t* user_data,
    size_t user_data_size,
    uint8_t* output)
{
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    int ret = -1;

    if (mbedtls_sha256_starts_ret(&ctx, 0) != 0)
        goto done;

    if (mbedtls_sha256_update_ret(&ctx, user_data, user_data_size) != 0)
        goto done;

    if (mbedtls_sha256_finish_ret(&ctx, output) != 0)
        goto done;

    ret = 0;

done:
    mbedtls_sha256_free(&ctx);
    return ret;
}

static int plugin1_get_evidence(
    oe_quote_customization_plugin_context_t* plugin_context,
    const uint8_t* user_data,
    size_t user_data_size,
    uint8_t** evidence_buffer,
    size_t* evidence_buffer_size)
{
    // Need to hash the user data first.
    uint8_t* report_data = NULL;
    size_t report_data_size = 0;
    uint8_t hash[32];
    int ret = -1;
    oe_result_t oe_ret;
    uint8_t* report_buffer = NULL;
    size_t report_buffer_size = 0;
    size_t total_evidence_size = 0;
    oe_evidence_header_t* header;

    if (user_data)
    {
        if (_calc_sha256(user_data, user_data_size, hash) != 0)
            goto done;

        report_data = hash;
        report_data_size = sizeof(hash);
    }

    // Technically, this will wrap the sgx report with the OE header,
    // which will get wrapped again in the caller of this function,
    // but that's fine.
    oe_ret = oe_get_report(
        OE_REPORT_FLAGS_REMOTE_ATTESTATION,
        report_data,
        report_data_size,
        NULL,
        0,
        &report_buffer,
        &report_buffer_size);

    if (oe_ret != OE_OK)
        goto done;

    // Set the custom data size to the right amount.
    header = (oe_evidence_header_t*)report_buffer;
    header->user_data_size = 0;
    if (!user_data)
    {
        ret = 0;
        goto done;
    }
    header->user_data_size = user_data_size;

    // Now, we need to append the user data to the end of the report.
    oe_ret = oe_safe_add_sizet(
        user_data_size, report_buffer_size, &total_evidence_size);
    if (oe_ret != OE_OK)
        goto done;

    *evidence_buffer = (uint8_t*)malloc(total_evidence_size);
    if (*evidence_buffer == NULL)
        goto done;

    memcpy(*evidence_buffer, report_buffer, report_buffer_size);
    memcpy(*evidence_buffer + report_buffer_size, user_data, user_data_size);
    *evidence_buffer_size = total_evidence_size;

    ret = 0;

done:
    return ret;
}
#else
static int plugin1_get_evidence(
    oe_quote_customization_plugin_context_t* plugin_context,
    const uint8_t* user_data,
    size_t user_data_size,
    uint8_t** evidence_buffer,
    size_t* evidence_buffer_size)
{
    OE_UNUSED(plugin_context);
    OE_UNUSED(user_data);
    OE_UNUSED(user_data_size);
    OE_UNUSED(evidence_buffer);
    OE_UNUSED(evidence_buffer_size);
    return -1;
}
#endif

static int plugin1_free_evidence(
    oe_quote_customization_plugin_context_t* plugin_context,
    uint8_t* evidence_buffer)
{
    oe_free_report(evidence_buffer);
    return 0;
}

// Convert oe_report_t parsed_report into an array of claims
static int _convert_parsed_report_to_claims(
    oe_report_t* parsed_report,
    oe_claim_element_t** claims,
    size_t* claim_count)
{
    int ret = 1;
    size_t count = 5; /* supports  security_version, unique_id, signer_id,
                         product_id, debug_flag*/
    oe_claim_element_t* all_claims = NULL;
    oe_identity_t* identity = NULL;

    identity = &parsed_report->identity;
    all_claims =
        (oe_claim_element_t*)malloc(sizeof(oe_claim_element_t) * count);
    if (all_claims == NULL)
    {
        goto done;
    }
    memset(all_claims, 0, sizeof(oe_claim_element_t) * count);

    all_claims[0].name = "security_version";
    all_claims[0].len = sizeof(identity->security_version);
    all_claims[0].value = (uint8_t*)malloc(all_claims[0].len);
    if (all_claims[0].value == NULL)
    {
        goto done;
    }
    memcpy(
        (void*)all_claims[0].value,
        &identity->security_version,
        all_claims[0].len);

    // MRENCLAVE for SGX
    all_claims[1].name = "unique_id";
    all_claims[1].len = OE_UNIQUE_ID_SIZE;
    all_claims[1].value = (uint8_t*)malloc(all_claims[1].len);
    if (all_claims[0].value == NULL)
    {
        goto done;
    }
    memcpy((void*)all_claims[1].value, &identity->unique_id, all_claims[1].len);

    all_claims[2].name = "signer_id";
    all_claims[2].len = OE_SIGNER_ID_SIZE;
    all_claims[2].value = (uint8_t*)malloc(all_claims[2].len);
    if (all_claims[0].value == NULL)
    {
        goto done;
    }
    memcpy((void*)all_claims[2].value, &identity->signer_id, all_claims[2].len);

    all_claims[3].name = "product_id";
    all_claims[3].len = OE_PRODUCT_ID_SIZE;
    all_claims[3].value = (uint8_t*)malloc(all_claims[3].len);
    if (all_claims[0].value == NULL)
    {
        goto done;
    }
    memcpy(
        (void*)all_claims[3].value, &identity->product_id, all_claims[3].len);

    all_claims[4].name = "debug_flag";
    all_claims[4].len = 1;
    all_claims[4].value = (uint8_t*)malloc(all_claims[4].len);
    if (all_claims[0].value == NULL)
    {
        goto done;
    }
    memcpy(
        (void*)all_claims[4].value, &identity->product_id, all_claims[4].len);
    *(bool*)all_claims[4].value =
        (identity->attributes & OE_REPORT_ATTRIBUTES_DEBUG) ? 1 : 0;

    *claims = all_claims;
    *claim_count = count;
    ret = 0;

done:
    if (ret)
    {
        if (all_claims)
        {
            // free all memory
            for (size_t i = 0; i < count; i++)
                free(all_claims[i].value);
            free(all_claims);
        }
    }
    return ret;
}

static int plugin1_verify_evidence(
    oe_quote_customization_plugin_context_t* plugin_context,
    const uint8_t* evidence_buffer,
    size_t evidence_buffer_size,
    oe_claim_element_t** claims,
    size_t* claims_count,
    uint8_t** user_data,
    size_t* user_data_size)
{
    oe_evidence_header_t* header = (oe_evidence_header_t*)evidence_buffer;
    oe_report_t report;
    int ret = -1;

    // Evidence should be oe report + custom report data.
    if (evidence_buffer_size < sizeof(*header))
        goto done;

    // Sanity check.
    if (header->user_data_size > evidence_buffer_size)
        goto done;

        // Verify the report.
#ifdef OE_BUILD_ENCLAVE
    if (oe_verify_report(evidence_buffer, evidence_buffer_size, &report) !=
        OE_OK)
#else
    if (oe_verify_report(
            NULL, evidence_buffer, evidence_buffer_size, &report) != OE_OK)
#endif
        goto done;

    // Return the user data to caller.
    *user_data = (uint8_t*)malloc(header->user_data_size);
    if (*user_data == NULL)
        goto done;

    memcpy(
        *user_data,
        evidence_buffer + evidence_buffer_size - header->user_data_size,
        header->user_data_size);

    *user_data_size = header->user_data_size;

    // Get the claims from the report.
    if (_convert_parsed_report_to_claims(&report, claims, claims_count) != 0)
    {
        free(*user_data);
        *user_data = NULL;
        *user_data_size = 0;
        goto done;
    }

    ret = 0;
done:
    return ret;
}

oe_quote_customization_plugin_context_t oe_plugin_context = {
    .format_id = UUID_INIT(
        0x6EBB65E5,
        0xF657,
        0x48B1,
        0x94,
        0xDF,
        0x0E,
        0xC0,
        0xB6,
        0x71,
        0xDA,
        0x26),
    .on_register = plugin1_on_register,
    .on_unregister = plugin1_on_unregister,
    .get_evidence = plugin1_get_evidence,
    .free_evidence = plugin1_free_evidence,
    .verify_evidence = plugin1_verify_evidence};

oe_quote_customization_plugin_context_t* create_plugin1()
{
    return &oe_plugin_context;
}
