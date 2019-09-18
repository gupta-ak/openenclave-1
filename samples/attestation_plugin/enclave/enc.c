// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// TODO:
// 1. add verify_full_evidence support
// 2. add support for get_tcb info, get_crl info, get qe identity info
//    Serialize and deserialize, and verufy time
// 3. Add oe_verify_report_ex(), which takes tcbinfo, qe_ide, and crl as inputs
// 4. Add a plugin smaple for verify_full_evidence
// 5. add a other report type for token

#include <stdio.h>
#include <stdlib.h>
// Include the trusted attestation_plugin header that is generated
// during the build. This file is generated by calling the
// sdk tool oeedger8r against the attestation_plugin.edl file.
#include "attestation_plugin_t.h"

// Contains a helper function to generate the first plugin.
#include "plugin1/plugin1.h"

// This is function demostrates how an attestation plugin is called.
void enclave_attestation_plugin()
{
    oe_result_t result = OE_FAILURE;
    uint8_t* evidence_buffer1 = NULL;
    size_t evidence_buffer1_size = 0;
    oe_claim_element_t* claims = NULL;
    size_t claim_count = 0;
    uint8_t* user_data1 = NULL;
    size_t user_data_size1 = 0;
    oe_quote_customization_plugin_context_t* plugin1 = create_oe_plugin();

    fprintf(stdout, "Hello from enclave::enclave_attestation_plugin\n");

    // Register attestation plugins.
    result = oe_register_attestation_plugin(plugin1, NULL, 0);
    if (result != OE_OK)
    {
        fprintf(
            stdout,
            "oe_register_attestation_plugin failed for "
            "evidence_format_uuid (1)\n");
        goto done;
    }
    fprintf(
        stdout,
        "oe_register_attestation_plugin succeeded for "
        "evidence_format_uuid (1)\n");

    result = oe_get_attestation_evidence(
        &plugin1->evidence_format_uuid,
        (const uint8_t*)"Hello World!",
        sizeof("Hello World!") - 1,
        &evidence_buffer1,
        &evidence_buffer1_size);
    if (result != OE_OK)
    {
        fprintf(
            stdout,
            "oe_get_attestation_evidence failed for "
            "evidence_format_uuid (1) with %s\n",
            oe_result_str(result));
        goto done;
    }
    fprintf(
        stdout,
        "oe_get_attestation_evidence succeeded with "
        "evidence_buffer1_size=%zu\n",
        evidence_buffer1_size);

    result = oe_verify_attestation_evidence(
        evidence_buffer1,
        evidence_buffer1_size,
        &claims,
        &claim_count,
        &user_data1,
        &user_data_size1);
    if (result != OE_OK)
    {
        fprintf(
            stdout,
            "oe_verify_attestation_evidence failed for "
            "evidence_format_uuid (1) with %s\n",
            oe_result_str(result));
        goto done;
    }

    fprintf(
        stdout,
        "oe_verify_attestation_evidence succeeded for evidence_format_uuid "
        "(1)\n");

    // Call back into the host to test the host side plugin.
    result = host_attestation_plugin();
    if (result != OE_OK)
    {
        fprintf(
            stderr,
            "Call to host_helloworld failed: result=%u (%s)\n",
            result,
            oe_result_str(result));
    }

    // Unregister all attestation plugins
    result = oe_unregister_attestation_plugin(plugin1);
    if (result != OE_OK)
        goto done;
    fprintf(
        stdout,
        "oe_unregister_attestation_plugin succeeded for "
        "evidence_format_uuid (1)\n");
done:
    oe_free_attestation_evidence(evidence_buffer1);
    return;
}
