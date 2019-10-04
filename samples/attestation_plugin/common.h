// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _SAMPLES_ATTESTATION_PLUGIN_COMMON_H
#define _SAMPLES_ATTESTATION_PLUGIN_COMMON_H

// Define the custom user data.
#define USER_DATA                                                              \
    "{\n"                                                                      \
    "    \"nonce\": \"09af62b1390237ab\",\n"                                   \
    "    \"public_key\": "                                                     \
    "\"04543822c3aba90f34278e84ea0cdb776a005da29182223306c\n"                  \
    "                   cbc155ddaac033991f8440bdeec5b22ce7c88826ee74ae4cdc7\n" \
    "                   d05fe8b5027f149019a08bf2081f\"\n"                      \
    "}"

#endif

static inline void print_claims(
    const oe_claim_element_t* claims,
    size_t claims_count)
{
    printf("claims list:\n");
    for (int i = 0; i < claims_count; i++)
    {
        printf("  %s = [", claims[i].name);
        for (int j = 0; j < claims[i].len; j++)
        {
            printf(" %hhu", claims[i].value[j]);
        }
        printf(" ]\n");
    }
}
