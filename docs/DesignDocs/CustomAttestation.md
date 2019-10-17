___

Custom Attestation Data Formats for Open Enclave
=====

This design document proposes a new attestation framework and set of APIs that
enable developers to use custom formats for their attestation data.  

Motivation
----------

Currently, Open Enclave provides several APIs that developers can use for
attestation. The two key functions are `oe_get_report`, which produces an opaque
blob that is signed by the enclave, and `oe_verify_report`, which can be used to
verify the generated report. The original purpose of those two APIs were to
provide a simple, cross-platform way to produce and verify attestation data.

However, some developers need more flexibility for their attestation
requirements. For example, one might want to extend Open Enclave's
current attestation structures with extra information, such as geolocation
or a timestamp. Another user might want their enclaves to generate attestation
data that is in a compatible format with their existing authentication
infrastructure, such as a JSON Web Token or an X.509 certificate. There are also
users who want to specify their endorsements (information from a second source
used for verification), instead of using the set of endorsements provided by Open
Enclave.

Overall, there has been interest in enhancing Open Enclave's APIs to support
custom attestation formats to enable these scenarios.

Terminology
-----------

This document uses the following terminology defined below. Note that
these definitions are consistent with the terms defined in the
[Remote Attestation Procedures (RATS)](https://datatracker.ietf.org/wg/rats/about/)
working group.

- Claims
  - Claims are statements about a particular subject. They consist of
    name-value pairs containing the claim name, which is a string, and
    claim value, which is arbitrary data. Example of claims could be
    [name="version", value=1] or [name="enclave_id", value=1111].
- Evidence
  - This is the data about the enclave that is produced and signed by it.
    The SGX report would be an example of evidence.
- Endorsements
  - This is additional data that used in the evidence verification process,
    but is not produced by the enclave. An example of an endorsement would be
    the quoting enclave's identity used in SGX remote attestation, because it
    is retrieved from Intel's servers, rather than the enclave.
- Verifier
  - The verifier is responsible for taking in the evidence and endorsements
    and deciding if the enclave is trustworthy.
- Relying party
  - The relying party is the entity interested in communicating with an
    enclave. The enclave must attest to the relying party before the
    relying party can trust it. The relying party can also play the role
    of the verifier, but it does not necessarily have to.

Specification
-------------

To support custom attestation formats, this document proposes adding a plugin
model for attestation. The Open Enclave SDK will define a set of common APIs
that each plugin must implement. Each plugin will define an UUID to distinguish
it from other plugins.

Futhermore, there will be additional attestation "plugin aware" APIs that are
analogous to `oe_get_report` and `oe_verify_report`, along with functions for
registering and unregistering plugins. The user can statically link in their
desired plugin and call the register plugin function. The attestation data can
be retrieved from the "plugin aware" analogue of `oe_get_report` with the
desired UUID. The generated data will have the UUID in its header. The user can
call the analogue of `oe_verify_report` to verify the data and the Open Enclave
runtime can use this UUID to determine what plugin verification routine to run.

### Plugin API

Each plugin must implement the functions below:

```C
/**
 * Claims struct used for claims parameters for the plugin.
 */
struct oe_claim_t
{
    char* name;
    uint8_t* value;
    size_t value_size;
};

/**
 * Struct that defines the structure of each plugin. Each plugin must
 * define an UUID for its format and implement the functions in this
 * struct. Ideally, each plugin should provide a helper function to
 * create this struct on the behalf of the plugin users.
 */
struct oe_attestation_plugin_t
{
    /**
     * The UUID for the plugin.
     */
    uuid_t format_id;

    /**
     * The function that gets executed when a plugin is registered.
     *
     * @param[in] plugin_context A pointer to the attestation plugin struct.
     * @param[in] config_data An optional pointer to the configuration data.
     * @param[in] config_data_size The size in bytes of config_data.
     * @retval OE_OK on success.
     */
    oe_result_t (*on_register)(
        oe_attestation_plugin_t* plugin_context,
        const void* config_data,
        size_t config_data_size);

    /**
     * The function that gets executed when a plugin is unregistered.
     *
     * @param[in] plugin_context A pointer to the attestation plugin struct.
     * @retval OE_OK on success.
     */
    oe_result_t (*on_unregister)(
        oe_attestation_plugin_t* plugin_context);

    /**
     * Generates the attestation evidence, which is defined as the data
     * produced by the enclave. The caller may pass in custom claims, which
     * must be attached to the evidence and then cryptographically signed.
     *
     * @param[in] plugin_context A pointer to the attestation plugin struct.
     * @param[in] input_params The optional plugin-specific input parameters.
     * @param[in] input_params_size The size of input_params.
     * @param[in] custom_claims The optional custom claims list.
     * @param[in] custom_claims_length The number of custom claims.
     * @param[out] evidence_buffer An output pointer that will be assigned the
     * address of the evidence buffer.
     * @param[out] evidence_buffer_size A pointer that points to the size of the
     * evidence buffer.
     * @param[out] endorsements_buffer An output pointer that will be assigned the
     * address of the endorsements buffer.
     * @param[out] endorsements_buffer_size A pointer that points to the size of the
     * endorsements buffer.
     * @retval OE_OK on success.
     */
    oe_result_t (*get_evidence)(
        oe_attestation_plugin_t* plugin_context,
        const void* input_params,
        size_t input_params_size,
        const oe_claim_t* custom_claims,
        size_t custom_claims_length,
        uint8_t** evidence_buffer,
        size_t* evidence_buffer_size,
        uint8_t** endorsements_buffer,
        size_t* endorsements_buffer_size);

    /**
     * Frees the generated attestation evidence.
     *
     * @param[in] plugin_context A pointer to the attestation plugin struct.
     * @param[in] evidence_buffer A pointer to the evidence buffer.
     * @retval OE_OK on success.
     */
    oe_result_t (*free_evidence)(
        oe_attestation_plugin_t* plugin_context,
        uint8_t* evidence_buffer);

    /**
     * Frees the generated attestation endorsements.
     *
     * @param[in] plugin_context A pointer to the attestation plugin struct.
     * @param[in] endorsements_buffer A pointer to the endorsements buffer.
     * @retval OE_OK on success.
     */
    oe_result_t (*free_endorsements)(
        oe_attestation_plugin_t* plugin_context,
        uint8_t* endorsements_buffer);

    /**
     * Verifies the attestation evidence and returns the claims contained in
     * the evidence.
     *
     * @param[in] plugin_context A pointer to the attestation plugin struct.
     * @param[in] evidence_buffer The evidence buffer.
     * @param[in] evidence_buffer_size The size of evidence_buffer in bytes.
     * @param[in] endorsements_buffer The endorsements buffer.
     * @param[in] endorsements_buffer_size The size of endorsements_buffer in bytes.
     * @param[in] input_validation_time Optional datetime to use when verifying
     * evidence. If not specified, it will use the creation_datetime of the
     * endorsements (if any endorsements are provided).
     * @param[out] claims The list of claims.
     * @param[out] claims_length The number of claims.
     * @retval OE_OK on success.
     */
    oe_result_t (*verify_evidence)(
        oe_attestation_plugin_t* plugin_context,
        const uint8_t* evidence_buffer,
        size_t evidence_buffer_size,
        const uint8_t* endorsements_buffer,
        size_t endorsements_buffer_size,
        const oe_datetime_t* input_validation_time,
        oe_claim_t** claims,
        size_t* claims_length);
};
```

Here is the rationale for each element in the plugin struct:

- `format_id`
  - Each plugin needs an unique identifier to distinguish itself.
- `on_register` and `on_unregister`
  - A plugin might require some setup or teardown when it is registered or
    unregistered, so these functions are required. Furthermore, a plugin
    might require configuration, which is why there is a `config_data`
    parameter. The configuration data can be plugin specific, so no format is
    specified in this proposal.
- `get_evidence`, `free_evidence`, and `free_endorsements`
  - Producing evidence and endorsements is necessary for attestation.
  - There an `input_params` field because some plugins might require plugin
    specific input. For example, the SGX local attestation needs the
    other enclave's target info struct.
  - There is a `custom_claims` parameter because many attestation protocols
    require the enclave to sign some claim from a relying party. For example,
    many protocols follow the "challenge response" architecture, which requires
    the enclave to sign a nonce from the relying party.
  - There is an `endorsements` parameters to return the endorsements that are
    coupled with the evidence to ensure that the evidence and endorsements are
    in sync.
- `verify_evidence`
  - Verifying evidence and endorsements is essential for attestation.
  - The `claims` field contains key-value pairs that can be verified by the
    caller. This will have the similar contents as the `oe_identity_t` field
    in the `oe_report_t` struct returned by `oe_verify_report` and any custom
    claims that were passed to the `get_evidence` function.
  - The `input_validation_time` is needed to validate the evidence against a
    specific time.

###  Known Open Enclave Claims

- Each plugin's `verify_evidence` function must, at minimum, return the
  following claims (mapped from the `oe_identity_t`):
  
| Claim Name       | Claim Value Type   | Description                                                          |
|:-----------------|:-------------------|:---------------------------------------------------------------------|
| id_version       | uint32_t           | Claims version. Must be 0                                            |
| security_version | uint32_t           | Security version of the enclave. (ISVN for SGX).                     |
| attributes       | uint64_t           | Attributes flags for the evidence: <br/> `OE_REPORT_ATTRIBUTES_DEBUG`: The evidence is for a debug enclave.<br/> `OE_REPORT_ATTRIBUTES_REMOTE`: The evidence can be used for remote attestation.   |
| unique_id        | uint8_t[32]        | The unique ID for the enclave (MRENCLAVE for SGX).                   |
| signer_id        | uint8_t[32]        | The signer ID for the enclave (MRSIGNER for SGX).                    |
| product_id       | uint8_t[32]        | The product ID for the enclave (ISVPRODID for SGX).                  |
| validity_from    | oe_datetime_t      | Overall datetime from which the evidence and endorsements are valid. |
| validity_until   | oe_datetime_t      | Overall datetime at which the evidence and endorsements expire.      |

### Built-in SGX Plugin

The current Open Enclave attestation only works on SGX platforms, so it will
be moved to an SGX plugin. Most of the current Open Enclave APIs can be mapped
directly to the plugin APIs. For the `on_register` and `on_unregister`  APIs,
they can simply be no-ops. `oe_get_report` can be mapped to the `get_evidence` API and
`oe_verify_report` can be mapped to the `verify_evidence` API.

### SGX Plug-In Definitions

`sgx_attestation_plugin.h`
```C

/* Define the uuid. */
#define SGX_PLUGIN_UUID                 \
{                                       \
 0x2f, 0x50, 0xdc, 0xb4,                \
 0x79, 0x9c,                            \
 0x45, 0x07,                            \
 0xa1, 0xe9,                            \
 0x86, 0x2c, 0x62, 0x9b, 0x76, 0x2a}    \
}

/*! sgx_attestation_plugin
 * 
 * Return the SGX attesation plug-in.
 */
oe_attestation_plugin_t* sgx_attestation_plugin();

```

`sgx_attestation_plugin.c`
```C
#include "sgx_attestation_plugin.h"

/* Struct containing params for oe report functions. */
struct sgx_params_t {
    uint32_t flags;
    void* target_info;
    size_t target_info_size;
};

static
oe_result_t
sgx_attestation_plugin_on_register(
    oe_attestation_plugin_t* plugin_context,
    const void* config_data,
    size_t config_data_size)
{
    OE_UNUSED(plugin_context);
    OE_UNUSED(config_data);
    OE_UNUSED(config_data_size);

    // Nothing to do
    return OE_OK;
}

static 
oe_result_t 
sgx_attestation_plugin_on_unregister(
    oe_attestation_plugin_t* plugin_context)
{
    OE_UNUSED(plugin_context);

    // Nothing to do
    return OE_OK;
}

static 
oe_result_t 
sgx_attestation_plugin_get_evidence(
    oe_attestation_plugin_t* plugin_context,
    const void* input_params,
    size_t input_params_size,
    const oe_claim_t* custom_claims,
    size_t custom_claims_length,
    uint8_t** evidence_buffer,
    size_t* evidence_buffer_size,
    uint8_t** endorsements_buffer,
    size_t* endorsements_buffer_size)
{
    OE_UNUSED(plugin_context);

    /*
     * Pseudocode description instead of actual C code:
     * 
     * Cast input_params to sgx_params_t struct.
     * Hash custom claims field.
     * Call oe_get_report with sgx_params_t struct filling in the flags and opt_param parameters.
     * and the hash filling in the report data parameter.
     * Report contains the endorsements, so extract them out.
     * Evidence will be report + custom_claims blob.
     */

    return OE_OK;
}

static 
oe_result_t 
sgx_attestation_plugin_free_evidence(
    oe_attestation_plugin_t* plugin_context,
    uint8_t* evidence_buffer)
{
    OE_UNUSED(plugin_context);

    return oe_free_report(evidence_buffer);
}

static 
oe_result_t 
sgx_attestation_plugin_free_endorsements(
    oe_attestation_plugin_t* plugin_context,
    uint8_t* endorsements_buffer)
{
    OE_UNUSED(plugin_context);

    return oe_free_endorsements(endorsements_buffer);
}

static 
oe_result_t 
sgx_attestation_plugin_verify_evidence(
    oe_attestation_plugin_t* plugin_context,
    const uint8_t* evidence_buffer,
    size_t evidence_buffer_size,
    const uint8_t* endorsements_buffer,
    size_t endorsements_buffer_size,
    const uint8_t* verification_params,
    size_t verification_params_size,
    uint_t** claims,
    size_t* claims_size)
{
    OE_UNUSED(plugin_context);

    /*
     * Pseudocode description instead of actual C code:
     *
     * Call oe_verify_report will all the input parameters and get the oe_identity_t back.
     * Look for the custom claims in the evidence header and extract them if found.
     * Verify the hash of custom claims == report data field in evidence report.
     * Convert oe_identity_t to the claims format.
     */

    return OE_OK;
}

/* Setting up the plugin struct. */
oe_attestation_plugin_t sgx_attestation_plugin = {

 /* Plugin UUID. */
 .format_id = SGX_PLUGIN_UUID,

 .on_register = sgx_attestation_plugin_on_register,
 .on_unregister = sgx_attestation_plugin_on_unregister,
 .get_evidence = sgx_attestation_plugin_get_evidence,
 .free_evidence = sgx_attestation_plugin_free_evidence,
 .free_endorsements = sgx_attestation_plugin_free_endorsements,
 .verify_evidence = sgx_attestation_plugin_verify_evidence,
};

/* Implement helper initialization function. */
oe_attestation_plugin_t* sgx_attestation_plugin() {
    return &sgx_attestation_plugin;
}

```

### New Open Enclave APIs

The functions are what the plugin user calls to use a plugin. They map almost
exactly to the plugin API. The main difference is that `oe_get_evidence`
require the UUID of the plugin as an input parameter.

```C
/**
 * oe_register_attestation_plugin
 *
 * Registers a new attestation plugin and optionally configures it with plugin
 * specific configuration data. The function will fail if the plugin UUID has
 * already been registered.
 * 
 * This is available in the enclave and host.
 *
 * @param[in] plugin A pointer to the attestation plugin struct. Note that will
 * not copy the contents of the pointer, so the pointer must be kept valid until
 * the plugin is unregistered.
 * @param[in] config_data An optional pointer to the configuration data.
 * @param[in] config_data_size The size in bytes of config_data.
 * @retval OE_OK The function succeeded.
 * @retval OE_ALREADY_EXISTS A plugin with the same UUID is already registered.
 */
oe_result_t oe_register_attestation_plugin(
    oe_attestation_plugin_t* plugin,
    const void* config_data,
    size_t config_data_size);

/**
 * oe_unregister_attestation_plugin
 *
 * Unregisters an attestation plugin. This is available in the enclave and host.
 * 
 * @param[in] plugin A pointer to the attestation plugin struct.
 * @retval OE_OK The function succeeded.
 * @retval OE_NOT_FOUND The plugin does not exist.
 */
oe_result_t oe_unregister_attestation_plugin(
    oe_attestation_plugin_t* plugin);

/**
 * oe_get_evidence
 *
 * Generates the attestation evidence for the given UUID attestation format.
 * This function is only available in the enclave.
 *
 * @param[in] evidence_format_uuid The UUID of the plugin.
 * @param[in] input_params The optional plugin-specific input parameters.
 * @param[in] input_params_size The size of input_params.
 * @param[in] custom_claims The optional custom claims list.
 * @param[in] custom_claims_length The number of custom claims.
 * @param[out] evidence_buffer An output pointer that will be assigned the
 * address of the evidence buffer.
 * @param[out] evidence_buffer_size A pointer that points to the size of the
 * evidence buffer.
 * @param[out] endorsements_buffer An output pointer that will be assigned the
 * address of the endorsements buffer.
 * @param[out] endorsements_buffer_size A pointer that points to the size of the
 * endorsements buffer.
 * @retval OE_OK The function succeeded.
 * @retval OE_NOT_FOUND The plugin does not exist.
 */
oe_result_t oe_get_evidence(
    const uuid_t* evidence_format_uuid,
    const void* input_params,
    size_t input_params_size,
    const oe_claim_t* custom_claims,
    size_t custom_claims_length,
    uint8_t** evidence_buffer,
    size_t* evidence_buffer_size,
    uint8_t** endorsements_buffer,
    size_t* endorsements_buffer_size);

/**
 * oe_free_evidence
 *
 * Frees the attestation evidence. This function is only available in the enclave.
 *
 * @param[in] evidence_buffer A pointer to the evidence buffer.
 * @retval OE_OK on success.
 */
oe_result_t oe_free_evidence(uint8_t* evidence_buffer);

/**
 * oe_free_endorsements
 * 
 * Frees the generated attestation endorsements. This function is only available in the enclave.
 *
 * @param[in] endorsements_buffer A pointer to the endorsements buffer.
 * @retval OE_OK on success.
 */
oe_result_t oe_free_endorsements(uint8_t* endorsements_buffer);

/**
 * oe_verify_evidence
 *
 * Verifies the attestation evidence and returns well known and custom claims.
 * This is available in the enclave and host.
 *
 * @param[in] evidence_buffer The evidence buffer.
 * @param[in] evidence_buffer_size The size of evidence_buffer in bytes.
 * @param[in] endorsements_buffer The endorsements buffer.
 * @param[in] endorsements_buffer_size The size of endorsements_buffer in bytes.
 * @param[in] input_validation_time Optional datetime to use when verifying
 * evidence. If not specified, it will use the creation_datetime of the
 * endorsements (if any endorsements are provided).
 * @param[out] claims The list of claims.
 * @param[out] claims_length The length of the claims list.
 * @retval OE_OK on success.
 */
oe_result_t oe_verify_evidence(
    const uint8_t* evidence_buffer,
    size_t evidence_buffer_size,
    const uint8_t* endorsements_buffer,
    size_t endorsements_buffer_size,
    const oe_datetime_t* input_validation_time,
    oe_claim_t** claims,
    size_t* claims_length);
```

The outputs returned by `oe_get_endorsements` will begin with the header
specified below. This allows `oe_verify_evidence` to determine what plugin
verification routine to use. Note that since these functions return opaque
structures, these headers are internal and not visible to the SDK consumers
or the plugin writers.

```C
/*
 * Header will be sent to oe_verify_evidence but not to the
 * plugin verification routines.
 */
typedef struct _oe_attestation_header
{
    /* Set to + 1 of existing header version. */
    uint32_t version;

    /* UUID to identify format. */
    uuid_t format_id;

    /* Size of evidence/endorsements sent to the plugin. */
    uint32_t data_size;

    /* The actual data */
    uint8_t data[];

    /* data_size bytes that follows the header will be sent to a plugin. */
} oe_attestation_header_t;
```

### Backwards compatibility
The new APIs should support verifying the old Open Enclave reports
generated by `oe_get_report`. The `oe_attestation_header_t` structure
shares the same 1st field (`uint32_t version`) as the old Open Enclave
report header. Consequently, the `oe_verify_evidence` can use this
information to decide if it needs to call a plugin or run the legacy
verification routine (which is technically the same logic as the SGX plugin).

User Experience
---------------

### Plug-in
There are two types of users: the plugin writers and the plugin consumers.

Plugin writers will implement their plugin according to the plugin API.
They should also provide a helper function that makes it easy for plugin
consumers to register the plugin as shown below:

`my_plugin.h`
```C
/* Helper function to create the plugin. */
oe_attestation_plugin_t* my_plugin();

/* Define the uuid. */
#define MY_PLUGIN_UUID                  \
{                                       \
 0x13, 0x99, 0x9a, 0xe5,                \
 0x23, 0xbe,                            \
 0x4f, 0xd4,                            \
 0x86, 0x63,                            \
 0x42, 0x1e, 0x3a, 0x57, 0xa0, 0xa4}    \
}

/* Example struct used for config data for my_plugin->on_register. */
struct my_plugin_config_data_t { ... };

/* Example struct used as input parameters for my_plugin->get_evidence. */
struct my_plugin_input_params_t { ... };
```

`my_plugin.c`
```C
/* Plugin implementation functions here. */
static oe_result_t my_plugin_on_register(
    oe_attestation_plugin_t* context,
    const void* config_data,
    size_t config_data_size)
{
    struct my_plugin_config_data_t* my_data = (struct my_plugin_config_data_t*) config_data;
    /* Do meaningful work with my_data here. */
    return OE_OK;
}

static oe_result_t my_plugin_on_unregister(...) { ... }
static oe_result_t my_plugin_get_evidence(...) { ... }
static oe_result_t my_plugin_free_evidence(...) { ... }
static oe_result_t my_plugin_free_endorsements(...) { ... }
static oe_result_t my_plugin_verify_evidence(...) { ... }

/* Setting up the plugin struct. */
oe_attestation_plugin_t my_plugin = {
 /* Plugin UUID. */
 .format_id = MY_PLUGIN_UUID,

  /* Plugin functions. */
 .on_register = my_plugin_on_register,
 .on_unregister = my_plugin_on_unregister,
 .free_evidence = my_plugin_free_evidence,
 .free_endorsements = my_plugin_free_endorsements,
 .verify_evidence = my_plugin_verify_evidence
};

/* Implement helper initialization function. */
oe_attestation_plugin_t* my_plugin() {
    return &my_plugin;
}
```

They can then compile their code in the standard way for building Open Enclave
enclave and host applications.

Plugin consumers will use the new "plugin aware" APIs like
`oe_get_attestation_evidence`. The enclave can generate the evidence
using the plugin like this:

enclave.c
```C
#include <my_plugin.h>

/* Register plugin. Send the config data if necessary. */
struct my_config_data_t config = { ... };
size_t config_size = sizeof(config);
oe_register_plugin(my_plugin(), &config, config_size);

/* Create input params struct if needed. */
struct my_plugin_input_params_t params = { ... };
size_t params_size = sizeof(params);

/* Create claims if desired. */
oe_claim_t claims = { ... };
size_t claims_size = ...;

/* Get evidence. */
oe_get_attestation_evidence(
    MY_PLUGIN_UUID,
    &params,
    params_size,
    my_custom_claims,
    my_custom_claims_size,
    &evidence,
    &evidence_size,
    &endorsements,
    &endorsements_size);

/* Send the evidence to the verifier. Protocol is up to enclave and verifier. */
send(VERIFIER_SOCKET_FD, evidence, evidence_size, 0);
send(VERIFIER_SOCKET_FD, endorsements, endorsements_size, 0);

/* Unregister plugin. */
oe_unregister_plugin(my_plugin());
```

The verifier, which can either be the enclave or the host, can verify the evidence like this:

verifier.c
```C
#include <my_plugin.h>

/* Register plugin. Send the config data if necessary. */
struct my_config_data_t config = { ... };
size_t config_size = sizeof(config);
oe_register_plugin(my_plugin(), &config, config_size);

/* Receive evidence and endorsement buffer from enclave. */
recv(ENCLAVE_SOCKET_FD, evidence, evidence_size, 0);
recv(ENCLAVE_SOCKET_FD, endorsements, endorsements_size, 0);

/* Set input validation time if desired. */
oe_datetime_t input_validation_time = { ... };

/* Verify evidence. Can check the claims if desired. */
oe_verify_attestation_evidence(
    evidence,
    evidence_size,
    endorsements,
    endorsements_size,
    &input_validation_time,
    &claims,
    &claims_size);
```

In either case, the plugin user can link in the plugin to build their app:

```bash
gcc -o my_app [enclave.o | verifier.o] my_plugin.o ...
```

Alternates
----------

Another option is to transform the Open Enclave report from a platform-specific
opaque blob to something like a JWT/CWT token or X.509 cert, which contains
platform-specific attestation data embedded inside it. This makes it easy to add
or parse claims and extend the report format. However, users would be constrained
to the format chosen by Open Enclave and they will not be able to use their own
custom format.

Authors
-------

Name: Akash Gupta

Email: akagup@microsoft.com

Github username: gupta-ak
