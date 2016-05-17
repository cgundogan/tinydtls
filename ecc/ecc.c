/*******************************************************************************
*
* Copyright (c) 2015, 2016 Olaf Bergmann (TZI) and others.
* All rights reserved. This program and the accompanying materials
* are made available under the terms of the Eclipse Public License v1.0
* and Eclipse Distribution License v. 1.0 which accompanies this distribution.
*
* The Eclipse Public License is available at http://www.eclipse.org/legal/epl-v10.html
* and the Eclipse Distribution License is available at 
* http://www.eclipse.org/org/documents/edl-v10.php.
*
*******************************************************************************/

#include "ecc.h"
#include <stddef.h>

///////////////////////////////////////////////////////
// Functions to set the callbacks for crypto operations
///////////////////////////////////////////////////////

static dtls_ec_make_key_Function g_make_key_cb = NULL;

void dtls_ec_set_make_key_cb(dtls_ec_make_key_Function p_make_key_cb)
{
    g_make_key_cb = p_make_key_cb;
}

static dtls_ec_shared_secret_Function g_shared_secret_cb = NULL;

void dtls_ec_set_shared_secret_cb(dtls_ec_shared_secret_Function p_shared_secret_cb)
{
    g_shared_secret_cb = p_shared_secret_cb;
}

static dtls_ec_sign_Function g_sign_cb = NULL;

void dtls_ec_set_sign_cb(dtls_ec_sign_Function p_sign_cb)
{
    g_sign_cb = p_sign_cb;
}

static dtls_ec_verify_Function g_verify_cb = NULL;

void dtls_ec_set_verify_cb(dtls_ec_verify_Function p_verify_cb)
{
	g_verify_cb = p_verify_cb;
}

static dtls_ec_ecdhe_Function g_ecdhe_cb = NULL;

void dtls_ec_set_ecdhe_cb(dtls_ec_ecdhe_Function p_ecdhe_cb)
{
	g_ecdhe_cb = p_ecdhe_cb;
}

static dtls_ec_get_pubkey_Function g_get_pubkey_cb = NULL;

void dtls_ec_set_get_pubkey_cb(dtls_ec_get_pubkey_Function p_get_pubkey_cb)
{
	g_get_pubkey_cb = p_get_pubkey_cb;
}

///////////////////////////////////////////////////////

// Safe calls to the callback functions
int dtls_ec_make_key(uint8_t p_publicKey[], uint8_t p_privateKey[], uECC_Curve curve)
{
    // Check for a valid function pointer
    if (g_make_key_cb != NULL)
    {
        return g_make_key_cb(p_publicKey, p_privateKey, curve);
    }
    else
    {
        return uECC_make_key(p_publicKey, p_privateKey, curve);
    }
}

int dtls_ec_shared_secret(const uint8_t p_publicKey[], const uint8_t p_privateKey[], uint8_t p_secret[], uECC_Curve p_curve)
{
    // Check for a valid function pointer
    if (g_shared_secret_cb != NULL)
    {
        return g_shared_secret_cb(p_publicKey, p_privateKey, p_secret, p_curve);
    }
    else
    {
        return uECC_shared_secret(p_publicKey, p_privateKey, p_secret, p_curve);
    }
}

int dtls_ec_sign(const uint8_t p_privateKey[], const uint8_t p_hash[],
             unsigned p_hash_size, uint8_t *p_signature, uECC_Curve p_curve)
{
    // Check for a valid function pointer
    if (g_sign_cb != NULL)
    {
        return g_sign_cb(p_privateKey, p_hash, p_hash_size, p_signature, p_curve);
    }
    else
    {
        return uECC_sign(p_privateKey, p_hash, p_hash_size, p_signature, p_curve);
    }
}


int dtls_ec_verify(const uint8_t p_publicKey[], const uint8_t p_hash[],
                   unsigned p_hash_size, const uint8_t *p_signature, uECC_Curve p_curve)
{
	// Check for a valid function pointer
	if (g_verify_cb != NULL)
	{
		return g_verify_cb(p_publicKey, p_hash, p_hash_size, p_signature, p_curve);
	}
	else
	{
		return uECC_verify(p_publicKey, p_hash, p_hash_size, p_signature, p_curve);
	}
}

int dtls_ec_ecdhe(const uint8_t p_public_key_in[], uint8_t p_public_key_out[], uint8_t p_secret[])
{
	// Check for a valid function pointer
	if (g_ecdhe_cb != NULL)
	{
		return g_ecdhe_cb(p_public_key_in, p_public_key_out, p_secret);
	}
	else
	{
		return 0; // No default implementation
	}
}

int dtls_ec_get_pubkey(const uint8_t p_key_handle[], uint8_t p_public_key[])
{
	// Check for a valid function pointer
	if (g_get_pubkey_cb != NULL)
	{
		return g_get_pubkey_cb(p_key_handle, p_public_key);
	}
	else
	{
		return 0; // No default implementation
	}
}
