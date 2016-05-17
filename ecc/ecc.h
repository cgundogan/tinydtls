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

#ifndef _ECC_H_
#define _ECC_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

/*
 * DTLS_CRYPTO_HAL
 */

struct dtls_ec_curve_t;
typedef const struct dtls_ec_eurve_t * dtls_ec_curve;

/**
* Call this function to create a unique public-private key pair in secure hardware
*
* @param[out] p_publicKey  The public key that is associated with the private key that was just created.
* @param[out] p_privateKeyHandle  A handle that is used to point to the private key stored in hardware.
* @return 1 upon success, 0 if an error occurred.
*/
typedef int (*dtls_ec_make_key_Function)(uint8_t p_publicKey[], uint8_t p_privateKeyHandle[], dtls_ec_curve curve);

/**
* Set the callback function that will be used to generate a public-private key pair.
* This function will replace uECC_make_key.
*
* @param[in] p_make_key_cb  The function that will be used to generate a public-private key pair.
*/
void dtls_ec_set_make_key_cb(dtls_ec_make_key_Function p_make_key_cb);

/**
* Call this function to sign a hash using a hardware protected private key.
*
* @param[in] p_privateKeyHandle  A handle that is used to point to the private key stored in hardware.
* @param[in] p_hash  The hash to sign.
* @param[out] p_signature  The signature that is produced in hardware by the private key..
* @return 1 upon success, 0 if an error occurred.
*/
typedef int (*dtls_ec_sign_Function)(uint8_t p_privateKeyHandle[], const uint8_t p_hash[], unsigned p_hash_size, uint8_t p_signature[], dtls_ec_curve p_curve);

/**
* Set the callback function that will be used to sign.
* This function will replace uECC_sign.
*
* @param[in] p_sign_cb  The function that will be used to sign.
*/
void dtls_ec_set_sign_cb(dtls_ec_sign_Function p_sign_cb);

/**
* Call this function to verify a signature using the public key and hash that was signed. 
*
* @param[in] p_publicKey  The public key that is associated with the private key that produced the signature.
* @param[in] p_hash  The hash that was signed.
* @param[in] p_signature  The signature that was produced the private key that is associated with p_public_key
* @return 1 upon success, 0 if an error occurred.
*/
typedef int (*dtls_ec_verify_Function)(const uint8_t p_publicKey[], const uint8_t p_hash[], unsigned p_hash_size, const uint8_t *p_signature, dtls_ec_curve p_curve);

/**
* Set the callback function that will be used to verify.
* This function will replace uECC_verify.
*
* @param[in] p_verify_cb  The function that will be used to verify.
*/
void dtls_ec_set_verify_cb(dtls_ec_verify_Function p_verify_cb);

/**
* Call this function to produce an ECDH shared key using the public key of the other node.
* A hardware protected private key will be used for the point multiply
*
* @param[in] p_publicKey  The public key from the other node used for communication.
* @param[in] p_privateKeyHandle  A handle that is used to point to the private key stored in hardware.
* @param[out] p_secret  The pre-master key that is produced by the point multiply with p_public_key and our private key
* @return 1 upon success, 0 if an error occurred.
*/
typedef int (*dtls_ec_shared_secret_Function)(const uint8_t p_publicKey[], const uint8_t p_privateKeyHandle[], uint8_t p_secret[], dtls_ec_curve curve);

/**
* Set the callback function that will be used to produce a shared secret.
* This function will replace uECC_shared_secret.
*
* @param[in] p_make_key_cb  The function that will be used to generate the shared secret.
*/
void dtls_ec_set_shared_secret_cb(dtls_ec_shared_secret_Function p_shared_secret_cb);

/**
* Call this function to produce a shared key using the public key of the other node.
* An ephemeral private key will be created in secure hardware that will be used for the point multiply
*
* @param[in] p_public_key  The public key from the other node used for communication.
* @param[out] p_public_key_out  The ephemeral public key that will be used in the point multiply.
* @param[out] p_secret  The pre-master key that is produced by the point multiply with p_public_key and our private key
* @return 1 upon success, 0 if an error occurred.
*/
typedef int (*dtls_ec_ecdhe_Function)(const uint8_t p_public_key_in[],
                                      uint8_t p_public_key_out[],
                                      uint8_t p_secret[]);

/**
* Set the callback function that will be used to produce a ECDHE shared secret.
*
* @param[in] p_ecdhe_cb  The function that will be used to generate the ECDHE shared secret.
*/
void dtls_ec_set_ecdhe_cb(dtls_ec_ecdhe_Function p_ecdhe_cb);

/**
* Call this function to return the public key for an existing private key.
*
* @param[out] p_key_handle  A handle that is used to point to the private key stored in hardware.
*    The public key that is associated with this private key will be returned
* @param[out] p_public_key  The public key that is associated with the private key that was just created.
* @return 1 upon success, 0 if an error occurred.
*/
typedef int (*dtls_ec_get_pubkey_Function)(const uint8_t p_key_handle[],
                                           uint8_t p_public_key[]);

/**
* Set the callback function that will be used to return the public key for an existing private key.
*
* @param[in] p_get_pubkey_cb  The function that will be used to return the public key for an existing private key.
*/
void dtls_ec_set_get_pubkey_cb(dtls_ec_get_pubkey_Function p_get_pubkey_cb);


/**
* Call this function to produce a shared key using the public key of the other node.
* An ephemeral private key will be created that will be used for the point multiply
*
* @param[in] p_public_key  The public key from the other node used for communication.
* @param[out] p_public_key_out  The ephemeral public key that will be used in the point multiply.
* @param[out] p_secret  The pre-master key that is produced by the point multiply with p_public_key and our private key
* @return 1 upon success, 0 if an error occurred.
*/
int dtls_ec_ecdhe(const uint8_t p_public_key_in[],
                  uint8_t p_public_key_out[],
                  uint8_t p_secret[]);

/**
* Call this function to return the public key for an existing private key.
*
* @param[out] p_key_handle  A handle that is used to point to the private key stored in hardware.
*    The public key that is associated with this private key will be returned
* @param[out] p_public_key  The public key that is associated with the private key that was just created.
* @return 1 upon success, 0 if an error occurred.
*/
int dtls_ec_get_pubkey(const uint8_t p_key_handle[], uint8_t p_public_key[]);

/**
 * Document me...
 *
 * @param p_publicKey
 * @param p_privateKey
 * @param p_curve
 * @return
 */
int dtls_ec_make_key(uint8_t p_publicKey[], uint8_t p_privateKey[], dtls_ec_curve p_curve);

/**
 * Document me...
 *
 * @param p_publicKey
 * @param p_privateKey
 * @param p_secret
 * @param curve
 * @return
 */
int dtls_ec_shared_secret(const uint8_t p_publicKey[], const uint8_t p_privateKey[], uint8_t p_secret[], dtls_ec_curve curve);

/**
 * Document me...
 *
 * @param p_privateKey
 * @param p_hash
 * @param p_hash_size
 * @param p_signature
 * @param p_curve
 * @return
 */
int dtls_ec_sign(const uint8_t p_privateKey[], const uint8_t p_hash[], unsigned p_hash_size, uint8_t *p_signature, dtls_ec_curve p_curve);

/**
 * Document me...
 *
 * @param p_publicKey
 * @param p_hash
 * @param p_hash_size
 * @param p_signature
 * @param p_curve
 * @return
 */
int dtls_ec_verify(const uint8_t p_publicKey[], const uint8_t p_hash[], unsigned p_hash_size, const uint8_t *p_signature, dtls_ec_curve p_curve);

/**
 * Document me...
 *
 * @param p_public_key_in
 * @param p_public_key_out
 * @param p_secret
 * @return
 */
int dtls_ec_ecdhe(const uint8_t p_public_key_in[], uint8_t p_public_key_out[], uint8_t p_secret[]);

/**
 * Document me...
 *
 * @param p_key_handle
 * @param p_public_key
 * @return
 */
int dtls_ec_get_pubkey(const uint8_t p_key_handle[], uint8_t p_public_key[]);

//////////////////////////////////////////

#ifdef __cplusplus
} /* end of extern "C" */
#endif
 
#endif /* _ECC_H_ */
