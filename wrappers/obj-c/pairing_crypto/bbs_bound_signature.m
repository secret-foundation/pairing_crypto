#import <Foundation/Foundation.h>

#import "PairingCryptoError.h"
#import "pairing_crypto_bbs_bound.h"
#import "bbs_bound_signature.h"

@implementation PCLBbsBoundSignature

- (nullable instancetype)sign:(NSData *_Nonnull)secretKey
                    publicKey:(NSData *_Nonnull)publicKey
                blsPublicKey:(NSData *_Nonnull)blsPublicKey
                       header:(NSData *_Nullable)header
                     messages:(NSArray *_Nullable)messages
                    withError:(NSError *_Nullable *_Nullable)errorPtr {
    pairing_crypto_error_t *err = (pairing_crypto_error_t *)malloc(sizeof(pairing_crypto_error_t));
    pairing_crypto_byte_buffer_t *secretKeyBuffer = nil;
    pairing_crypto_byte_buffer_t *publicKeyBuffer = nil;
    pairing_crypto_byte_buffer_t *blsPublicKeyBuffer = nil;
    pairing_crypto_byte_buffer_t *headerBuffer = nil;
    pairing_crypto_byte_buffer_t *messageBuffer = nil;
    pairing_crypto_byte_buffer_t *signatureBuffer = nil;

    uint64_t handle = bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_context_init(err);
    if (handle == 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }

    secretKeyBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
    secretKeyBuffer->len = secretKey.length;
    secretKeyBuffer->data = (uint8_t *)secretKey.bytes;
    if (bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_context_set_secret_key(handle, secretKeyBuffer, err) > 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }

    publicKeyBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
    publicKeyBuffer->len = publicKey.length;
    publicKeyBuffer->data = (uint8_t *)publicKey.bytes;
    if (bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_context_set_public_key(handle, publicKeyBuffer, err) > 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }

    blsPublicKeyBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
    blsPublicKeyBuffer->len = blsPublicKey.length;
    blsPublicKeyBuffer->data = (uint8_t *)blsPublicKey.bytes;
    if (bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_context_set_bls_public_key(handle, blsPublicKeyBuffer, err) > 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }

    if (header) {
        headerBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
        headerBuffer->len = header.length;
        headerBuffer->data = (uint8_t *)header.bytes;
        if (bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_context_set_header(handle, headerBuffer, err) > 0) {
            *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
            goto exit;
        }
    }

    messageBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
    if (messages && [messages count] != 0) {
        for (NSData *message in messages) {
            messageBuffer->len = message.length;
            messageBuffer->data = (uint8_t *)message.bytes;
            if (bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_context_add_message(handle, messageBuffer, err) > 0) {
                *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
                goto exit;
            }
        }
    }

    signatureBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
    if (bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_context_finish(handle, signatureBuffer, err) > 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }

    self.value = [[NSData alloc] initWithBytesNoCopy:signatureBuffer->data
                                              length:(NSUInteger)signatureBuffer->len
                                        freeWhenDone:true];

    free(err);

exit:
    if (signatureBuffer != nil) {
        free(signatureBuffer);
    }
    if (messageBuffer != nil) {
        free(messageBuffer);
    }
    if (headerBuffer != nil) {
        free(headerBuffer);
    }
    if (blsPublicKeyBuffer != nil) {
        free(blsPublicKeyBuffer);
    }
    if (publicKeyBuffer != nil) {
        free(publicKeyBuffer);
    }
    if (secretKeyBuffer != nil) {
        free(secretKeyBuffer);
    }

    return self;
}

- (bool)verify:(NSData *_Nonnull)publicKey
    blsSecretKey:(NSData *_Nonnull)blsSecretKey
          header:(NSData *_Nullable)header
        messages:(NSArray *_Nullable)messages
       withError:(NSError *_Nullable *_Nullable)errorPtr {
    bool result = false;
    pairing_crypto_error_t *err = (pairing_crypto_error_t *)malloc(sizeof(pairing_crypto_error_t));
    pairing_crypto_byte_buffer_t *publicKeyBuffer = nil;
    pairing_crypto_byte_buffer_t *blsSecretKeyBuffer = nil;
    pairing_crypto_byte_buffer_t *headerBuffer = nil;
    pairing_crypto_byte_buffer_t *signatureBuffer = nil;
    pairing_crypto_byte_buffer_t *messageBuffer = nil;

    uint64_t handle = bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_context_init(err);
    if (handle == 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }

    publicKeyBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
    publicKeyBuffer->len = publicKey.length;
    publicKeyBuffer->data = (uint8_t *)publicKey.bytes;
    if (bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_context_set_public_key(handle, publicKeyBuffer, err) != 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }

    blsSecretKeyBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
    blsSecretKeyBuffer->len = blsSecretKey.length;
    blsSecretKeyBuffer->data = (uint8_t *)blsSecretKey.bytes;
    if (bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_context_set_bls_secret_key(handle, blsSecretKeyBuffer, err) != 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }

    if (header) {
        headerBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
        headerBuffer->len = header.length;
        headerBuffer->data = (uint8_t *)header.bytes;
        if (bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_context_set_header(handle, headerBuffer, err) > 0) {
            *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
            goto exit;
        }
    }

    signatureBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
    signatureBuffer->len = self.value.length;
    signatureBuffer->data = (uint8_t *)self.value.bytes;
    if (bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_context_set_signature(handle, signatureBuffer, err) != 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }

    messageBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
    if (messages && [messages count] != 0) {
        for (NSData *message in messages) {
            messageBuffer->len = message.length;
            messageBuffer->data = (uint8_t *)message.bytes;
            if (bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_context_add_message(handle, messageBuffer, err) != 0) {
                *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
                goto exit;
            }
        }
    }

    if (bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_context_finish(handle, err) != 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }

    result = true;
    free(err);

exit:
    if (messageBuffer != nil) {
        free(messageBuffer);
    }
    if (signatureBuffer != nil) {
        free(signatureBuffer);
    }
    if (headerBuffer != nil) {
        free(headerBuffer);
    }
    if (blsSecretKeyBuffer != nil) {
        free(blsSecretKeyBuffer);
    }
    if (publicKeyBuffer != nil) {
        free(publicKeyBuffer);
    }
    return result;
}

@end
