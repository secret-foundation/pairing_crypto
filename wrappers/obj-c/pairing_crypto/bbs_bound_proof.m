#import <Foundation/Foundation.h>

#import "PairingCryptoError.h"
#import "pairing_crypto_bbs_bound.h"
#import "bbs_bound_proof.h"

@implementation PCLBbsBoundProof

- (nullable instancetype)createProof:(NSData *_Nonnull)publicKey
                        blsSecretKey:(NSData *_Nonnull)blsSecretKey
                              header:(NSData *_Nullable)header
                  presentationHeader:(NSData *_Nullable)presentationHeader
                           signature:(PCLBbsBoundSignature *_Nonnull)signature
                     verifySignature:(BOOL)verifySignature
                    disclosedIndices:(NSSet *_Nullable)disclosedIndices
                            messages:(NSArray *_Nullable)messages
                           withError:(NSError *_Nullable *_Nullable)errorPtr {
    pairing_crypto_error_t *err = (pairing_crypto_error_t *)malloc(sizeof(pairing_crypto_error_t));
    pairing_crypto_byte_buffer_t *publicKeyBuffer = nil;
    pairing_crypto_byte_buffer_t *blsSecretKeyBuffer = nil;
    pairing_crypto_byte_buffer_t *headerBuffer = nil;
    pairing_crypto_byte_buffer_t *presentationHeaderBuffer = nil;
    pairing_crypto_byte_buffer_t *signatureBuffer = nil;
    pairing_crypto_byte_buffer_t *messageBuffer = nil;
    pairing_crypto_byte_buffer_t *proofBuffer = nil;

    uint64_t handle = bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_init(err);
    if (handle == 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }

    publicKeyBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
    publicKeyBuffer->len = publicKey.length;
    publicKeyBuffer->data = (uint8_t *)publicKey.bytes;
    if (bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_set_public_key(handle, publicKeyBuffer, err) != 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }

    blsSecretKeyBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
    blsSecretKeyBuffer->len = blsSecretKey.length;
    blsSecretKeyBuffer->data = (uint8_t *)blsSecretKey.bytes;
    if (bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_set_bls_secret_key(handle, blsSecretKeyBuffer, err) != 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }

    if (header) {
        headerBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
        headerBuffer->len = header.length;
        headerBuffer->data = (uint8_t *)header.bytes;
        if (bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_set_header(handle, headerBuffer, err) > 0) {
            *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
            goto exit;
        }
    }

    if (presentationHeader) {
        presentationHeaderBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
        presentationHeaderBuffer->len = presentationHeader.length;
        presentationHeaderBuffer->data = (uint8_t *)presentationHeader.bytes;
        if (bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_set_presentation_header(handle, presentationHeaderBuffer, err) > 0) {
            *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
            goto exit;
        }
    }

    signatureBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
    signatureBuffer->len = signature.value.length;
    signatureBuffer->data = (uint8_t *)signature.value.bytes;
    if (bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_set_signature(handle, signatureBuffer, err) != 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }

    if (bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_set_verify_signature(handle, verifySignature, err) != 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }

    messageBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
    if (messages && disclosedIndices && [messages count] != 0) {
        for (int i = 0; i < [messages count]; i++) {
            NSData *message = [messages objectAtIndex:i];
            BOOL isDisclosed = [disclosedIndices containsObject:[[NSNumber alloc] initWithInt:i]];
            messageBuffer->len = message.length;
            messageBuffer->data = (uint8_t *)message.bytes;
            if (bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_add_message(handle, isDisclosed, messageBuffer, err) > 0) {
                *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
                goto exit;
            }
        }
    }

    proofBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
    if (bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_finish(handle, proofBuffer, err) != 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }

    self.value = [[NSData alloc] initWithBytesNoCopy:proofBuffer->data
                                              length:(NSUInteger)proofBuffer->len
                                        freeWhenDone:true];

    free(err);

exit:
    if (proofBuffer != nil) {
        free(proofBuffer);
    }
    if (messageBuffer != nil) {
        free(messageBuffer);
    }
    if (signatureBuffer != nil) {
        free(signatureBuffer);
    }
    if (presentationHeaderBuffer != nil) {
        free(presentationHeaderBuffer);
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

    return self;
}

- (bool)verifyProof:(NSData *_Nonnull)publicKey
              header:(NSData *_Nullable)header
  presentationHeader:(NSData *_Nullable)presentationHeader
            messages:(NSDictionary *_Nullable)messages
           withError:(NSError *_Nullable *_Nullable)errorPtr {
    bool result = false;
    pairing_crypto_error_t *err = (pairing_crypto_error_t *)malloc(sizeof(pairing_crypto_error_t));
    pairing_crypto_byte_buffer_t *publicKeyBuffer = nil;
    pairing_crypto_byte_buffer_t *headerBuffer = nil;
    pairing_crypto_byte_buffer_t *presentationHeaderBuffer = nil;
    pairing_crypto_byte_buffer_t *proofBuffer = nil;
    pairing_crypto_byte_buffer_t *messageBuffer = nil;

    uint64_t handle = bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_context_init(err);
    if (handle == 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }

    publicKeyBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
    publicKeyBuffer->len = publicKey.length;
    publicKeyBuffer->data = (uint8_t *)publicKey.bytes;
    if (bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_context_set_public_key(handle, publicKeyBuffer, err) != 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }

    if (header) {
        headerBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
        headerBuffer->len = header.length;
        headerBuffer->data = (uint8_t *)header.bytes;
        if (bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_context_set_header(handle, headerBuffer, err) > 0) {
            *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
            goto exit;
        }
    }

    if (presentationHeader) {
        presentationHeaderBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
        presentationHeaderBuffer->len = presentationHeader.length;
        presentationHeaderBuffer->data = (uint8_t *)presentationHeader.bytes;
        if (bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_context_set_presentation_header(handle, presentationHeaderBuffer, err) > 0) {
            *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
            goto exit;
        }
    }

    proofBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
    proofBuffer->len = self.value.length;
    proofBuffer->data = (uint8_t *)self.value.bytes;
    if (bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_context_set_proof(handle, proofBuffer, err) != 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }

    messageBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
    if (messages && [messages count] != 0) {
        for (id index in messages) {
            NSData *message = [messages objectForKey:index];
            messageBuffer->len = message.length;
            messageBuffer->data = (uint8_t *)message.bytes;
            if (bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_context_add_message(handle, [index intValue], messageBuffer, err) > 0) {
                *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
                goto exit;
            }
        }
    }

    if (bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_context_finish(handle, err) != 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }

    result = true;
    free(err);

exit:
    if (messageBuffer != nil) {
        free(messageBuffer);
    }
    if (proofBuffer != nil) {
        free(proofBuffer);
    }
    if (presentationHeaderBuffer != nil) {
        free(presentationHeaderBuffer);
    }
    if (headerBuffer != nil) {
        free(headerBuffer);
    }
    if (publicKeyBuffer != nil) {
        free(publicKeyBuffer);
    }

    return result;
}

@end
