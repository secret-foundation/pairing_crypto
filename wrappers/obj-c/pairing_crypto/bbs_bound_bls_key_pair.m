#import <Foundation/Foundation.h>

#import "PairingCryptoError.h"
#import "pairing_crypto_bbs_bound.h"
#import "bbs_bound_bls_key_pair.h"

@implementation PCLBbsBoundBlsKeyPair

@synthesize publicKey;
@synthesize secretKey;

- (void)generateKeyPair:(NSData *_Nullable)ikm
                keyInfo:(NSData *_Nullable)keyInfo
              withError:(NSError *_Nullable *_Nullable)errorPtr {
    pairing_crypto_error_t *err = (pairing_crypto_error_t *)malloc(sizeof(pairing_crypto_error_t));
    pairing_crypto_byte_buffer_t ikmBuffer;
    if (ikm != nil) {
        ikmBuffer.len = ikm.length;
        ikmBuffer.data = (uint8_t *)ikm.bytes;
    } else {
        ikmBuffer.len = 0;
        ikmBuffer.data = NULL;
    }

    pairing_crypto_byte_buffer_t keyInfoBuffer;
    if (keyInfo != nil) {
        keyInfoBuffer.len = keyInfo.length;
        keyInfoBuffer.data = (uint8_t *)keyInfo.bytes;
    } else {
        keyInfoBuffer.len = 0;
        keyInfoBuffer.data = NULL;
    }

    pairing_crypto_byte_buffer_t *sk = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
    pairing_crypto_byte_buffer_t *pk = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));

    int32_t ret = bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_generate_bls_key_pair(
        ikmBuffer,
        keyInfoBuffer,
        sk,
        pk,
        err
    );

    if (ret > 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        free(pk);
        free(sk);
        free(err);
        return;
    }

    self.secretKey = [[NSData alloc] initWithBytesNoCopy:sk->data length:(NSUInteger)sk->len freeWhenDone:true];
    self.publicKey = [[NSData alloc] initWithBytesNoCopy:pk->data length:(NSUInteger)pk->len freeWhenDone:true];

    free(pk);
    free(sk);
    free(err);
}

@end
