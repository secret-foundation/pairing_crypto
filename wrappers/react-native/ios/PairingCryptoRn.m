#import <Foundation/Foundation.h>
#import <React/RCTConvert.h>

#import <PairingCryptoError.h>
#import <bbs_signature.h>
#import <bbs_bls12381_sha256_key_pair.h>
#import <bbs_bls12381_shake256_key_pair.h>
#import <bbs_bls12381_sha256_signature.h>
#import <bbs_bls12381_shake256_signature.h>
#import <bbs_bls12381_sha256_proof.h>
#import <bbs_bls12381_shake256_proof.h>
#import <bbs_bound_bbs_key_pair.h>
#import <bbs_bound_bls_key_pair.h>
#import <bbs_bound_signature.h>
#import <bbs_bound_proof.h>
#import "pairing_crypto_bbs_bound.h"

#import "Convert.h"
#import "Operation.h"
#import "PairingCryptoRn.h"

@implementation PairingCryptoRn

RCT_EXPORT_MODULE()

//TODO check heap allocations are all free'd

RCT_EXPORT_METHOD(Bls12381Sha256GenerateKeyPair:(NSDictionary *)request
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)
{
    Operation<NSDictionary*, NSDictionary*> *operation = [Operation new:^NSDictionary*(NSDictionary* request, NSError** error) {
        NSData *ikm = nil;
        NSData *keyInfo = nil;

        if ([request valueForKey:@"ikm"] != nil) {
            ikm = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"ikm"]]];
        }

        if ([request valueForKey:@"keyInfo"] != nil) {
            ikm = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"keyInfo"]]];
        }

        PCLBbsBls12381Sha256KeyPair *keyPair = [[PCLBbsBls12381Sha256KeyPair alloc] initWithIkm:ikm keyInfo:keyInfo
                                                                                withError:error];

        return [NSDictionary dictionaryWithObjects:@[[Convert byteArrayFromData:keyPair.publicKey],
                                                     [Convert byteArrayFromData:keyPair.secretKey]]
                                           forKeys:@[@"publicKey",
                                                     @"secretKey"]];
    }];

    [operation exec:request
       withResolver:resolve
       withRejecter:reject];
}

RCT_EXPORT_METHOD(Bls12381Shake256GenerateKeyPair:(NSDictionary *)request
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)
{
    Operation<NSDictionary*, NSDictionary*> *operation = [Operation new:^NSDictionary*(NSDictionary* request, NSError** error) {
        NSData *ikm = nil;
        NSData *keyInfo = nil;

        if ([request valueForKey:@"ikm"] != nil) {
            ikm = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"ikm"]]];
        }

        if ([request valueForKey:@"keyInfo"] != nil) {
            ikm = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"keyInfo"]]];
        }

        PCLBbsBls12381Shake256KeyPair *keyPair = [[PCLBbsBls12381Shake256KeyPair alloc] initWithIkm:ikm keyInfo:keyInfo
                                                                                    withError:error];

        return [NSDictionary dictionaryWithObjects:@[[Convert byteArrayFromData:keyPair.publicKey],
                                                     [Convert byteArrayFromData:keyPair.secretKey]]
                                           forKeys:@[@"publicKey",
                                                     @"secretKey"]];
    }];

    [operation exec:request
       withResolver:resolve
       withRejecter:reject];
}

RCT_EXPORT_METHOD(Bls12381Sha256Sign:(NSDictionary *)request
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)
{
    Operation<NSDictionary*, NSArray*> *operation = [Operation new:^NSArray*(NSDictionary* request, NSError** error) {
        NSArray *messages = nil;
        NSData *header = nil;
        NSData *secretKey = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"secretKey"]]];
        NSData *publicKey = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"publicKey"]]];

        if ([request valueForKey:@"header"] != nil) {
            header = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"header"]]];
        }
        if ([request valueForKey:@"messages"] != nil) {
            messages = [Convert dataArrayFromArrayOfByteArrays:[RCTConvert NSArray:request[@"messages"]]];
        }

        PCLBbsBls12381Sha256Signature *signature = [[PCLBbsBls12381Sha256Signature alloc] sign:secretKey
                                                                               publicKey:publicKey
                                                                                  header:header
                                                                                messages:messages
                                                                               withError:error];
        return [Convert byteArrayFromData:signature.value];
    }];

    [operation exec:request
       withResolver:resolve
       withRejecter:reject];
}

RCT_EXPORT_METHOD(Bls12381Shake256Sign:(NSDictionary *)request
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)
{
    Operation<NSDictionary*, NSArray*> *operation = [Operation new:^NSArray*(NSDictionary* request, NSError** error) {
        NSArray *messages = nil;
        NSData *header = nil;
        NSData *secretKey = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"secretKey"]]];
        NSData *publicKey = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"publicKey"]]];

        if ([request valueForKey:@"header"] != nil) {
            header = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"header"]]];
        }
        if ([request valueForKey:@"messages"] != nil) {
            messages = [Convert dataArrayFromArrayOfByteArrays:[RCTConvert NSArray:request[@"messages"]]];
        }

        PCLBbsBls12381Shake256Signature *signature = [[PCLBbsBls12381Shake256Signature alloc] sign:secretKey
                                                                                   publicKey:publicKey
                                                                                      header:header
                                                                                    messages:messages
                                                                                   withError:error];
        return [Convert byteArrayFromData:signature.value];
    }];

    [operation exec:request
       withResolver:resolve
       withRejecter:reject];
}

RCT_EXPORT_METHOD(Bls12381Sha256Verify:(NSDictionary *)request
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)
{
    Operation<NSDictionary*, NSNumber*> *operation = [Operation new:^NSNumber*(NSDictionary* request, NSError** error) {
        NSArray *messages = nil;
        NSData *header = nil;
        NSData *publicKey = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"publicKey"]]];
        NSData *signatureBytes = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"signature"]]];

        if ([request valueForKey:@"header"] != nil) {
            header = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"header"]]];
        }
        if ([request valueForKey:@"messages"] != nil) {
            messages = [Convert dataArrayFromArrayOfByteArrays:[RCTConvert NSArray:request[@"messages"]]];
        }

        PCLBbsBls12381Sha256Signature *signature = [[PCLBbsBls12381Sha256Signature alloc] initWithBytes:signatureBytes
                                                                                        withError:error];
        return [[NSNumber alloc] initWithBool:[signature verify:publicKey
                                                         header:header
                                                       messages:messages
                                                      withError:error]];
    }];

    [operation exec:request
       withResolver:resolve
       withRejecter:reject];
}

RCT_EXPORT_METHOD(Bls12381Shake256Verify:(NSDictionary *)request
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)
{
    Operation<NSDictionary*, NSNumber*> *operation = [Operation new:^NSNumber*(NSDictionary* request, NSError** error) {
        NSArray *messages = nil;
        NSData *header = nil;
        NSData *publicKey = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"publicKey"]]];
        NSData *signatureBytes = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"signature"]]];

        if ([request valueForKey:@"header"] != nil) {
            header = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"header"]]];
        }
        if ([request valueForKey:@"messages"] != nil) {
            messages = [Convert dataArrayFromArrayOfByteArrays:[RCTConvert NSArray:request[@"messages"]]];
        }

        PCLBbsBls12381Shake256Signature *signature = [[PCLBbsBls12381Shake256Signature alloc] initWithBytes:signatureBytes
                                                                                            withError:error];

        bool isVerified = [signature verify:publicKey
                                     header:header
                                   messages:messages
                                  withError:error];

        return [[NSNumber alloc] initWithBool:isVerified];
    }];

    [operation exec:request
       withResolver:resolve
       withRejecter:reject];
}

RCT_EXPORT_METHOD(Bls12381Sha256ProofVerify:(NSDictionary *)request
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)
{
    Operation<NSDictionary*, NSNumber*> *operation = [Operation new:^NSNumber*(NSDictionary* request, NSError** error) {
        NSMutableDictionary *disclosedMessage = nil;
        NSData *header = nil;
        NSData *presentationHeader = nil;
        NSData *publicKey = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"publicKey"]]];
        NSData *proofBytes = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"proof"]]];

        if ([request valueForKey:@"header"] != nil) {
            header = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"header"]]];
        }
        if ([request valueForKey:@"presentationHeader"] != nil) {
            presentationHeader = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"presentationHeader"]]];
        }
        if ([request valueForKey:@"messages"] != nil) {
            disclosedMessage = [[NSMutableDictionary alloc] init];
            NSDictionary *messagesInput = [RCTConvert NSDictionary:request[@"messages"]];

            for (NSString *key in messagesInput) {
                NSArray *messageBytes = [RCTConvert NSArray:[messagesInput valueForKey:key]];

                [disclosedMessage setObject:[Convert dataFromByteArray:messageBytes]
                                     forKey:[[NSNumber alloc] initWithLong:[key integerValue]]];
            }
        }

        PCLBbsBls12381Sha256Proof *proof = [[PCLBbsBls12381Sha256Proof alloc] initWithBytes:proofBytes
                                                                            withError:error];

        bool isVerified = [proof verifyProof:publicKey
                                      header:header
                          presentationHeader:presentationHeader
                                    messages:disclosedMessage
                                   withError:error];

        return [[NSNumber alloc] initWithBool:isVerified];
    }];

    [operation exec:request
       withResolver:resolve
       withRejecter:reject];
}

RCT_EXPORT_METHOD(Bls12381Shake256ProofVerify:(NSDictionary *)request
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)
{
    Operation<NSDictionary*, NSNumber*> *operation = [Operation new:^NSNumber*(NSDictionary* request, NSError** error) {
        NSMutableDictionary *disclosedMessage = nil;
        NSData *header = nil;
        NSData *presentationHeader = nil;
        NSData *publicKey = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"publicKey"]]];
        NSData *proofBytes = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"proof"]]];

        if ([request valueForKey:@"header"] != nil) {
            header = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"header"]]];
        }
        if ([request valueForKey:@"presentationHeader"] != nil) {
            presentationHeader = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"presentationHeader"]]];
        }
        if ([request valueForKey:@"messages"] != nil) {
            NSDictionary *messagesInput = [RCTConvert NSDictionary:request[@"messages"]];
            disclosedMessage = [[NSMutableDictionary alloc] init];

            for (NSString *key in messagesInput) {
                NSArray *messageBytes = [RCTConvert NSArray:[messagesInput valueForKey:key]];
                [disclosedMessage setObject:[Convert dataFromByteArray:messageBytes] forKey:key];
            }
        }

        PCLBbsBls12381Shake256Proof *proof = [[PCLBbsBls12381Shake256Proof alloc] initWithBytes:proofBytes
                                                                                withError:error];

        bool isVerified = [proof verifyProof:publicKey
                                      header:header
                          presentationHeader:presentationHeader
                                    messages:disclosedMessage
                                   withError:error];

        return [[NSNumber alloc] initWithBool:isVerified];
    }];

    [operation exec:request
       withResolver:resolve
       withRejecter:reject];
}

RCT_EXPORT_METHOD(Bls12381Sha256ProofGen:(NSDictionary *)request
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)
{
    Operation<NSDictionary*, NSArray*> *operation = [Operation new:^NSArray*(NSDictionary* request, NSError** error) {
        NSMutableSet *disclosedIndices = nil;
        NSMutableArray *messages = nil;
        NSData *header = nil;
        NSData *presentationHeader = nil;
        NSData *publicKey = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"publicKey"]]];
        NSData *signatureBytes = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"signature"]]];
        BOOL verifySignature = [request[@"verifySignature"] isEqual:@([RCTConvert BOOL:@(YES)])];

        if ([request valueForKey:@"header"] != nil) {
            header = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"header"]]];
        }
        if ([request valueForKey:@"presentationHeader"] != nil) {
            presentationHeader = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"presentationHeader"]]];
        }
        if ([request valueForKey:@"messages"] != nil) {
            NSArray *messagesInput = [RCTConvert NSArray:request[@"messages"]];

            disclosedIndices = [[NSMutableSet alloc] init];
            messages = [[NSMutableArray alloc] init];

            for (int idx = 0; idx < [messagesInput count]; idx++) {
                NSDictionary *input = [RCTConvert NSDictionary:messagesInput[idx]];
                NSArray *messageBytes = [RCTConvert NSArray:input[@"value"]];

                if ([input[@"reveal"] isEqual:@([RCTConvert BOOL:@(YES)])]) {
                    [disclosedIndices addObject:[NSNumber numberWithInt:idx]];
                }
                [messages addObject:[Convert dataFromByteArray:messageBytes]];
            }
        }

        PCLBbsBls12381Sha256Signature *signature = [[PCLBbsBls12381Sha256Signature alloc] initWithBytes:signatureBytes
                                                                                        withError:error];

        PCLBbsBls12381Sha256Proof *proof = [[PCLBbsBls12381Sha256Proof alloc] createProof:publicKey
                                                                             header:header
                                                                 presentationHeader:presentationHeader
                                                                          signature:signature
                                                                    verifySignature:verifySignature
                                                                   disclosedIndices:disclosedIndices
                                                                           messages:messages
                                                                          withError:error];

        return [Convert byteArrayFromData:proof.value];
    }];

    [operation exec:request
       withResolver:resolve
       withRejecter:reject];
}

RCT_EXPORT_METHOD(Bls12381Shake256ProofGen:(NSDictionary *)request
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)
{
    Operation<NSDictionary*, NSArray*> *operation = [Operation new:^NSArray*(NSDictionary* request, NSError** error) {
        NSMutableSet *disclosedIndices = nil;
        NSMutableArray *messages = nil;
        NSData *header = nil;
        NSData *presentationHeader = nil;
        NSData *publicKey = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"publicKey"]]];
        NSData *signatureBytes = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"signature"]]];
        BOOL verifySignature = [request[@"verifySignature"] isEqual:@([RCTConvert BOOL:@(YES)])];

        if ([request valueForKey:@"header"] != nil) {
            header = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"header"]]];
        }
        if ([request valueForKey:@"presentationHeader"] != nil) {
            presentationHeader = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"presentationHeader"]]];
        }
        if ([request valueForKey:@"messages"] != nil) {
            NSArray *messagesInput = [RCTConvert NSArray:request[@"messages"]];

            disclosedIndices = [[NSMutableSet alloc] init];
            messages = [[NSMutableArray alloc] init];

            for (int idx = 0; idx < [messagesInput count]; idx++) {
                NSDictionary *input = [RCTConvert NSDictionary:messagesInput[idx]];
                NSArray *messageBytes = [RCTConvert NSArray:input[@"value"]];

                if ([input[@"reveal"] isEqual:@([RCTConvert BOOL:@(YES)])]) {
                    [disclosedIndices addObject:[NSNumber numberWithInt:idx]];
                }
                [messages addObject:[Convert dataFromByteArray:messageBytes]];
            }
        }

        PCLBbsBls12381Shake256Signature *signature = [[PCLBbsBls12381Shake256Signature alloc] initWithBytes:signatureBytes
                                                                                            withError:error];

        PCLBbsBls12381Shake256Proof *proof = [[PCLBbsBls12381Shake256Proof alloc] createProof:publicKey
                                                                                 header:header
                                                                     presentationHeader:presentationHeader
                                                                              signature:signature
                                                                        verifySignature:verifySignature
                                                                       disclosedIndices:disclosedIndices
                                                                               messages:messages
                                                                              withError:error];

        return [Convert byteArrayFromData:proof.value];
    }];

    [operation exec:request
       withResolver:resolve
       withRejecter:reject];
}

RCT_EXPORT_METHOD(Bls12381BbsG1BlsSigG2Sha256GenerateBbsKeyPair:(NSDictionary *)request
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)
{
    Operation<NSDictionary*, NSDictionary*> *operation = [Operation new:^NSDictionary*(NSDictionary* request, NSError** error) {
        NSData *ikm = nil;
        NSData *keyInfo = nil;

        if ([request valueForKey:@"ikm"] != nil) {
            ikm = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"ikm"]]];
        }

        if ([request valueForKey:@"keyInfo"] != nil) {
            keyInfo = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"keyInfo"]]];
        }

        PCLBbsBoundBbsKeyPair *keyPair = [[PCLBbsBoundBbsKeyPair alloc] initWithIkm:ikm keyInfo:keyInfo withError:error];
        return [NSDictionary dictionaryWithObjects:@[[Convert byteArrayFromData:keyPair.publicKey],
                                                     [Convert byteArrayFromData:keyPair.secretKey]]
                                           forKeys:@[@"publicKey",
                                                     @"secretKey"]];
    }];

    [operation exec:request
       withResolver:resolve
       withRejecter:reject];
}

RCT_EXPORT_METHOD(Bls12381BbsG1BlsSigG2Sha256GenerateBlsKeyPair:(NSDictionary *)request
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)
{
    Operation<NSDictionary*, NSDictionary*> *operation = [Operation new:^NSDictionary*(NSDictionary* request, NSError** error) {
        NSData *ikm = nil;
        NSData *keyInfo = nil;

        if ([request valueForKey:@"ikm"] != nil) {
            ikm = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"ikm"]]];
        }

        if ([request valueForKey:@"keyInfo"] != nil) {
            keyInfo = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"keyInfo"]]];
        }

        PCLBbsBoundBlsKeyPair *keyPair = [[PCLBbsBoundBlsKeyPair alloc] initWithIkm:ikm keyInfo:keyInfo withError:error];
        return [NSDictionary dictionaryWithObjects:@[[Convert byteArrayFromData:keyPair.publicKey],
                                                     [Convert byteArrayFromData:keyPair.secretKey]]
                                           forKeys:@[@"publicKey",
                                                     @"secretKey"]];
    }];

    [operation exec:request
       withResolver:resolve
       withRejecter:reject];
}

RCT_EXPORT_METHOD(Bls12381BbsG1BlsSigG2Sha256BlsKeyPopGen:(NSDictionary *)request
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)
{
    Operation<NSDictionary*, NSArray*> *operation = [Operation new:^NSArray*(NSDictionary* request, NSError** error) {
        NSData *blsSecretKey = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"blsSecretKey"]]];
        NSData *aud = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"aud"]]];
        NSData *dst = nil;
        NSData *extraInfo = nil;

        if ([request valueForKey:@"dst"] != nil) {
            dst = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"dst"]]];
        }

        if ([request valueForKey:@"extraInfo"] != nil) {
            extraInfo = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"extraInfo"]]];
        }

        pairing_crypto_error_t *err = (pairing_crypto_error_t *)malloc(sizeof(pairing_crypto_error_t));
        pairing_crypto_byte_buffer_t blsSecretKeyBuffer = { .len = blsSecretKey.length, .data = (uint8_t *)blsSecretKey.bytes };
        pairing_crypto_byte_buffer_t audBuffer = { .len = aud.length, .data = (uint8_t *)aud.bytes };
        pairing_crypto_byte_buffer_t dstBuffer = { .len = dst ? dst.length : 0, .data = dst ? (uint8_t *)dst.bytes : NULL };
        pairing_crypto_byte_buffer_t extraBuffer = { .len = extraInfo ? extraInfo.length : 0, .data = extraInfo ? (uint8_t *)extraInfo.bytes : NULL };
        pairing_crypto_byte_buffer_t *popBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));

        int32_t ret = bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_bls_key_pop_gen(
            &blsSecretKeyBuffer,
            &audBuffer,
            &dstBuffer,
            &extraBuffer,
            popBuffer,
            err
        );

        if (ret > 0) {
            *error = [PairingCryptoError errorFromPairingCryptoError:err];
            free(popBuffer);
            free(err);
            return nil;
        }

        NSData *popData = [[NSData alloc] initWithBytesNoCopy:popBuffer->data length:(NSUInteger)popBuffer->len freeWhenDone:true];
        NSArray *result = [Convert byteArrayFromData:popData];

        free(popBuffer);
        free(err);

        return result;
    }];

    [operation exec:request
       withResolver:resolve
       withRejecter:reject];
}

RCT_EXPORT_METHOD(Bls12381BbsG1BlsSigG2Sha256BlsKeyPopVerify:(NSDictionary *)request
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)
{
    Operation<NSDictionary*, NSNumber*> *operation = [Operation new:^NSNumber*(NSDictionary* request, NSError** error) {
        NSData *blsKeyPop = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"blsKeyPop"]]];
        NSData *blsPublicKey = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"blsPublicKey"]]];
        NSData *aud = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"aud"]]];
        NSData *dst = nil;
        NSData *extraInfo = nil;

        if ([request valueForKey:@"dst"] != nil) {
            dst = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"dst"]]];
        }

        if ([request valueForKey:@"extraInfo"] != nil) {
            extraInfo = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"extraInfo"]]];
        }

        pairing_crypto_error_t *err = (pairing_crypto_error_t *)malloc(sizeof(pairing_crypto_error_t));
        pairing_crypto_byte_buffer_t popBuffer = { .len = blsKeyPop.length, .data = (uint8_t *)blsKeyPop.bytes };
        pairing_crypto_byte_buffer_t publicKeyBuffer = { .len = blsPublicKey.length, .data = (uint8_t *)blsPublicKey.bytes };
        pairing_crypto_byte_buffer_t audBuffer = { .len = aud.length, .data = (uint8_t *)aud.bytes };
        pairing_crypto_byte_buffer_t dstBuffer = { .len = dst ? dst.length : 0, .data = dst ? (uint8_t *)dst.bytes : NULL };
        pairing_crypto_byte_buffer_t extraBuffer = { .len = extraInfo ? extraInfo.length : 0, .data = extraInfo ? (uint8_t *)extraInfo.bytes : NULL };

        int32_t ret = bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_bls_key_pop_verify(
            &popBuffer,
            &publicKeyBuffer,
            &audBuffer,
            &dstBuffer,
            &extraBuffer,
            err
        );

        if (ret > 1) {
            *error = [PairingCryptoError errorFromPairingCryptoError:err];
            free(err);
            return nil;
        }

        free(err);
        return [[NSNumber alloc] initWithBool:(ret == 0)];
    }];

    [operation exec:request
       withResolver:resolve
       withRejecter:reject];
}

RCT_EXPORT_METHOD(Bls12381BbsG1BlsSigG2Sha256Sign:(NSDictionary *)request
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)
{
    Operation<NSDictionary*, NSArray*> *operation = [Operation new:^NSArray*(NSDictionary* request, NSError** error) {
        NSArray *messages = nil;
        NSData *header = nil;
        NSData *secretKey = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"secretKey"]]];
        NSData *publicKey = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"publicKey"]]];
        NSData *blsPublicKey = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"blsPublicKey"]]];

        if ([request valueForKey:@"header"] != nil) {
            header = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"header"]]];
        }
        if ([request valueForKey:@"messages"] != nil) {
            messages = [Convert dataArrayFromArrayOfByteArrays:[RCTConvert NSArray:request[@"messages"]]];
        }

        PCLBbsBoundSignature *signature = [[PCLBbsBoundSignature alloc] sign:secretKey
                                                                   publicKey:publicKey
                                                               blsPublicKey:blsPublicKey
                                                                      header:header
                                                                    messages:messages
                                                                   withError:error];
        return [Convert byteArrayFromData:signature.value];
    }];

    [operation exec:request
       withResolver:resolve
       withRejecter:reject];
}

RCT_EXPORT_METHOD(Bls12381BbsG1BlsSigG2Sha256Verify:(NSDictionary *)request
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)
{
    Operation<NSDictionary*, NSNumber*> *operation = [Operation new:^NSNumber*(NSDictionary* request, NSError** error) {
        NSArray *messages = nil;
        NSData *header = nil;
        NSData *publicKey = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"publicKey"]]];
        NSData *blsSecretKey = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"blsSecretKey"]]];
        NSData *signatureBytes = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"signature"]]];

        if ([request valueForKey:@"header"] != nil) {
            header = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"header"]]];
        }
        if ([request valueForKey:@"messages"] != nil) {
            messages = [Convert dataArrayFromArrayOfByteArrays:[RCTConvert NSArray:request[@"messages"]]];
        }

        PCLBbsBoundSignature *signature = [[PCLBbsBoundSignature alloc] initWithBytes:signatureBytes withError:error];

        bool verified = [signature verify:publicKey
                             blsSecretKey:blsSecretKey
                                   header:header
                                 messages:messages
                                withError:error];

        return [[NSNumber alloc] initWithBool:verified];
    }];

    [operation exec:request
       withResolver:resolve
       withRejecter:reject];
}

RCT_EXPORT_METHOD(Bls12381BbsG1BlsSigG2Sha256ProofVerify:(NSDictionary *)request
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)
{
    Operation<NSDictionary*, NSNumber*> *operation = [Operation new:^NSNumber*(NSDictionary* request, NSError** error) {
        NSMutableDictionary *disclosedMessage = nil;
        NSData *header = nil;
        NSData *presentationHeader = nil;
        NSData *publicKey = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"publicKey"]]];
        NSData *proofBytes = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"proof"]]];

        if ([request valueForKey:@"header"] != nil) {
            header = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"header"]]];
        }
        if ([request valueForKey:@"presentationHeader"] != nil) {
            presentationHeader = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"presentationHeader"]]];
        }
        if ([request valueForKey:@"messages"] != nil) {
            disclosedMessage = [[NSMutableDictionary alloc] init];
            NSDictionary *messagesInput = [RCTConvert NSDictionary:request[@"messages"]];

            for (NSString *key in messagesInput) {
                NSArray *messageBytes = [RCTConvert NSArray:[messagesInput valueForKey:key]];

                [disclosedMessage setObject:[Convert dataFromByteArray:messageBytes]
                                     forKey:[[NSNumber alloc] initWithLong:[key integerValue]]];
            }
        }

        PCLBbsBoundProof *proof = [[PCLBbsBoundProof alloc] initWithBytes:proofBytes withError:error];

        bool isVerified = [proof verifyProof:publicKey
                                      header:header
                          presentationHeader:presentationHeader
                                    messages:disclosedMessage
                                   withError:error];

        return [[NSNumber alloc] initWithBool:isVerified];
    }];

    [operation exec:request
       withResolver:resolve
       withRejecter:reject];
}

RCT_EXPORT_METHOD(Bls12381BbsG1BlsSigG2Sha256ProofGen:(NSDictionary *)request
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)
{
    Operation<NSDictionary*, NSArray*> *operation = [Operation new:^NSArray*(NSDictionary* request, NSError** error) {
        NSMutableSet *disclosedIndices = nil;
        NSMutableArray *messages = nil;
        NSData *header = nil;
        NSData *presentationHeader = nil;
        NSData *publicKey = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"publicKey"]]];
        NSData *blsSecretKey = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"blsSecretKey"]]];
        NSData *signatureBytes = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"signature"]]];
        BOOL verifySignature = [request[@"verifySignature"] isEqual:@([RCTConvert BOOL:@(YES)])];

        if ([request valueForKey:@"header"] != nil) {
            header = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"header"]]];
        }
        if ([request valueForKey:@"presentationHeader"] != nil) {
            presentationHeader = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"presentationHeader"]]];
        }
        if ([request valueForKey:@"messages"] != nil) {
            NSArray *messagesInput = [RCTConvert NSArray:request[@"messages"]];

            disclosedIndices = [[NSMutableSet alloc] init];
            messages = [[NSMutableArray alloc] init];

            for (int idx = 0; idx < [messagesInput count]; idx++) {
                NSDictionary *input = [RCTConvert NSDictionary:messagesInput[idx]];
                NSArray *messageBytes = [RCTConvert NSArray:input[@"value"]];

                if ([input[@"reveal"] isEqual:@([RCTConvert BOOL:@(YES)])]) {
                    [disclosedIndices addObject:[NSNumber numberWithInt:idx]];
                }
                [messages addObject:[Convert dataFromByteArray:messageBytes]];
            }
        }

        PCLBbsBoundSignature *signature = [[PCLBbsBoundSignature alloc] initWithBytes:signatureBytes withError:error];

        PCLBbsBoundProof *proof = [[PCLBbsBoundProof alloc] createProof:publicKey
                                                           blsSecretKey:blsSecretKey
                                                                 header:header
                                                     presentationHeader:presentationHeader
                                                              signature:signature
                                                        verifySignature:verifySignature
                                                       disclosedIndices:disclosedIndices
                                                               messages:messages
                                                              withError:error];

        return [Convert byteArrayFromData:proof.value];
    }];

    [operation exec:request
       withResolver:resolve
       withRejecter:reject];
}

@end
