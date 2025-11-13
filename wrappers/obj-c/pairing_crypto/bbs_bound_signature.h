#ifndef bbs_bound_signature_h
#define bbs_bound_signature_h

#import "bbs_signature.h"

@interface PCLBbsBoundSignature : PCLBbsSignature

- (nullable instancetype)sign:(NSData *_Nonnull)secretKey
                    publicKey:(NSData *_Nonnull)publicKey
                blsPublicKey:(NSData *_Nonnull)blsPublicKey
                       header:(NSData *_Nullable)header
                     messages:(NSArray *_Nullable)messages
                    withError:(NSError *_Nullable *_Nullable)errorPtr;

- (bool)verify:(NSData *_Nonnull)publicKey
    blsSecretKey:(NSData *_Nonnull)blsSecretKey
          header:(NSData *_Nullable)header
        messages:(NSArray *_Nullable)messages
       withError:(NSError *_Nullable *_Nullable)errorPtr;

@end

#endif /* bbs_bound_signature_h */
