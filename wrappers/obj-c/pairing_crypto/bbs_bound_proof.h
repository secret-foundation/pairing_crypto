#ifndef bbs_bound_proof_h
#define bbs_bound_proof_h

#import "bbs_proof.h"
#import "bbs_bound_signature.h"

@interface PCLBbsBoundProof : PCLBbsProof

- (nullable instancetype)createProof:(NSData *_Nonnull)publicKey
                        blsSecretKey:(NSData *_Nonnull)blsSecretKey
                              header:(NSData *_Nullable)header
                  presentationHeader:(NSData *_Nullable)presentationHeader
                           signature:(PCLBbsBoundSignature *_Nonnull)signature
                     verifySignature:(BOOL)verifySignature
                    disclosedIndices:(NSSet *_Nullable)disclosedIndices
                            messages:(NSArray *_Nullable)messages
                           withError:(NSError *_Nullable *_Nullable)errorPtr;

- (bool)verifyProof:(NSData *_Nonnull)publicKey
              header:(NSData *_Nullable)header
  presentationHeader:(NSData *_Nullable)presentationHeader
            messages:(NSDictionary *_Nullable)messages
           withError:(NSError *_Nullable *_Nullable)errorPtr;

@end

#endif /* bbs_bound_proof_h */
