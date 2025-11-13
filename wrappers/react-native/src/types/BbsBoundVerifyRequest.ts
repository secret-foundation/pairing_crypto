/*
 * Copyright 2022 - MATTR Limited
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * A request to verify a BBS bound signature
 */
export interface BbsBoundVerifyRequest {
  /**
   * BBS public key of the signer
   */
  readonly publicKey: Uint8Array;
  /**
   * BLS secret key of the verifier
   */
  readonly blsSecretKey: Uint8Array;
  /**
   * Header used during signing
   */
  readonly header?: Uint8Array;
  /**
   * Messages to verify
   */
  readonly messages?: readonly Uint8Array[];
  /**
   * Signature to verify
   */
  readonly signature: Uint8Array;
}
