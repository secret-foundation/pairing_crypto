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

import { RevealMessage } from '../utilities';

/**
 * A request to derive a bound BBS signature proof
 */
export interface BbsBoundDeriveProofRequest {
  /**
   * BBS public key associated to the signature
   */
  readonly publicKey: Uint8Array;
  /**
   * BLS secret key to include in the proof
   */
  readonly blsSecretKey: Uint8Array;
  /**
   * Header used during signing
   */
  readonly header?: Uint8Array;
  /**
   * Messages protected by the signature as an array of reveal instructions
   */
  readonly messages?: readonly RevealMessage<Uint8Array>[];
  /**
   * Signature to derive the proof from
   */
  readonly signature: Uint8Array;
  /**
   * Presentation header to bind to the proof
   */
  readonly presentationHeader?: Uint8Array;
  /**
   * Indicates if the signature should be verified prior to deriving the proof
   */
  readonly verifySignature?: boolean;
}
