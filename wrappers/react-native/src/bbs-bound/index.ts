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

import { NativeModules } from 'react-native';
import {
  BbsBoundDeriveProofRequest,
  BbsBoundSignRequest,
  BbsBoundVerifyProofRequest,
  BbsBoundVerifyRequest,
  BbsBoundVerifyResult,
  BlsKeyPopGenRequest,
  BlsKeyPopVerifyRequest,
  KeyGenerationRequest,
  KeyPair,
  PairingCryptoError,
} from '../types';
import { UInt8ArrayToArray, mapObjIndexed } from '../utilities';

const { PairingCryptoRn } = NativeModules;

export const generateBbsKeyPair = async (request?: KeyGenerationRequest): Promise<Required<KeyPair>> => {
  try {
    const result = await PairingCryptoRn.Bls12381BbsG1BlsSigG2Sha256GenerateBbsKeyPair(
      request
        ? {
            ikm: request.ikm ? UInt8ArrayToArray(request.ikm) : undefined,
            keyInfo: request.keyInfo ? UInt8ArrayToArray(request.keyInfo) : undefined,
          }
        : {}
    );
    return {
      publicKey: new Uint8Array(result.publicKey),
      secretKey: new Uint8Array(result.secretKey),
    };
  } catch (err) {
    throw new PairingCryptoError('Failed to generate BBS key pair', err);
  }
};

export const generateBlsKeyPair = async (request?: KeyGenerationRequest): Promise<Required<KeyPair>> => {
  try {
    const result = await PairingCryptoRn.Bls12381BbsG1BlsSigG2Sha256GenerateBlsKeyPair(
      request
        ? {
            ikm: request.ikm ? UInt8ArrayToArray(request.ikm) : undefined,
            keyInfo: request.keyInfo ? UInt8ArrayToArray(request.keyInfo) : undefined,
          }
        : {}
    );
    return {
      publicKey: new Uint8Array(result.publicKey),
      secretKey: new Uint8Array(result.secretKey),
    };
  } catch (err) {
    throw new PairingCryptoError('Failed to generate BLS key pair', err);
  }
};

export const blsKeyPopGen = async (request: BlsKeyPopGenRequest): Promise<Uint8Array> => {
  const { blsSecretKey, aud, dst, extraInfo } = request;
  try {
    const result = await PairingCryptoRn.Bls12381BbsG1BlsSigG2Sha256BlsKeyPopGen({
      blsSecretKey: UInt8ArrayToArray(blsSecretKey),
      aud: UInt8ArrayToArray(aud),
      dst: dst ? UInt8ArrayToArray(dst) : undefined,
      extraInfo: extraInfo ? UInt8ArrayToArray(extraInfo) : undefined,
    });
    return new Uint8Array(result);
  } catch (err) {
    throw new PairingCryptoError('Failed to generate BLS key proof of possession', err);
  }
};

export const blsKeyPopVerify = async (request: BlsKeyPopVerifyRequest): Promise<boolean> => {
  const { blsKeyPop, blsPublicKey, aud, dst, extraInfo } = request;
  try {
    return await PairingCryptoRn.Bls12381BbsG1BlsSigG2Sha256BlsKeyPopVerify({
      blsKeyPop: UInt8ArrayToArray(blsKeyPop),
      blsPublicKey: UInt8ArrayToArray(blsPublicKey),
      aud: UInt8ArrayToArray(aud),
      dst: dst ? UInt8ArrayToArray(dst) : undefined,
      extraInfo: extraInfo ? UInt8ArrayToArray(extraInfo) : undefined,
    });
  } catch (err) {
    throw new PairingCryptoError('Failed to verify BLS key proof of possession', err);
  }
};

export const sign = async (request: BbsBoundSignRequest): Promise<Uint8Array> => {
  const { secretKey, publicKey, blsPublicKey, header, messages } = request;
  try {
    const result = await PairingCryptoRn.Bls12381BbsG1BlsSigG2Sha256Sign({
      secretKey: UInt8ArrayToArray(secretKey),
      publicKey: UInt8ArrayToArray(publicKey),
      blsPublicKey: UInt8ArrayToArray(blsPublicKey),
      messages: messages ? messages.map(UInt8ArrayToArray) : undefined,
      header: header ? UInt8ArrayToArray(header) : undefined,
    });
    return new Uint8Array(result);
  } catch (err) {
    throw new PairingCryptoError('Failed to create bound signature', err);
  }
};

export const verify = async (request: BbsBoundVerifyRequest): Promise<BbsBoundVerifyResult> => {
  const { publicKey, blsSecretKey, header, messages, signature } = request;
  try {
    return {
      verified: await PairingCryptoRn.Bls12381BbsG1BlsSigG2Sha256Verify({
        publicKey: UInt8ArrayToArray(publicKey),
        blsSecretKey: UInt8ArrayToArray(blsSecretKey),
        signature: UInt8ArrayToArray(signature),
        messages: messages ? messages.map(UInt8ArrayToArray) : undefined,
        header: header ? UInt8ArrayToArray(header) : undefined,
      }),
    };
  } catch (err) {
    return {
      verified: false,
      error: new PairingCryptoError('Failed to verify bound signature', err),
    };
  }
};

export const deriveProof = async (request: BbsBoundDeriveProofRequest): Promise<Uint8Array> => {
  const { publicKey, blsSecretKey, header, messages, signature, presentationHeader, verifySignature } = request;
  try {
    const result = await PairingCryptoRn.Bls12381BbsG1BlsSigG2Sha256ProofGen({
      publicKey: UInt8ArrayToArray(publicKey),
      blsSecretKey: UInt8ArrayToArray(blsSecretKey),
      signature: UInt8ArrayToArray(signature),
      messages: messages
        ? messages.map(message => ({
            reveal: message.reveal,
            value: UInt8ArrayToArray(message.value),
          }))
        : undefined,
      header: header ? UInt8ArrayToArray(header) : undefined,
      presentationHeader: presentationHeader ? UInt8ArrayToArray(presentationHeader) : undefined,
      verifySignature,
    });
    return new Uint8Array(result);
  } catch (err) {
    throw new PairingCryptoError('Failed to derive bound proof', err);
  }
};

export const verifyProof = async (request: BbsBoundVerifyProofRequest): Promise<BbsBoundVerifyResult> => {
  const { publicKey, header, presentationHeader, proof, messages } = request;
  try {
    return {
      verified: await PairingCryptoRn.Bls12381BbsG1BlsSigG2Sha256ProofVerify({
        publicKey: UInt8ArrayToArray(publicKey),
        proof: UInt8ArrayToArray(proof),
        header: header ? UInt8ArrayToArray(header) : undefined,
        presentationHeader: presentationHeader ? UInt8ArrayToArray(presentationHeader) : undefined,
        messages: messages ? mapObjIndexed(UInt8ArrayToArray, messages) : undefined,
      }),
    };
  } catch (err) {
    return {
      verified: false,
      error: new PairingCryptoError('Failed to verify bound proof', err),
    };
  }
};
