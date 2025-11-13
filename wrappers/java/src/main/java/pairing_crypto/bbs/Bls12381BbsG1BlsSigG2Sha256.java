package pairing_crypto;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

public class Bls12381BbsG1BlsSigG2Sha256 {
    public static final int BBS_SECRET_KEY_SIZE = 32;
    public static final int BBS_PUBLIC_KEY_SIZE = 96;
    public static final int BBS_SIGNATURE_SIZE = 80;

    public static final int BLS_SECRET_KEY_SIZE = 32;
    public static final int BLS_PUBLIC_KEY_SIZE = 192;
    public static final int BLS_KEY_POP_SIZE = 192;

    static {
        System.loadLibrary("pairing_crypto_jni");
    }

    private static native int generate_bbs_key_pair(byte[] ikm, byte[] keyInfo, byte[] public_key, byte[] secret_key);
    private static native int generate_bls_key_pair(byte[] ikm, byte[] keyInfo, byte[] public_key, byte[] secret_key);

    private static native long sign_context_init();
    private static native int sign_context_set_secret_key(long handle, byte[] secret_key);
    private static native int sign_context_set_public_key(long handle, byte[] public_key);
    private static native int sign_context_set_bls_public_key(long handle, byte[] bls_public_key);
    private static native int sign_context_set_header(long handle, byte[] header);
    private static native int sign_context_add_message(long handle, byte[] message);
    private static native int sign_context_finish(long handle, byte[] signature);

    private static native long verify_context_init();
    private static native int verify_context_set_public_key(long handle, byte[] public_key);
    private static native int verify_context_set_bls_secret_key(long handle, byte[] bls_secret_key);
    private static native int verify_context_set_header(long handle, byte[] header);
    private static native int verify_context_add_message(long handle, byte[] message);
    private static native int verify_context_set_signature(long handle, byte[] signature);
    private static native int verify_context_finish(long handle);

    private static native long proof_gen_context_init();
    private static native int proof_gen_context_set_public_key(long handle, byte[] public_key);
    private static native int proof_gen_context_set_bls_secret_key(long handle, byte[] bls_secret_key);
    private static native int proof_gen_context_set_header(long handle, byte[] header);
    private static native int proof_gen_context_set_signature(long handle, byte[] signature);
    private static native int proof_gen_context_set_presentation_header(long handle, byte[] presentation_header);
    private static native int proof_gen_context_set_verify_signature(long handle, boolean verifySignature);
    private static native int proof_gen_context_add_message(long handle, boolean reveal, byte[] message);
    private static native int proof_gen_context_finish(long handle, byte[] proof);

    private static native long proof_verify_context_init();
    private static native int proof_verify_context_set_public_key(long handle, byte[] public_key);
    private static native int proof_verify_context_set_header(long handle, byte[] header);
    private static native int proof_verify_context_set_presentation_header(long handle, byte[] presentation_header);
    private static native int proof_verify_context_set_proof(long handle, byte[] proof);
    private static native int proof_verify_context_add_message(long handle, int index, byte[] message);
    private static native int proof_verify_context_finish(long handle);

    private static native int get_proof_size(int numberOfUndisclosedMessages);

    private static native int bls_key_pop_gen(byte[] blsSecretKey, byte[] aud, byte[] dst, byte[] extraInfo, byte[] keyPop);
    private static native int bls_key_pop_verify(byte[] blsKeyPop, byte[] blsPublicKey, byte[] aud, byte[] dst, byte[] extraInfo);

    public KeyPair generateBbsKeyPair(byte[] ikm, byte[] keyInfo) throws Exception {
        byte[] publicKey = new byte[BBS_PUBLIC_KEY_SIZE];
        byte[] secretKey = new byte[BBS_SECRET_KEY_SIZE];
        if (0 != generate_bbs_key_pair(ikm, keyInfo, publicKey, secretKey)) {
            throw new Exception("Unable to generate BBS keys");
        }
        return new KeyPair(publicKey, secretKey);
    }

    public KeyPair generateBlsKeyPair(byte[] ikm, byte[] keyInfo) throws Exception {
        byte[] publicKey = new byte[BLS_PUBLIC_KEY_SIZE];
        byte[] secretKey = new byte[BLS_SECRET_KEY_SIZE];
        if (0 != generate_bls_key_pair(ikm, keyInfo, publicKey, secretKey)) {
            throw new Exception("Unable to generate BLS keys");
        }
        return new KeyPair(publicKey, secretKey);
    }

    public byte[] blsKeyPopGen(byte[] blsSecretKey, byte[] aud, byte[] dst, byte[] extraInfo) throws Exception {
        byte[] keyPop = new byte[BLS_KEY_POP_SIZE];
        if (0 != bls_key_pop_gen(blsSecretKey, aud, dst, extraInfo, keyPop)) {
            throw new Exception("Unable to generate BLS key pop");
        }
        return keyPop;
    }

    public boolean blsKeyPopVerify(byte[] blsKeyPop, byte[] blsPublicKey, byte[] aud, byte[] dst, byte[] extraInfo) throws Exception {
        int res = bls_key_pop_verify(blsKeyPop, blsPublicKey, aud, dst, extraInfo);
        switch (res) {
            case 0:
                return true;
            case 1:
                return false;
            default:
                throw new Exception("Unable to verify BLS key pop");
        }
    }

    public byte[] sign(byte[] secretKey, byte[] publicKey, byte[] blsPublicKey, byte[] header, byte[][] messages) throws Exception {
        long handle = sign_context_init();
        if (0 == handle) {
            throw new Exception("Unable to create signing context");
        }
        if (0 != sign_context_set_secret_key(handle, secretKey)) {
            throw new Exception("Unable to set secret key");
        }
        if (0 != sign_context_set_public_key(handle, publicKey)) {
            throw new Exception("Unable to set public key");
        }
        if (0 != sign_context_set_bls_public_key(handle, blsPublicKey)) {
            throw new Exception("Unable to set BLS public key");
        }
        if (0 != sign_context_set_header(handle, header)) {
            throw new Exception("Unable to set header");
        }
        for (byte[] message : messages) {
            if (0 != sign_context_add_message(handle, message)) {
                throw new Exception("Unable to add message");
            }
        }
        byte[] signature = new byte[BBS_SIGNATURE_SIZE];
        if (0 != sign_context_finish(handle, signature)) {
            throw new Exception("Unable to create signature");
        }
        return signature;
    }

    public boolean verify(byte[] publicKey, byte[] blsSecretKey, byte[] header, byte[] signature, byte[][] messages) throws Exception {
        long handle = verify_context_init();
        if (0 == handle) {
            throw new Exception("Unable to create verify signature context");
        }
        if (0 != verify_context_set_public_key(handle, publicKey)) {
            throw new Exception("Unable to set public key");
        }
        if (0 != verify_context_set_bls_secret_key(handle, blsSecretKey)) {
            throw new Exception("Unable to set BLS secret key");
        }
        if (0 != verify_context_set_header(handle, header)) {
            throw new Exception("Unable to set header");
        }
        if (0 != verify_context_set_signature(handle, signature)) {
            throw new Exception("Unable to set signature");
        }
        for (byte[] message : messages) {
            if (0 != verify_context_add_message(handle, message)) {
                throw new Exception("Unable to add message");
            }
        }
        int res = verify_context_finish(handle);
        switch (res) {
            case 0:
                return true;
            case 1:
                return false;
            default:
                throw new Exception("Unable to verify signature");
        }
    }

    public byte[] createProof(byte[] publicKey, byte[] blsSecretKey, byte[] header, byte[] presentationHeader, byte[] signature, boolean verifySignature, HashSet<Integer> disclosedIndices, byte[][] messages) throws Exception {
        int numberOfUndisclosedMessages = 0;
        long handle = proof_gen_context_init();
        if (0 == handle) {
            throw new Exception("Unable to create proof context");
        }
        if (0 != proof_gen_context_set_public_key(handle, publicKey)) {
            throw new Exception("Unable to set public key");
        }
        if (0 != proof_gen_context_set_bls_secret_key(handle, blsSecretKey)) {
            throw new Exception("Unable to set BLS secret key");
        }
        if (0 != proof_gen_context_set_header(handle, header)) {
            throw new Exception("Unable to set header");
        }
        if (0 != proof_gen_context_set_presentation_header(handle, presentationHeader)) {
            throw new Exception("Unable to set presentation header");
        }
        if (0 != proof_gen_context_set_verify_signature(handle, verifySignature)) {
            throw new Exception("Unable to set verify-signature flag");
        }
        if (0 != proof_gen_context_set_signature(handle, signature)) {
            throw new Exception("Unable to set signature");
        }
        for (int i = 0; i < messages.length; i++) {
            byte[] message = messages[i];
            boolean reveal = disclosedIndices.contains(i);
            if (!reveal) {
                numberOfUndisclosedMessages++;
            }
            if (0 != proof_gen_context_add_message(handle, reveal, message)) {
                throw new Exception("Unable to add message");
            }
        }
        int proofSize = get_proof_size(numberOfUndisclosedMessages);
        if (proofSize <= 0) {
            throw new Exception("Unable to get proof size");
        }
        byte[] proof = new byte[proofSize];
        if (0 != proof_gen_context_finish(handle, proof)) {
            throw new Exception("Unable to create proof");
        }
        return proof;
    }

    public boolean verifyProof(byte[] publicKey, byte[] header, byte[] presentationHeader, byte[] proof, HashMap<Integer, byte[]> messages) throws Exception {
        long handle = proof_verify_context_init();
        if (0 == handle) {
            throw new Exception("Unable to create verify proof context");
        }
        if (0 != proof_verify_context_set_public_key(handle, publicKey)) {
            throw new Exception("Unable to set public key");
        }
        if (0 != proof_verify_context_set_header(handle, header)) {
            throw new Exception("Unable to set header");
        }
        if (0 != proof_verify_context_set_presentation_header(handle, presentationHeader)) {
            throw new Exception("Unable to set presentation header");
        }
        if (0 != proof_verify_context_set_proof(handle, proof)) {
            throw new Exception("Unable to set proof");
        }
        for (Map.Entry<Integer, byte[]> message : messages.entrySet()) {
            if (0 != proof_verify_context_add_message(handle, message.getKey(), message.getValue())) {
                throw new Exception("Unable to add message");
            }
        }
        int res = proof_verify_context_finish(handle);
        switch (res) {
            case 0:
                return true;
            case 1:
                return false;
            default:
                throw new Exception("Unable to verify proof");
        }
    }
}
