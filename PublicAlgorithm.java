import java.math.BigInteger;

public class PublicAlgorithm {

    // Paillier

    static final int PAILLIER_KEY_K = 256;
    static final int PAILLIER_KEY_LENGTH = 65;

    /**
     * [Public Algorithm] Generate Paillier key
     */
    public static Object[] generatePaillierKey() {
        Paillier plr = new Paillier();
        plr.keyGeneration(PAILLIER_KEY_K);

        Paillier.PublicKey pk = plr.getPubkey();
        byte[] nBytesSRC = pk.getN().toByteArray();
        byte[] nBytes = new byte[PAILLIER_KEY_LENGTH];
        System.arraycopy(nBytesSRC, 0, nBytes, PAILLIER_KEY_LENGTH-nBytesSRC.length, nBytesSRC.length); // 防止生成的n长度不足length
        byte[] gBytesSRC = pk.getG().toByteArray();
        byte[] gBytes = new byte[PAILLIER_KEY_LENGTH];
        System.arraycopy(gBytesSRC, 0, gBytes, PAILLIER_KEY_LENGTH-gBytesSRC.length, gBytesSRC.length); // 防止生成的g长度不足length

        byte[] pkh = new byte[2 * PAILLIER_KEY_LENGTH];
        System.arraycopy(nBytes, 0, pkh, 0, PAILLIER_KEY_LENGTH);
        System.arraycopy(gBytes, 0, pkh, PAILLIER_KEY_LENGTH, PAILLIER_KEY_LENGTH);

        Paillier.PrivateKey sk = plr.getPrikey();
        byte[] lambdaBytesSRC = sk.getLambda().toByteArray();
        byte[] lambdaBytes = new byte[PAILLIER_KEY_LENGTH];
        System.arraycopy(lambdaBytesSRC, 0, lambdaBytes, PAILLIER_KEY_LENGTH-lambdaBytesSRC.length, lambdaBytesSRC.length); // 防止生成的λ长度不足length
        byte[] muBytesSRC = sk.getMu().toByteArray();
        byte[] muBytes = new byte[PAILLIER_KEY_LENGTH];
        System.arraycopy(muBytesSRC, 0, muBytes, PAILLIER_KEY_LENGTH-muBytesSRC.length, muBytesSRC.length); // 防止生成的μ长度不足length

        byte[] skh = new byte[2 * PAILLIER_KEY_LENGTH];
        System.arraycopy(lambdaBytes, 0, skh, 0, PAILLIER_KEY_LENGTH);
        System.arraycopy(muBytes, 0, skh, PAILLIER_KEY_LENGTH, PAILLIER_KEY_LENGTH);

        return new Object[]{pkh, skh};
    }

    /**
     * [Public Algorithm]
     * @param pkh       Paillier public key
     * @param m         BigInteger type message
     * @return          BigInteger c
     */
    public static BigInteger paillierEncrypt(byte[] pkh, BigInteger m) {
        byte[] nBytes = new byte[PAILLIER_KEY_LENGTH];
        byte[] gBytes = new byte[PAILLIER_KEY_LENGTH];
        System.arraycopy(pkh, 0, nBytes, 0, PAILLIER_KEY_LENGTH);
        System.arraycopy(pkh, PAILLIER_KEY_LENGTH, gBytes, 0, PAILLIER_KEY_LENGTH);
        Paillier.PublicKey pk = new Paillier.PublicKey(new BigInteger(nBytes), new BigInteger(gBytes));

        try {
            return Paillier.encrypt(m, pk);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    /**
     * [Public Algorithm]
     * @param pkh       Paillier public key
     * @param skh       Paillier secret key
     * @param c         BigInteger type ciphertext
     * @return          BigInteger m
     */
    public static BigInteger paillierDecrypt(byte[] pkh, byte[] skh, BigInteger c) {
        byte[] nBytes = new byte[PAILLIER_KEY_LENGTH];
        byte[] gBytes = new byte[PAILLIER_KEY_LENGTH];
        System.arraycopy(pkh, 0, nBytes, 0, PAILLIER_KEY_LENGTH);
        System.arraycopy(pkh, PAILLIER_KEY_LENGTH, gBytes, 0, PAILLIER_KEY_LENGTH);
        Paillier.PublicKey pk = new Paillier.PublicKey(new BigInteger(nBytes), new BigInteger(gBytes));

        byte[] lambdaBytes = new byte[PAILLIER_KEY_LENGTH];
        byte[] muBytes = new byte[PAILLIER_KEY_LENGTH];
        System.arraycopy(skh, 0, lambdaBytes, 0, PAILLIER_KEY_LENGTH);
        System.arraycopy(skh, PAILLIER_KEY_LENGTH, muBytes, 0, PAILLIER_KEY_LENGTH);
        Paillier.PrivateKey sk = new Paillier.PrivateKey(new BigInteger(lambdaBytes), new BigInteger(muBytes));

        try {
            return Paillier.decrypt(c, pk, sk);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }


    // 阈值Paillier

    public static byte[][] thresholdPaillierSecretKeySharing(byte[] skh, int nc) {
        byte[][] skhs = new byte[nc][];
        for(int i=0; i<nc; i++) {
            /* Shamir secret sharing operation on skh */
        }
        return skhs;
    }

    public static BigInteger thresholdPaillierPartialDecrypt(byte[] pkh, byte[] skh, BigInteger c) {
        /* Partial decryption using private key share skh = skhs[i] */
    }

    public static BigInteger thresholdPaillierCombine(byte[] pkh, int nc_t, BigInteger[] partialDecryptedCiphers) {
        BigInteger c_;
        for(int i=0; i<partialDecryptedCiphers.length; i++) {
            /* The share combination */
        }
        return c_;
    }

    public static BigInteger thresholdPaillierFinalDecrypt(byte[] pkh, BigInteger combinedRes) {
        /* Final decryption */
    }

}
