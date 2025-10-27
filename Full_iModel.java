import java.math.BigInteger;

public class Full_iModel extends iModel{
    int nc;  // Cloud server number
    int nc_t; // Number of cloud servers required for threshold decryption

    /**
     * [KGC] Generate e, G, GT, Zp, g
     * @param n         Total user number
     * @param paraNum   Model size
     * @return          Element[] msk, Element[] mpk
     */
    public Object[] setUp(int n, int paraNum, int nc, int nc_t) {
        this.nc = nc;
        this.nc_t = nc_t;
        return super.setUp(n, paraNum);
    }

    /**
     * [Cloud Server with secret key]
     * @param pkh       Paillier public key corresponding to the Paillier private key held by this cloud server
     * @param skh       Paillier secret key share held by this cloud server
     * @param SR_cipher The ciphertext of the model's running results
     * @return          BigInteger SR_cipher
     */
    public BigInteger modAvail_Cloud_partialDecrypt(byte[] pkh, byte[] skh, BigInteger SR_cipher) {
        return PublicAlgorithm.thresholdPaillierPartialDecrypt(pkh, skh, SR_cipher);
    }

    /**
     * [Cloud Server with secret key]
     * @param pkh       Paillier public key
     * @param partialDecryptedCiphers Partial decryption shares
     * @return          The result of the share combination
     */
    public BigInteger modAvail_Cloud_combine(byte[] pkh, BigInteger[] partialDecryptedCiphers) {
        return PublicAlgorithm.thresholdPaillierCombine(pkh, nc_t, partialDecryptedCiphers);
    }

    /**
     * [Cloud Server with secret key]
     * @param pkh       Paillier public key
     * @param combinedRes The result of the share combination
     * @return          Final decryption result
     */
    public BigInteger modAvail_Cloud_finalDecrypt(byte[] pkh, BigInteger combinedRes) {
        return PublicAlgorithm.thresholdPaillierFinalDecrypt(pkh, combinedRes);
    }

}