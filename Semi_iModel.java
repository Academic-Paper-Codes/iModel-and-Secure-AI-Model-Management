import java.math.BigInteger;

public class Semi_iModel extends iModel {
    /**
     * [AI Provider]
     * @param pkh       Paillier public key
     * @param skh       Paillier secret key
     * @param SR_cipher Ciphertext
     * @return          BigInteger SR
     */
    public BigInteger modAvail_Provider(byte[] pkh, byte[] skh, BigInteger SR_cipher) {
        return PublicAlgorithm.paillierDecrypt(pkh, skh, SR_cipher);
    }
}