import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Random;

public class iModel {
    Pairing e;
    Field G;
    Field GT;
    Field Zp;
    Element g;
    int n; // User number
    int paraNum; // Model size
    HashMap<byte[], Element> vid_rid;

    public static final int AVAIL = 1;
    public static final int TRAIN = 2;
    public static final int UPGRADE = 3;

    Element H1(byte[] data) {
        /* Hash(SHA-256), bytes -> Zp element. */
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(data);
            byte[] hash = sha256.digest();
            return this.Zp.newElementFromBytes(hash).getImmutable();
        }
        catch (NoSuchAlgorithmException e) {
            System.err.println("SHA-256 algorithm not available.");
            return this.Zp.newZeroElement().getImmutable();
        }
    }

    byte[] H2(Element data) {
        /* Hash(SHA-256), GT Element -> bytes. */
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(data.toBytes());
            return sha256.digest();
        }
        catch (NoSuchAlgorithmException e) {
            System.err.println("SHA-256 algorithm not available.");
            return null;
        }
    }

    byte[] generateVid() {
        /* 256 bits. */
        int length = 32;
        byte[] vid = new byte[length];
        new Random().nextBytes(vid);
        return vid;
    }

    Element[] calculatePolyCoefficients(Object[] P, Element r) {
        /* Input permission control policy and random number, output polynomial coefficient array.*/
        int len = P.length;
        Element[] data = new Element[n];
        int i, j;
        for(i=0; i<len; i++)
            data[i] = H1((byte[]) P[i]).negate(); // The coefficient is an opposite number.
        for(; i<n; i++)
            data[i] = H1(generateVid()).negate(); // The coefficient is an opposite number.
        // Expand polynomial
        Element[] result = new Element[n+1];
        result[0] = Zp.newOneElement().getImmutable();
        for(i=0; i<n; i++) {
            result[i+1] = Zp.newZeroElement().getImmutable();
            for(j=i; j>=0; j--) {
                result[j+1] = result[j+1].add(result[j]);
                result[j] = result[j].mulZn(data[i]);
            }
        }
        result[0] = result[0].add(r);
        return result;
    }

    Element calculateH1c0(Element[] c1, Element[] c2, Element c3, byte[] c4, Element[] c5, Element[] c6, Element c7, byte[] c8, Element[] c9, Element[] c10, Element c11, byte[] c12, Element pkc, BigInteger[] c13, byte[] vid) {
        byte[][] c13Bytes = new byte[paraNum][];
        int length = 128 * ( 6*(n+1) + 4 ) + c4.length + c8.length + c12.length + vid.length;
        int i;
        for(i=0; i<paraNum; i++) {
            c13Bytes[i] = c13[i].toByteArray();
            length += (c13Bytes[i]).length;
        }
        byte[] c0 = new byte[length];
        int currentPos = 0;

        for(i=0; i<=n; i++) {
            System.arraycopy(c1[i].toBytes(), 0, c0, currentPos, 128);
            currentPos += 128;
        }

        for(i=0; i<=n; i++) {
            System.arraycopy(c2[i].toBytes(), 0, c0, currentPos, 128);
            currentPos += 128;
        }

        System.arraycopy(c3.toBytes(), 0, c0, currentPos, 128);
        currentPos += 128;

        System.arraycopy(c4, 0, c0, currentPos, c4.length);
        currentPos += c4.length;

        for(i=0; i<=n; i++) {
            System.arraycopy(c5[i].toBytes(), 0, c0, currentPos, 128);
            currentPos += 128;
        }

        for(i=0; i<=n; i++) {
            System.arraycopy(c6[i].toBytes(), 0, c0, currentPos, 128);
            currentPos += 128;
        }

        System.arraycopy(c7.toBytes(), 0, c0, currentPos, 128);
        currentPos += 128;

        System.arraycopy(c8, 0, c0, currentPos, c8.length);
        currentPos += c8.length;

        for(i=0; i<=n; i++) {
            System.arraycopy(c9[i].toBytes(), 0, c0, currentPos, 128);
            currentPos += 128;
        }

        for(i=0; i<=n; i++) {
            System.arraycopy(c10[i].toBytes(), 0, c0, currentPos, 128);
            currentPos += 128;
        }

        System.arraycopy(c11.toBytes(), 0, c0, currentPos, 128);
        currentPos += 128;

        System.arraycopy(c12, 0, c0, currentPos, c12.length);
        currentPos += c12.length;

        System.arraycopy(pkc.toBytes(), 0, c0, currentPos, 128);
        currentPos += 128;

        for(i=0; i<paraNum; i++) {
            System.arraycopy(c13Bytes[i], 0, c0, currentPos, (c13Bytes[i]).length);
            currentPos += (c13Bytes[i]).length;
        }

        System.arraycopy(vid, 0, c0, currentPos, vid.length);

        return H1(c0);
    }

    byte[] xorBytes(byte[] bytes, byte[] hashBytes) {
        /* If the hash is longer, it will be truncated to the length of bytes before XORing.
           If the bytes are longer, the hash will be looped before XORing. */
        byte[] result = new byte[bytes.length];
        for(int i=0; i<bytes.length; i++)
            result[i] = (byte) (bytes[i] ^ hashBytes[i%hashBytes.length]);
        return result;
    }

    byte[] modToBytes(BigInteger[] M) {
        int length = 32; // Assuming that each parameter is within 256 bits.
        byte[] result = new byte[paraNum * length];
        for(int i=0; i<paraNum; i++) {
            byte[] Mi = M[i].toByteArray();
            System.arraycopy(Mi, 0, result, length * i + length - Mi.length, Mi.length);
        }
        return result;
    }

    BigInteger[] bytesToMod(byte[] bytes) {
        int length = 32; // Assuming that each parameter is within 256 bits.
        BigInteger[] result = new BigInteger[paraNum];
        for(int i=0; i<paraNum; i++) {
            byte[] temp = new byte[length];
            System.arraycopy(bytes, length * i, temp, 0, length);
            result[i] = new BigInteger(temp);
        }
        return result;
    }

    /**
     * [KGC] Generate e, G, GT, Zp, g
     * @param n         Total user number
     * @param paraNum   Model size
     * @return          Element[] msk, Element[] mpk
     */
    public Object[] setUp(int n, int paraNum) {
        e = PairingFactory.getPairing("a.properties");
        G = e.getG1();
        GT = e.getGT();
        Zp = e.getZr();
        g = G.newRandomElement().getImmutable();
        this.n = n;
        this.paraNum = paraNum;
        vid_rid = new HashMap<>();
        Element[] msk = new Element[n+1];
        Element[] mpk = new Element[n+1];
        for(int i=0; i<=n; i++)
            msk[i] = Zp.newRandomElement().getImmutable();
        for(int i=0; i<=n; i++)
            mpk[i] = g.powZn(msk[i].invert());
        return new Object[]{msk, mpk};
    }

    /**
     * [KGC]
     * @param msk       Master secret key
     * @param uid       User account
     * @return          Element rid, Element[] skid, byte[] vid
     */
    public Object[] keyGen(Element[] msk, byte[] uid) {
        Element rid = Zp.newRandomElement().getImmutable();
        Element[] skid = new Element[n+1];
        for(int i=0; i<=n; i++)
            skid[i] = g.powZn(msk[i].mulZn(rid).mulZn(H1(uid).pow(BigInteger.valueOf(i))));
        byte[] vid = generateVid();
        // Send (skid, vid) to user;
        // Send (rid, vid) to cloud server;
        // Store (uid, rid, vid);
        vid_rid.put(vid, rid);
        return new Object[]{rid, skid, vid};
    }

    /**
     * [AI Provider]
     * @param M         Model paremeter array
     * @param Pa        Permission control policy - Avial
     * @param Pt        Permission control policy - Train
     * @param Pu        Permission control policy - Upgrade
     * @param mpk       Master public key
     * @param pkh       Paillier public key
     * @return          Element CH, Object[] CM1, byte[][] pkhs, byte[][] skhs
     */
    public Object[] modProcess(BigInteger[] M, Object[] Pa, Object[] Pt, Object[] Pu, Element[] mpk, byte[] pkh) {
        Element alpha, beta, omega;
        Element[] alpha_, beta_, omega_;
        alpha = Zp.newRandomElement().getImmutable();
        alpha_ = calculatePolyCoefficients(Pa, alpha);
        beta = Zp.newRandomElement().getImmutable();
        beta_ = calculatePolyCoefficients(Pt, beta);
        omega = Zp.newRandomElement().getImmutable();
        omega_ = calculatePolyCoefficients(Pu, omega);
        Element ra1, ra2, rt1, rt2, ru1, ru2;
        ra1 = Zp.newRandomElement().getImmutable();
        ra2 = Zp.newRandomElement().getImmutable();
        rt1 = Zp.newRandomElement().getImmutable();
        rt2 = Zp.newRandomElement().getImmutable();
        ru1 = Zp.newRandomElement().getImmutable();
        ru2 = Zp.newRandomElement().getImmutable();

        Element skc = Zp.newRandomElement().getImmutable();
        Element pkc = g.powZn(skc);
        Element rh = Zp.newRandomElement().getImmutable();

        Element[] c1 = new Element[n+1];
        Element[] c2 = new Element[n+1];
        Element[] c5 = new Element[n+1];
        Element[] c6 = new Element[n+1];
        Element[] c9 = new Element[n+1];
        Element[] c10 = new Element[n+1];
        for(int i=0; i<=n; i++) {
            c1[i] = mpk[i].powZn(ra1.mulZn(alpha_[i]));
            c2[i] = mpk[i].powZn(ra2.mulZn(alpha_[i]));
            c5[i] = mpk[i].powZn(rt1.mulZn(beta_[i]));
            c6[i] = mpk[i].powZn(rt2.mulZn(beta_[i]));
            c9[i] = mpk[i].powZn(ru1.mulZn(omega_[i]));
            c10[i] = mpk[i].powZn(ru2.mulZn(omega_[i]));
        }
        Element egg = e.pairing(g, g).getImmutable();
        Element c3 = g.powZn(ra2.mulZn(alpha));
        byte[] c4 = xorBytes(pkh, H2(egg.powZn(alpha.mulZn(ra1))));
        Element c7 = g.powZn(rt2.mulZn(beta));
        byte[] c8 = xorBytes(modToBytes(M), H2(egg.powZn(beta.mulZn(rt1))));
        Element c11 = g.powZn(ru2.mulZn(omega));
        byte[] c12 = xorBytes(skc.toBytes(), H2(egg.powZn(omega.mulZn(ru1))));
        BigInteger[] c13 = new BigInteger[paraNum];
        for(int i=0; i<paraNum; i++) {
            c13[i] = PublicAlgorithm.paillierEncrypt(pkh, M[i]);
        }

        byte[] vid = generateVid(); // 模型所有者随机生成一个

        Element H1c0 = calculateH1c0(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, pkc, c13, vid);
        Element CH = g.powZn(H1c0).mul(g.powZn(skc.mulZn(rh)));
        Object[] CM1 = new Object[]{vid, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, pkc, c13, rh};
        return new Object[]{CH, CM1};
    }

    /**
     * [Public Algorithm]
     * @param CH        Chameleon hash
     * @param CM1       Processed model
     * @return          True/False
     */
    public boolean intCheck(Element CH, Object[] CM1) {
        byte[] vid = (byte[]) CM1[0];
        Element[] c1 = (Element[]) CM1[1];
        Element[] c2 = (Element[]) CM1[2];
        Element c3 = (Element) CM1[3];
        byte[] c4 = (byte[]) CM1[4];
        Element[] c5 = (Element[]) CM1[5];
        Element[] c6 = (Element[]) CM1[6];
        Element c7 = (Element) CM1[7];
        byte[] c8 = (byte[]) CM1[8];
        Element[] c9 = (Element[]) CM1[9];
        Element[] c10 = (Element[]) CM1[10];
        Element c11 = (Element) CM1[11];
        byte[] c12 = (byte[]) CM1[12];
        Element pkc = (Element) CM1[13];
        BigInteger[] c13 = (BigInteger[]) CM1[14];
        Element rh = (Element) CM1[15];

        Element H1c0 = calculateH1c0(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, pkc, c13, vid);
        Element right = g.powZn(H1c0).mul(pkc.powZn(rh));
        return CH.isEqual(right);
    }

    /**
     * [AI User]
     * @param Req       Avial/Train/Upgrade
     * @param skid      User secret key
     * @return          Req, Tid
     */
    public Object[] riToken(int Req, Element[] skid) {
        Element rt = Zp.newRandomElement();
        Element t1 = g.powZn(rt);
        Element[] t2 = new Element[n+1];
        for(int i=0; i<=n; i++)
            t2[i] = skid[i].powZn(rt);
        Object[] Tid = new Object[]{t1, t2};
        return new Object[]{Req, Tid};
    }

    /**
     * [Cloud Server]
     * @param Req       Avial/Train/Upgrade
     * @param CM1       Processed model
     * @param Tid       User’s right token
     * @param vid       Pseudonymous Account
     * @return          flag; If the verification is successful, the corresponding p1/p2/p3 will also be returned.
     */
    public Object[] riCheck(int Req, Object[] CM1, Object[] Tid, byte[] vid) {
        Element rid = vid_rid.get(vid);
        Element t1 = (Element) Tid[0];
        Element[] t2 = (Element[]) Tid[1];
        if(Req == AVAIL) {
            Element[] c2 = (Element[]) CM1[2];
            Element c3 = (Element) CM1[3];
            Element left = GT.newOneElement().getImmutable();
            for(int i=0; i<=n; i++)
                left = left.mul(e.pairing(c2[i].powZn(rid.invert()), t2[i]));
            Element right = e.pairing(c3, t1).getImmutable();
            if (left.isEqual(right)) {
                Element[] c1 = (Element[]) CM1[1];
                byte[] c4 = (byte[]) CM1[4];
                Element[] c1_star = new Element[n+1];
                for(int i=0; i<=n; i++)
                    c1_star[i] = c1[i].powZn(rid.invert());
                return new Object[]{AVAIL, new Object[]{c1_star, c4}}; // return p1
            }
        }
        else if(Req == TRAIN) {
            Element[] c6 = (Element[]) CM1[6];
            Element c7 = (Element) CM1[7];
            Element left = GT.newOneElement().getImmutable();
            for(int i=0; i<=n; i++)
                left = left.mul(e.pairing(c6[i].powZn(rid.invert()), t2[i]));
            Element right = e.pairing(c7, t1).getImmutable();
            if (left.isEqual(right)) {
                Element[] c5 = (Element[]) CM1[5];
                byte[] c8 = (byte[]) CM1[8];
                Element[] c5_star = new Element[n+1];
                for(int i=0; i<=n; i++)
                    c5_star[i] = c5[i].powZn(rid.invert());
                return new Object[]{TRAIN, new Object[]{c5_star, c8}}; // return p2
            }
        }
        else if(Req == UPGRADE) {
            Element[] c10 = (Element[]) CM1[10];
            Element c11 = (Element) CM1[11];
            Element left = GT.newOneElement().getImmutable();
            for(int i=0; i<=n; i++)
                left = left.mul(e.pairing(c10[i].powZn(rid.invert()), t2[i]));
            Element right = e.pairing(c11, t1).getImmutable();
            if (left.isEqual(right)) {
                Element[] c1 = (Element[]) CM1[1];
                byte[] c4 = (byte[]) CM1[4];
                Element[] c1_star = new Element[n+1];
                for(int i=0; i<=n; i++)
                    c1_star[i] = c1[i].powZn(rid.invert());
                Element[] c5 = (Element[]) CM1[5];
                byte[] c8 = (byte[]) CM1[8];
                Element[] c5_star = new Element[n+1];
                for(int i=0; i<=n; i++)
                    c5_star[i] = c5[i].powZn(rid.invert());
                Element[] c9 = (Element[]) CM1[9];
                byte[] c12 = (byte[]) CM1[12];
                Element[] c9_star = new Element[n+1];
                for(int i=0; i<=n; i++)
                    c9_star[i] = c9[i].powZn(rid.invert());
                return new Object[]{
                        UPGRADE,
                        new Object[]{c1_star, c4},
                        new Object[]{c5_star, c8},
                        new Object[]{c9_star, c12}
                }; // return p1, p2, p3
            }
        }
        return new Object[]{0};
    }

    /**
     * [AI User with Avail Permission]
     * @param skid      User secret key
     * @param p1        p1 obtained from the cloud server
     * @param m         User plaintext message
     * @return          BigInteger c
     */
    public BigInteger modAvail_User(Element[] skid, Object[] p1, BigInteger m) {
        Element[] c1_star = (Element[]) p1[0];
        byte[] c4 = (byte[]) p1[1];
        Element data = GT.newOneElement().getImmutable();
        for(int i=0; i<=n; i++)
            data = data.mul(e.pairing(c1_star[i], skid[i]));
        byte[] pkh = xorBytes(c4, H2(data));
        return PublicAlgorithm.paillierEncrypt(pkh, m);
    }

    /**
     * [Cloud Server]
     * @param c         User submitted ciphertext
     * @param CM1       Processed model
     * @return          BigInteger SR_cipher
     */
    public BigInteger modAvail_Cloud(BigInteger c, Object[] CM1) {
        BigInteger[] c13 = (BigInteger[]) CM1[14];
        BigInteger SR_cipher;
        // The cloud server passes c to the encrypted model for computation, and the result is SR_cipher.
        return SR_cipher;
    }

    /**
     * [AI User with Train Permission]
     * @param skid      User secret key
     * @param p2        p2 obtained from the cloud server
     * @return          byte[] CM2
     */
    public byte[] modTrain(Element[] skid, Object[] p2) {
        Element[] c5_star = (Element[]) p2[0];
        byte[] c8 = (byte[]) p2[1];
        Element data = GT.newOneElement().getImmutable();
        for(int i=0; i<=n; i++)
            data = data.mul(e.pairing(c5_star[i], skid[i]));
        BigInteger[] M = bytesToMod(xorBytes(c8, H2(data)));
        BigInteger[] M2;
        // The user trains based on model M, and the trained model parameter array is M2.
        return xorBytes(modToBytes(M2), H2(data));
    }

    /**
     * [AI User with Upgrade Permission]
     * @param skid      User secret key
     * @param p1        p1 obtained from the cloud server
     * @param p2        p2 obtained from the cloud server
     * @param p3        p3 obtained from the cloud server
     * @param CM1       Current global model
     * @param CM2s      List of collected local models CM2
     * @return          CM3
     */
    public Object[] modUpgrade(Element[] skid, Object[] p1, Object[] p2, Object[] p3, Object[] CM1, Object[] CM2s) {
        Element[] c1_star = (Element[]) p1[0];
        byte[] c4 = (byte[]) p1[1];
        Element data1 = GT.newOneElement().getImmutable();
        for(int i=0; i<=n; i++)
            data1 = data1.mul(e.pairing(c1_star[i], skid[i]));
        byte[] pkh = xorBytes(c4, H2(data1));

        Element[] c5_star = (Element[]) p2[0];
        byte[] c8 = (byte[]) p2[1];
        Element data2 = GT.newOneElement().getImmutable();
        for(int i=0; i<=n; i++)
            data2 = data2.mul(e.pairing(c5_star[i], skid[i]));
        BigInteger[] M = bytesToMod(xorBytes(c8, H2(data2)));

        Element[] c9_star = (Element[]) p3[0];
        byte[] c12 = (byte[]) p3[1];
        Element data3 = GT.newOneElement().getImmutable();
        for(int i=0; i<=n; i++)
            data3 = data3.mul(e.pairing(c9_star[i], skid[i]));
        Element skc = Zp.newElementFromBytes(xorBytes(c12, H2(data3)));

        Object[] M2s = new Object[CM2s.length];
        for(int i=0; i<CM2s.length; i++)
            M2s[i] = bytesToMod(xorBytes((byte[]) CM2s[i], H2(data2)));
        BigInteger[] M3;
        // Generate a new global model M3 based on M and M2s.
        // Here, each parameter takes the average of all M2 values.
        M3 = new BigInteger[paraNum];
        System.arraycopy(M, 0, M3, 0, paraNum);
        for(int j=0; j<paraNum; j++) {
            for (int i=0; i<CM2s.length; i++)
                M3[j] = M3[j].add(((BigInteger[]) M2s[i])[j]);
            M3[j] = M3[j].divide(BigInteger.valueOf(CM2s.length));
        }

        byte[] c8_star = xorBytes(modToBytes(M3), H2(data2));
        BigInteger[] c13_star = new BigInteger[paraNum];
        for(int i=0; i<paraNum; i++) {
            c13_star[i] = PublicAlgorithm.paillierEncrypt(pkh, M3[i]);
        }
        byte[] vid = (byte[]) CM1[0];
        Element[] c1 = (Element[]) CM1[1];
        Element[] c2 = (Element[]) CM1[2];
        Element c3 = (Element) CM1[3];
        Element[] c5 = (Element[]) CM1[5];
        Element[] c6 = (Element[]) CM1[6];
        Element c7 = (Element) CM1[7];
        Element[] c9 = (Element[]) CM1[9];
        Element[] c10 = (Element[]) CM1[10];
        Element c11 = (Element) CM1[11];
        Element pkc = (Element) CM1[13];
        BigInteger[] c13 = (BigInteger[]) CM1[14];
        Element rh = (Element) CM1[15];

        Element H1c0 = calculateH1c0(c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, pkc, c13, vid);
        Element H1c0_star = calculateH1c0(c1, c2, c3, c4, c5, c6, c7, c8_star, c9, c10, c11, c12, pkc, c13_star, vid);
        Element rh3 = (H1c0.sub(H1c0_star)).div(skc).add(rh);

        return new Object[]{c8_star, c13_star, rh3};
    }

    /**
     * [Cloud Server]
     * @param CM1       Current global model
     * @param CM3       CM3 uploaded by user with upgrade permission
     * @return          New global model
     */
    public Object[] CM3replaceCM1(Object[] CM1, Object[] CM3) {
        byte[] vid = (byte[]) CM1[0];
        Element[] c1 = (Element[]) CM1[1];
        Element[] c2 = (Element[]) CM1[2];
        Element c3 = (Element) CM1[3];
        byte[] c4 = (byte[]) CM1[4];
        Element[] c5 = (Element[]) CM1[5];
        Element[] c6 = (Element[]) CM1[6];
        Element c7 = (Element) CM1[7];
        byte[] c8_star = (byte[]) CM3[0];
        Element[] c9 = (Element[]) CM1[9];
        Element[] c10 = (Element[]) CM1[10];
        Element c11 = (Element) CM1[11];
        byte[] c12 = (byte[]) CM1[12];
        Element pkc = (Element) CM1[13];
        BigInteger[] c13_star = (BigInteger[]) CM3[1];
        Element rh3 = (Element) CM3[2];

        return new Object[]{vid, c1, c2, c3, c4, c5, c6, c7, c8_star, c9, c10, c11, c12, pkc, c13_star, rh3};
    }
}
