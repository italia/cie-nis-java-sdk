package it.ipzs.cie.nis.core;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;

public class RSA {

    private RSAPublicKey key;
    private Cipher cipher = null;

    public RSA(byte[] mod,byte[] exp) throws Exception {
        createPublicKey(mod,exp);
    }

    private void createPublicKey(byte[] modulo, byte[] esponente) throws Exception{
        BigInteger modulus = new BigInteger(AppUtil.bytesToHex(modulo), 16);
        BigInteger privateExp = new BigInteger(AppUtil.bytesToHex(esponente), 16);

        RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(modulus, privateExp);

        cipher = Cipher.getInstance("RSA/ECB/NoPadding");
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        this.key = (RSAPublicKey) keyFactory.generatePublic(pubKeySpec);
    }

    public byte[] decrypt(byte[] data)throws Exception{
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }

}
