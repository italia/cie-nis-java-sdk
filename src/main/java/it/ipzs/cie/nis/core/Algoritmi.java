package it.ipzs.cie.nis.core;
import java.security.MessageDigest;

/**
 * metodi di supporto per Encrypt e Decrypt
 */
public class Algoritmi {

    public static byte[] getSha(String instance,byte[] array) throws  Exception{
        MessageDigest md = MessageDigest.getInstance(instance);
        return md.digest(array);
    }

}
