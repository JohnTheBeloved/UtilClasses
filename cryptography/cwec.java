 /*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.interswitchng.techquest.kimono.tms.util;

import com.interswitchng.techquest.kimono.core.log.LogManager;
import com.interswitchng.techquest.kimono.core.util.HexConverter;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import org.apache.commons.codec.binary.Base64;

/**
 *
 * @author Onuoha.Uchechukwu
 */
public class SecurityUtil {

    private static final Logger errorLogger = LogManager.getErrorLogger(SecurityUtil.class);

//   public static byte[] do3DESDecryption(byte[] key, byte[] data) {
//        byte[] decryptedInfo = null;
//        try {
//            SecretKey secretKey=get3DESecretKey(key);
//            Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
//            cipher.init(Cipher.DECRYPT_MODE, secretKey);
//             decryptedInfo = cipher.doFinal(data);
//        } catch (Exception ex) {
//            errorLogger.log(Level.SEVERE, ex.getMessage(), ex);
//        }
//        return decryptedInfo;
//    }
    public static byte[] do3DESEncryption(byte[] key, byte[] data) {
        byte[] encryptedInfo = null;

        try {
            byte[] key1 = Arrays.copyOfRange(key, 0, 8);
            byte[] key2 = Arrays.copyOfRange(key, 8, 16);
            encryptedInfo = Desencrypt(key1, data);
            encryptedInfo = Desdecrypt(key2, encryptedInfo);
            encryptedInfo = Desencrypt(key1, encryptedInfo);
        } catch (Exception ex) {
            errorLogger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return encryptedInfo;
    }

    public static byte[] do3DESDecryption(byte[] key, byte[] data) {
        byte[] decryptedInfo = null;
        try {
            byte[] key1 = Arrays.copyOfRange(key, 0, 8);
            byte[] key2 = Arrays.copyOfRange(key, 8, key.length);
            decryptedInfo = Desdecrypt(key1, data);
            decryptedInfo = Desencrypt(key2, decryptedInfo);
            decryptedInfo = Desdecrypt(key1, decryptedInfo);
        } catch (Exception ex) {
            errorLogger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return decryptedInfo;
    }

    public static SecretKey get3DESecretKey(byte[] encryptionKey) {
        SecretKey secretKey = null;
        if (encryptionKey == null) {
            return null;
        }
        byte[] keyValue = new byte[24]; // final 3DES key
        if (encryptionKey.length == 16) {
            // Create the third key from the first 8 bytes
            System.arraycopy(encryptionKey, 0, keyValue, 0, 16);
            System.arraycopy(encryptionKey, 0, keyValue, 16, 8);
        } else if (encryptionKey.length != 24) {
            throw new IllegalArgumentException("A TripleDES key should be 24 bytes long");
        } else {
            keyValue = encryptionKey;
        }
        DESedeKeySpec keySpec;
        try {
            keySpec = new DESedeKeySpec(keyValue);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
            secretKey = keyFactory.generateSecret(keySpec);
        } catch (Exception e) {
            throw new RuntimeException("Error in key Generation", e);
        }
        return secretKey;
    }

    public static SecretKey getDESecretKey(byte[] rawkey) throws Exception {
        DESKeySpec keyspec = new DESKeySpec(rawkey);
        SecretKeyFactory keyfactory = SecretKeyFactory.getInstance("DES");
        SecretKey key = keyfactory.generateSecret(keyspec);
        return key;
    }

    public static String rsaEncrypt(String pan, String keyAlias, String aliasPassword) throws KeyStoreException {
        String encryptedPan;
        RSAServiceUtil rsaEncrypter = new RSAServiceUtil();
        rsaEncrypter.openKeyStore(keyAlias, aliasPassword);
        encryptedPan = rsaEncrypter.encrypt(pan.getBytes());
        return encryptedPan;
    }
    
    public static byte[] rsaDecryptToBytes(String data, String keyAlias, String aliasPassword) throws KeyStoreException {
        RSAServiceUtil rsaEncrypter = new RSAServiceUtil();
        rsaEncrypter.openKeyStore(keyAlias, aliasPassword);
        return rsaEncrypter.decrypt(data);
    }


    public static String rsaDecrypt(String data, String keyAlias, String aliasPassword) throws KeyStoreException {
        return new String(rsaDecryptToBytes(data, keyAlias, aliasPassword));
    }

    public static String hashPan(String pan, String salt) {
        byte[] digest;
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-512");
            md.update(HexConverter.fromHex2ByteArray(salt.getBytes()));
            digest = md.digest(pan.getBytes());
            return Base64.encodeBase64String(digest);
        } catch (NoSuchAlgorithmException ex) {
        }
        return null;
    }

    public static String maskPan(String pan) {
        String maskedPan = null;
        int panLength = pan.length();

        if (panLength == 16) {
            maskedPan = pan.substring(0, 6) + "******"
                    + pan.substring(pan.length() - 4, pan.length());
        } else if (panLength == 19) {
            maskedPan = pan.substring(0, 6) + "*********"
                    + pan.substring(pan.length() - 4, pan.length());
        } else if (panLength >= 10) {
            maskedPan = pan.substring(0, 6);
            int leftOverLngth = panLength - maskedPan.length();
            String leftOver = pan.substring(6, pan.length());
            int toMaskLngth = leftOverLngth - 4;
            String tailEnd = leftOver.substring(toMaskLngth, leftOverLngth);
            String mask = "";

            for (int i = 0; i < toMaskLngth; i++) {
                mask += "*";
            }

            maskedPan += mask + tailEnd;
        } else {
            maskedPan = "Invalid PAN";
        }
        return maskedPan;
    }

    public static PublicKey getRSAPublicKey(byte[] keyMod, byte[] keyExp) {
        BigInteger mod = new BigInteger(1, keyMod);
        BigInteger exp = new BigInteger(1, keyExp);
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(mod, exp);
        try {
            KeyFactory keyFact = KeyFactory.getInstance("RSA");
            PublicKey pubKey = keyFact.generatePublic(keySpec);
            return pubKey;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException nsae) {
            errorLogger.log(Level.SEVERE, nsae.getMessage(), nsae);
        }
        return null;
    }

    public static String encryptDesKeyWithRSAPublicKey(PublicKey rsaKey, byte[] key) {
        byte[] keyBytes;

        try {
            Cipher c = Cipher.getInstance("RSA/ECB/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, rsaKey);
            keyBytes = c.doFinal(key);
            return HexConverter.fromBinary2Hex(keyBytes);
        } catch (NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchPaddingException nsae) {
            errorLogger..