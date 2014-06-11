
/**
 * TrippleDESTool.java Purpose: Encrypts and Decrypts String of data. using
 * Tripple DES encryption Also used in generating pin block
 *
 * @author JohnTheBeloved
 *
 * Note that you cannot Encypt a non Hexadecimal String So This Class concerts
 * the data you pass in to hexadecimal before encrypting it
 *
 * Likewise, it converts the the decrypted data back to a normal String i.e Hex
 * String is returned after a normal java cryptogram decryption
 */

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

import java.util.regex.*;

public class PinBlockGen {

   
    /**
     * This function Encrypts the an hexadecimal String using the java Secret
     * Key Provided
     *
     * @return Encrypted Hexadecimal String
     * @param keyInHex The key in Hex format to use for the encryption
     * @param dataToEncryptInHex The data to encrypt ***In Hexadecimal Form****
     */
    private String encrypt(String keyInHex, String dataToEncryptInHex) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException, IOException {

    	byte[] rawData = ConvertUtils.hexToBytes(dataToEncryptInHex);
        byte[] rawKey = ConvertUtils.hexToBytes(keyInHex);

        Cryptor encryptor;
        encryptor = new Cryptor(Cryptor.T3DES_ALGORITHM,Cryptor.ENCRYPT_MODE);
       
        encryptor.processData(rawKey, rawData);
        return encryptor.getResult();

    }

    /**
     * This function Decrypts the an hexadecimal String using the java Secret
     * Key Object Provided
     *
     * @return Decrypted Hexadecimal String
     * @param key The Java SecretKey to use for the encryption
     * @param dataToEncryptInHex THe data to decrypt***In Hexadecimal Form****
     */
    private String decrypt(String keyInHex, String dataToDecryptInHex) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException {
        byte[] rawData = ConvertUtils.hexToBytes(dataToDecryptInHex);
        byte[] rawKey = ConvertUtils.hexToBytes(keyInHex);

        Cryptor encryptor;
        if (keyInHex.length() == 16) {
            encryptor = new Cryptor(Cryptor.DECRYPT_MODE);
        } else if (keyInHex.length() == 16 & keyInHex.length() % 16 == 0) {
            encryptor = new Cryptor(Cryptor.DECRYPT_MODE);
        } else {
            throw new RuntimeException("Key length seems not correct");
        }
        encryptor.processData(rawKey, rawData);
        return encryptor.getResult();

    }

    public SecretKey readKey(byte[] rawkey) throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException {

		// Read the raw bytes from the keyfile
        DESedeKeySpec keyspec = new DESedeKeySpec(rawkey);
        SecretKeyFactory keyfactory = SecretKeyFactory.getInstance("DESede");
        SecretKey key;
        key = keyfactory.generateSecret(keyspec);

        key = keyfactory.translateKey(key);
        return key;

    }

    /**
     * This method makes sures the key string length is 48 Cos Encryption uses
     * se bytes key Do your padding of the keys here, depending
     */
    private String getPaddedKey(String keyStringInHex) {
        //Pad the key to make it 48 length
        if (keyStringInHex.length() % 16 != 0) {
            throw new RuntimeException("Key length seems not correct!");
        }
        switch (keyStringInHex.length()) {
            case 16:
                return keyStringInHex + keyStringInHex + keyStringInHex;

            case 32:
                return keyStringInHex + keyStringInHex;

            case 48:
                return keyStringInHex;

            default:
                return keyStringInHex;

        }
    }

    private String getPaddedPINFormat(String cardPIN) {

        cardPIN = "0" + cardPIN.length() + cardPIN;
        while (cardPIN.length() < 16) {
            cardPIN = cardPIN + "F";
        }
       // System.out.println("PADDED CARD PIN===" + cardPIN);
        return cardPIN;
    }

    private String getPaddedPANFormat(String cardPAN) {

		//Remove checkDigit
        //123456789012345 6
        String cardPANPart1 = cardPAN.substring(0, cardPAN.length() - 1);
        //Remove Institution code
        // 456789012345
        String cardPANPart2 = cardPANPart1.substring(cardPANPart1.length() - 12, cardPANPart1.length());
       String paddedCardPAN = cardPANPart2;

        int length = cardPANPart2.length();

		//System.out.println("IN CARD PAN");
        //Loop to pad the result to become 16
        while (paddedCardPAN.length() < 16) {
            paddedCardPAN = "0" + paddedCardPAN;
        }

       // System.out.println("PADDED CARD PAN===" + paddedCardPAN);
        return paddedCardPAN;

    }

    public String getPINBlock(String PAN, String PIN, String iPEK1, String iPEK2) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IOException {
        //Make sure that the Second Encryption Key is 48....By adding the last 16 digits of the PEK
        String PEK1 = iPEK1 + iPEK1.substring(0, 48 - iPEK1.length());
        //Make sure that the Second Encryption Key is 48....By adding the last 16 digits of the PEK
        String PEK2 = iPEK2 + iPEK2.substring(0, 48 - iPEK2.length());

        //Get XOR or the two keys
        byte[] PEK = getRawKey(PEK1, PEK2);

        String hexPEK = ConvertUtils.bytesToHex(PEK);
        //THe unencrypted pin block format
        String finalPinFormat = getPINFormat(PIN, PAN);
        
        return encrypt(hexPEK, finalPinFormat);

    }

    public String getPINBlock(String PAN, String PIN, String iPEK) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IOException {
        //Make sure that the Second Encryption Key is 48....By adding the last 16 digits of the PEK
        String PEK1 = iPEK + iPEK.substring(0, 48 - iPEK.length());

        //Get XOR or the two keys
        byte[] PEK = getRawKey(PEK1);

        String hexPEK = ConvertUtils.bytesToHex(PEK);
        //THe unencrypted pin block format
        String FINALPINFORMAT = getPINFormat(PIN, PAN);

        return encrypt(hexPEK, FINALPINFORMAT);

    }

    //One Key Provided
    private byte[] getRawKey(String key) {
        return ConvertUtils.hexToBytes(getPaddedKey(key));
    }

    //Two Keys Provided
    private byte[] getRawKey(String firstKey, String secondKey) {

        return XOR(ConvertUtils.hexToBytes(getPaddedKey(firstKey)), ConvertUtils.hexToBytes(getPaddedKey(secondKey)));

    }

    /**
     * Gets the Final PIN format to encrpt in order to get the PIN BLOCK
     *
     * @param PIN The PIN of the Card
     * @param PAN The PAN of the Card
     */
    private String getPINFormat(String PIN, String PAN) {

        String PINFormat = getPaddedPINFormat(PIN);
        String PANFormat = getPaddedPANFormat(PAN);
        //Exclusive OR of the two formats for pin block
        byte[] rawPINBlockFormat = XOR(ConvertUtils.hexToBytes(PINFormat), ConvertUtils.hexToBytes(PANFormat));
        //Convert to Hex back
        String hexPINBlockFormat = ConvertUtils.bytesToHex(rawPINBlockFormat);

        return hexPINBlockFormat;
    }

    //Used to find XOR of two keys 
    private byte[] XOR(byte[] first, byte[] second) {

        int byteArrayLength = (first.length + second.length) / 2;
        byte[] xorResult = new byte[byteArrayLength];
        for (int i = 0; i < byteArrayLength; i++) {
            xorResult[i] = (byte) (first[i] ^ second[i]);
            //print("inXOR----------" + first[i] + "secondPIN==" + second[i]);
        }
      //  System.out.println("The xor is " + ConvertUtils.bytesToHex(xorResult));
        return xorResult;
    }

    /**
     *
     * Arguments 0 = Card PAN 1 = Card PIN 2= Key 2 3= Key 3
     *
     * @param args
     * @throws java.lang.Exception
     */
    public static void main(String[] args) throws Exception {

        try {
            //Instance of this class
            PinBlockGen pinBlockGenerator = new PinBlockGen();
            //The PAN of the card
            String PAN = args[0];
            //THe PIN of the Card
            String PIN = args[1];
            //The First PEK-PIN Encryption Key
            String PEK1 = args[2];
            String PEK2 = "";
            try {
                //The second PEK-PIN Encryption Key
                PEK2 = args[3];

                System.out.println("Using two Keys for Encryption");
            } catch (Exception ex) {
                System.out.println("Using only one Key for Encryption");
            }

            //Java Hexadecimal Pattern class
            Pattern hexPattern = Pattern.compile("[0-9a-fA-F]*");
            if (hexPattern.matcher(PAN).matches() == false || hexPattern.matcher(PIN).matches() == false || hexPattern.matcher(PEK1).matches() == false || hexPattern.matcher(PEK2).matches() == false) {
                System.out.println("Check Input Data......One or more of your input String is not an hexadecimal character");
                return;
            }

            if (!PEK1.equals("") && PEK2.equals("")) {
                System.out.println("The PIN Block is " + pinBlockGenerator.getPINBlock(PIN, PAN, PEK1));
            } else if (!PEK1.equals("") && !PEK2.equals("")) {
                System.out.println("The PIN Block is " + pinBlockGenerator.getPINBlock(PIN, PAN, PEK1, PEK2));
            } else {
                System.out.println("No PEK Provided.....");
            }

        } catch (ArrayIndexOutOfBoundsException ex) {
            System.out.println("No Data to encrypt provided, \n Usage: \n 1: java TrippleDESTool CardPIN CardPAN PEK1 PEK2 \n \t\t or \n 2: java TrippleDESTool CardPIN CardPAN PEK1");
        }

    }
}
