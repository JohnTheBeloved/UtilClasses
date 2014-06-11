
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.DESKeySpec;
import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

/**
 * A Cryptography class used for encryption using JCE
 */
public class Cryptor {

    /**
    *The data supplied for encryption or decryption
    */
    private byte[] operand;
    /**
    *The result of the encryption or decryption
    */
    private byte[] result;
    /**
     * Used to specify the algorithm used for the cryptography
     */
    private int ALGORITHM = 0;
    /**
    *Used to specify if Triple DES Algorithm should be used
    */
    public static final int T3DES_ALGORITHM = 1;
    /**
    *Used to specify if DES algorithm should be used
    */
    public static final int DES_ALGORITHM = 2;
      /**
    *Used to specify if the cryptography mode should be detected using the key provided
    */
    public static final int AUTO_DETECT_ALGORITHM = 3;
    /*
     *Used to represent the Encrypt mode specified
     */
    private int MODE = 0;
    /**
    *Used to specify if mode is for encryption
    */
    public static final int ENCRYPT_MODE = 4;
    /**
    *Used to specify if the cryptography mode is for decryption
    */
    public static final int DECRYPT_MODE = 5;
  

    /**
     * Constructor automatically detects the mode for encryption using the Key Length when the mode isn't specified
     * @param xcryptMode The Cryptography mode
     * @param algorithm 
     */
    public Cryptor(int xcryptMode){
        this(AUTO_DETECT_ALGORITHM,xcryptMode);
    }
    
    /*
     *Constructor used to encrypt or decrypt 
     */
    public Cryptor(int algorithm, int xcryptMode) {
        //Checks if the algorithm supplied is valid
        ALGORITHM = algorithm;
        MODE = xcryptMode;
        if (algorithm != DES_ALGORITHM && algorithm != T3DES_ALGORITHM & algorithm != AUTO_DETECT_ALGORITHM) {
            throw new RuntimeException("Invalid Algorithm Mode Supplied");
        }
        if (xcryptMode != ENCRYPT_MODE && xcryptMode != DECRYPT_MODE) {
            throw new RuntimeException("Invalid Cipher Mode Supplied");
        }

    }

    public void processData(byte[] key, byte[] toXcrypt) {
        operand = toXcrypt;
        //
        if (ALGORITHM == DES_ALGORITHM) {
            if (MODE == ENCRYPT_MODE) {
                result = encryptDES(key, toXcrypt);
            } else if (MODE == DECRYPT_MODE) {
                result = decryptDES(key, toXcrypt);
            }

        } else if (ALGORITHM == T3DES_ALGORITHM) {
            if (MODE == ENCRYPT_MODE) {
                result = encrypt3DES(key, toXcrypt);
            } else if (MODE == DECRYPT_MODE) {
                result = decrypt3DES(key, toXcrypt);
            }
        }
    }

    public void processData(String key, String toXcrypt) throws InvalidKeyException {
        if(key.length() % 16 != 0)throw new InvalidKeyException("The Key Length provided is wrong");
        
       processData(ConvertUtils.hexToBytes(key), ConvertUtils.hexToBytes(toXcrypt));
    }

    /**
     * Encrypts the supplied data with the supplied key in DES
     *
     * @param key - The key used to encrypt in byte[]
     * @param data Data to encrypt in byte[]
     * @return byte[] The Encrypted result data in byte[]
     *
     */
    public byte[] encryptDES(byte[] key, byte[] data) {

        try {
            SecretKey secretKey;
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            DESKeySpec desKeySpec = new DESKeySpec(key);

            secretKey = keyFactory.generateSecret(desKeySpec);

            secretKey = keyFactory.translateKey(secretKey);

            Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            try (CipherOutputStream cipherOS = new CipherOutputStream(bos, cipher)) {
                cipherOS.write(data);
                cipherOS.flush();
            }

            byte[] bytesEncrypted = bos.toByteArray();
            System.out.println("Encryption length is\t" + bytesEncrypted.length + ConvertUtils.bytesToHex(bytesEncrypted));

            return bytesEncrypted;

        } catch (UnsupportedEncodingException ex) {
            System.out.println("UnsupportedEncodingException\t" + ex.getMessage());
        } catch (NoSuchAlgorithmException ex) {
            System.out.println("NoSuchAlgorithmException\t" + ex.getMessage());
        } catch (InvalidKeySpecException ex) {
            System.out.println("InvalidKeySpecException\t" + ex.getMessage());
        } catch (InvalidKeyException ex) {
            System.out.println("InvalidKeyException\t" + ex.getMessage());
        }/*catch(IllegalBlockSizeException ex)
         {
         System.out.println("IllegalBlockSizeException\t"+ex.getMessage());
         }catch(BadPaddingException ex){
         System.out.println("BadPaddingException\t"+ex.getMessage());
         }*/ catch (NoSuchPaddingException ex) {
            System.out.println("NoSuchPaddingException\t" + ex.getMessage());
        } catch (IOException ex) {
            System.out.println("IOException\t" + ex.getMessage());
        }
        return null;
    }

    /**
     * Encrypts the supplied data with the supplied key in Tripple DES
     *
     * @param key - The key used to encrypt in byte[]
     * @param data Data to encrypt in byte[]
     * @return byte[] The Encrypted result data in byte[]
     *
     */
    public byte[] encrypt3DES(byte[] key, byte[] data) {

        try {

            //method  def in javadoc
            //arraycopy(Object src, int srcPos, Object dest, int destPos, int length)
            //byte[] keyToUse = new byte[24];
            //Pad the key if not yet 24 bytes
           /*if (key.length == 8) {
                System.arraycopy(key, 0, keyToUse, 0, 8);
                System.arraycopy(key, 0, keyToUse, 8, 8);
                System.arraycopy(key, 0, keyToUse, 16, 8);
            } else if (key.length == 16) {
                //keyToUse = key;
                System.arraycopy(key, 0, keyToUse, 0, 8);
                System.arraycopy(key, 0, keyToUse, 8, 8);
                System.arraycopy(key, 0, keyToUse, 16, 8);
            }*/

           // System.out.println("Key in is"+ConvertUtils.bytesToHex(key)+"\tKey length is \t"+key.length+"The final Key used for 3DES encrption is\t" + ConvertUtils.bytesToHex(key) + "\tPlease remove this statement");

            SecretKey secretKey;
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
            DESedeKeySpec desedeKeySpec = new DESedeKeySpec(key);

            secretKey = keyFactory.generateSecret(desedeKeySpec);

            secretKey = keyFactory.translateKey(secretKey);

            Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            CipherOutputStream cipherOS = new CipherOutputStream(bos, cipher);
                cipherOS.write(data);
                cipherOS.flush();
                cipherOS.close();
                bos.flush();
                bos.close();
            

            byte[] bytesEncrypted = bos.toByteArray();

           return bytesEncrypted;

        } catch (UnsupportedEncodingException ex) {
            System.out.println("UnsupportedEncodingException\t" + ex.getMessage());
        } catch (NoSuchAlgorithmException ex) {
            System.out.println("NoSuchAlgorithmException\t" + ex.getMessage());
        } catch (InvalidKeySpecException ex) {
            System.out.println("InvalidKeySpecException\t" + ex.getMessage());
        } catch (InvalidKeyException ex) {
            System.out.println("InvalidKeyException\t" + ex.getMessage());
        }/*catch(IllegalBlockSizeException ex)
         {
         System.out.println("IllegalBlockSizeException\t"+ex.getMessage());
         }catch(BadPaddingException ex){
         System.out.println("BadPaddingException\t"+ex.getMessage());
         }*/ catch (NoSuchPaddingException ex) {
            System.out.println("NoSuchPaddingException\t" + ex.getMessage());
        } catch (IOException ex) {
            System.out.println("IOException\t" + ex.getMessage());
        }
        return null;
    }

    /**
     * Used to validate the correctness of a key
     *
     * @param keyHex - The key Provided, Please provide correct length of the
     * key
     * <br>
     * because the function assumes to use DES when the 8 bytes(16 Hex
     * Characters) Key is provided
     * @param inKeyCheckValue The KCV supplied with the Key
     * @return boolean To check if the <i>inKeyCheckValue</i>
     *
     */
    public boolean validateKeyCheckValue(String keyHex, String inKeyCheckValue) {
        String keyCheckStdData = "0000000000000000";
        //byte[] bytesToEncrypt = ConvertUtils.hexToBytes(key);
        byte[] key = ConvertUtils.hexToBytes(keyHex);
        byte[] data = ConvertUtils.hexToBytes(keyCheckStdData);
        //
        boolean correct = false;
        //Use 3DES if key length is more than 8 bytes 64 bits(16 Hex)
        byte[] keyCheckValue = key.length > 8 ? encryptDES(key, data) : encrypt3DES(key, data);
        //
        System.out.println("The Key Check value should be " + inKeyCheckValue);
        return inKeyCheckValue.equals(ConvertUtils.bytesToHex(keyCheckValue));
    }

    public byte[] decryptDES(byte[] key, byte[] data) {

        try {
            SecretKey secretKey;
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            DESKeySpec desKeySpec = new DESKeySpec(key);

            secretKey = keyFactory.generateSecret(desKeySpec);

            secretKey = keyFactory.translateKey(secretKey);

            Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");

            //Used as the Initialition vector for CBC mode
            IvParameterSpec ivp = new IvParameterSpec(ConvertUtils.hexToBytes("0000000000000000"));
			//CBC mode
            //cipher.init(Cipher.DECRYPT_MODE,secretKey,ivp);

            //ECB mode
            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            ByteArrayOutputStream bos;
            CipherOutputStream cipherOS;

            bos = new ByteArrayOutputStream();
            cipherOS = new CipherOutputStream(bos, cipher);
            cipherOS.write(data);
            cipherOS.flush();
            cipherOS.close();

            byte[] bytesDecrypted = bos.toByteArray();
            System.out.println("Decryption length is\t" + bytesDecrypted.length + ConvertUtils.bytesToHex(bytesDecrypted));
            return bytesDecrypted;

        } catch (UnsupportedEncodingException ex) {
            System.out.println("UnsupportedEncodingException\t" + ex.getMessage());
        } catch (NoSuchAlgorithmException ex) {
            System.out.println("NoSuchAlgorithmException\t" + ex.getMessage());
        } catch (InvalidKeySpecException ex) {
            ex.printStackTrace(System.out);
            System.out.println("InvalidKeySpecException\t" + ex.getMessage());
        } catch (InvalidKeyException ex) {
            System.out.println("InvalidKeyException\t" + ex.getMessage());
        }/*catch(IllegalBlockSizeException ex)
         {
         System.out.println("IllegalBlockSizeException\t"+ex.getMessage());
         }catch(BadPaddingException ex){
         System.out.println("BadPaddingException\t"+ex.getMessage());
         }*/ catch (NoSuchPaddingException ex) {
            System.out.println("NoSuchPaddingException\t" + ex.getMessage());
        } catch (IOException ex) {
            System.out.println("IOException\t" + ex.getMessage());
        }
        return null;
    }

    /**
     * Function decrypts bytes of data using the key provided
     *
     * @param key The used for decryption
     * @param data The data to decrypt
     * @return byte[] The decrypted data in byte
     */
    public byte[] decrypt3DES(byte[] key, byte[] data) {

        try {

            //method  def in javadoc
            //arraycopy(Object src, int srcPos, Object dest, int destPos, int length)
            byte[] keyToUse = new byte[24];
            //Pad the key if not yet 24 bytes
            if (key.length == 8) {
                System.arraycopy(key, 0, keyToUse, 0, 8);
                System.arraycopy(key, 0, keyToUse, 8, 8);
                System.arraycopy(key, 0, keyToUse, 16, 8);
            } else if (key.length == 16) {
                System.arraycopy(key, 0, keyToUse, 0, 8);
                System.arraycopy(key, 0, keyToUse, 8, 8);
                System.arraycopy(key, 0, keyToUse, 16, 8);
            }

            System.out.println("The final Key used for 3DES decryption is\t" + ConvertUtils.bytesToHex(keyToUse));

            SecretKey secretKey;
            //byte[] keyByte = key.getBytes("UTF-8");
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
            DESedeKeySpec desedeKeySpec = new DESedeKeySpec(keyToUse);

            secretKey = keyFactory.generateSecret(desedeKeySpec);

            secretKey = keyFactory.translateKey(secretKey);

            Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");

            //Used as the Initialition vector for CBC mode(variable no used)
            //gives the same result with ECB mode when 16 0s are used
            IvParameterSpec ivp = new IvParameterSpec(ConvertUtils.hexToBytes("0000000000000000"));
			//CBC mode
            //cipher.init(Cipher.DECRYPT_MODE,secretKey,ivp);

            //ECB mode
            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            ByteArrayOutputStream bos;
            CipherOutputStream cipherOS;

            bos = new ByteArrayOutputStream();
            cipherOS = new CipherOutputStream(bos, cipher);
            cipherOS.write(data);
            cipherOS.flush();
            cipherOS.close();

            byte[] bytesDecrypted = bos.toByteArray();
            System.out.println("Encryption length is\t" + bytesDecrypted.length + ConvertUtils.bytesToHex(bytesDecrypted));

            return bytesDecrypted;
        } catch (UnsupportedEncodingException ex) {
            System.out.println("UnsupportedEncodingException\t" + ex.getMessage());
        } catch (NoSuchAlgorithmException ex) {
            System.out.println("NoSuchAlgorithmException\t" + ex.getMessage());
        } catch (InvalidKeySpecException ex) {
            ex.printStackTrace(System.out);
            System.out.println("InvalidKeySpecException\t" + ex.getMessage());
        } catch (InvalidKeyException ex) {
            System.out.println("InvalidKeyException\t" + ex.getMessage());
        }/*catch(IllegalBlockSizeException ex)
         {
         System.out.println("IllegalBlockSizeException\t"+ex.getMessage());
         }catch(BadPaddingException ex){
         System.out.println("BadPaddingException\t"+ex.getMessage());
         }*/ catch (NoSuchPaddingException ex) {
            System.out.println("NoSuchPaddingException\t" + ex.getMessage());
        } catch (IOException ex) {
            System.out.println("IOException\t" + ex.getMessage());
        }
        return null;
    }
    
     /**
     * Gets the Result of the Crytography done
     *
     * @return String The Result of the Cryptography
     */
    public String getResult() {
        String stringOperand = ConvertUtils.bytesToHex(operand);
        String stringResult = ConvertUtils.bytesToHex(result);
        switch (MODE) {
            case ENCRYPT_MODE:
                System.out.println("Encrypted \t" + stringOperand + "\tto\t" + stringResult);
                break;
            case DECRYPT_MODE:
                System.out.println("Decrypted \t" + stringOperand + "\tto\t" + stringResult);
                break;
        }
        return stringResult;
    }

    /**
     * Usage: args[0] : Crypt mode (2 for Encryption, 3 for Decryption) args[1]
     * : Algorithm to use(0 for Tripple DES, 1 for DES) args[2] : dataToEncrypt
     * args[3] : key to use(key 1 if two keys) args[4] : key 2 (if two keys)
     *
     * @param args
     * @throws java.lang.Exception
     */
    public static void main(String[] args) throws Exception {
        String dataToEncrypt, key1, key2;
        byte[] keyBytes;
        int cryptoMode, algorithm;
        try {
            cryptoMode = ENCRYPT_MODE;//Integer.valueOf(args[0]);
            algorithm = T3DES_ALGORITHM;// Integer.valueOf(args[1]);
            dataToEncrypt = "0433646FD6976AAF";//args[2];
            key1 = "ADB876C4FF8A187D372B42A4A7B693F8";//args[3];
            try {
                key2 = args[4];
                keyBytes = ConvertUtils.XORToBytes(key1, key2);
                System.out.println("Two keys supplied, using two keys...");
            } catch (ArrayIndexOutOfBoundsException ex) {
                keyBytes = ConvertUtils.hexToBytes(key1);
                System.out.println("One key supplied, using one key...");
            }

        } catch (ArrayIndexOutOfBoundsException ex) {//D64F31B0C96128CC
            System.out.println("Usage: \n1. java KeyGen cryptionMode algorithm dataToEncrypt key1InHEX\t or \n. java KeyGen dataToEncrypt key1InHEX keyInHEX");
            return;
        }
        
        Cryptor encryptor, decryptor;
        
        encryptor = new Cryptor(T3DES_ALGORITHM, ENCRYPT_MODE);
        System.out.println("Key passed in\t"+ConvertUtils.bytesToHex(keyBytes));
        encryptor.processData(keyBytes, ConvertUtils.hexToBytes(dataToEncrypt));

        decryptor = new Cryptor(T3DES_ALGORITHM, DECRYPT_MODE);
        decryptor.processData(keyBytes, ConvertUtils.hexToBytes(encryptor.getResult()));
        decryptor.getResult();
    }

   

}
