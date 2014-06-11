
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;
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

public class arc4{
	

	public static void main(String [] args) throws Exception{
		String masterKey = "892ee41b152d5a58963d2491c7e867ed";
		String terminalID = "0000000000123456";
		String terminalIDHex = ConvertUtils.bytesToHex(terminalID.getBytes("UTF-8"));
		String key = masterKey + terminalIDHex ;
		String data = "56d3b0fca22f15b51b0422ba8849ec3d";

		new arc4().processData(key,data);
	}


	/**
    *Performs the encryption and decryption process
    *using the encryption mode and algorithm specified 
    *in the constructor
    *@param key THe Key to use for encryption
    *@param toXcrypt the data to encrypt or decrypt
    */
    public void processData(String key, String toXcrypt) throws InvalidKeyException {
        if(key.length() % 16 != 0)throw new InvalidKeyException("The Key Length provided is wrong");
        
      byte[] result = encryptRC4(ConvertUtils.hexToBytes(key), ConvertUtils.hexToBytes(toXcrypt));
      System.out.println("The result is ==="+ConvertUtils.bytesToHex(result));

    }

	 /**
     * Encrypts the supplied data with the supplied key in Tripple DES
     *
     * @param key - The key used to encrypt in byte[]
     * @param data Data to encrypt in byte[]
     * @return byte[] The Encrypted result data in byte[]
     *
     */
    private byte[] encryptRC4(byte[] key, byte[] data) {

        try {

          

            String finalKey = ConvertUtils.bytesToHex(key);

            byte[] finalRawKey = ConvertUtils.hexToBytes(finalKey);

         //  System.out.println("Key in is"+ConvertUtils.bytesToHex(key)+"\tKey length is \t"+key.length+"The final Key used for 3DES encrption is\t" + finalKey + "\tPlease remove this statement");

         //  System.out.println("Data is ==="+ConvertUtils.bytesToHex(data));
            SecretKey secretKey;
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "RC4");
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("RC4");
          
            secretKey = keyFactory.generateSecret(secretKeySpec);

            secretKey = keyFactory.translateKey(secretKey);

            Cipher cipher = Cipher.getInstance("RC4");
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
           //return result;

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
}