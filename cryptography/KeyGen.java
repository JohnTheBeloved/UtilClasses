import javax.crypto.KeyGenerator;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.DESKeySpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;

/**
*A Cryptography class used for encryption using JCE
*/
public class Cryptor{

	/**
	*Used to specify the algorithm used for the cryptography
	*/
	public static final int 3DES_ALGORITHM = 0;
	public static final int DES_ALGORITHM = 1;

	/*
	*Used to specify if cipher should be initialised the cryptographing(CIpher)
	*/
	public static final int ENCRYPT_MODE = 2;
	public static final int DECRYPT_MODE = 3;

	/*
	*Constructor used to encrypt or decrypt 
	*/
	public Cryptor(byte[] keyBytes, String hexToXcrypt, int algorithm, int xcryptMode){
		//Checks if the algorithm supplied is valid
		if(xcryptMode != ENCRYPT_MODE && xcryptMode != DECRYPT_MODE)throw new RuntimeException("Invalid Cipher Mode Supplied");
		//
		if(algorithm == DES_ALGORITHM){
			if(xcryptoMode == ENCRYPT_MODE)return encryptDES(keyBytes, hexToXcrypt);
			else if(cryptoMode == DECRYPT_MODE)return decryptDES(keyBytes,hexToXcrypt);
			
		}else if(algorithm == 3DES_ALGORITHM){
			if(xcryptoMode == ENCRYPT_MODE)return encrypt3DES(keyBytes, hexToXcrypt);
			else if(cryptoMode == DECRYPT_MODE)return decrypt3DES(keyBytes,hexToXcrypt);
		}

	}

	/**
	*@param keyByte -
	*
	*/
	public String encryptDES(byte[] keyByte, String hexToEncrypt){
		
		try{
			SecretKey secretKey = null;
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
			DESKeySpec desKeySpec = new DESKeySpec(keyByte);

			secretKey = keyFactory.generateSecret(desKeySpec);
			
			secretKey = keyFactory.translateKey(secretKey);

			//System.out.println("The Key is "+new String(secretKey.getEncoded(),"UTF-8"));

			Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE,secretKey);
			String wordToEncrypt = hexToEncrypt;//"abcdef134567890";
			//byte[] byteToEncrypt = wordToEncrypt.getBytes("UTF-8");
			byte[] byteToEncrypt = ConvertUtils.hexToBytes(wordToEncrypt);
			byte[] bytesEncrypted;
			String stringEncrypted;

			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			CipherOutputStream cipherOS = new CipherOutputStream(bos,cipher);
			cipherOS.write(byteToEncrypt);
			cipherOS.flush();
			cipherOS.close();
			
			bytesEncrypted = bos.toByteArray();
			stringEncrypted = ConvertUtils.bytesToHex(bytesEncrypted);

			//System.out.println("Encypted word is \t"+ new String(bytesEncrypted,"UTF-8"));
			System.out.println("Encypted\t"+wordToEncrypt+" to\t"+ stringEncrypted);
			return stringEncrypted;

		}catch(UnsupportedEncodingException ex){
			System.out.println("UnsupportedEncodingException\t"+ex.getMessage());
		}catch(NoSuchAlgorithmException ex){
			System.out.println("NoSuchAlgorithmException\t"+ex.getMessage());
		}catch(InvalidKeySpecException ex)
		{
			System.out.println("InvalidKeySpecException\t"+ex.getMessage());
		}catch(InvalidKeyException ex){
			System.out.println("InvalidKeyException\t"+ex.getMessage());
		}/*catch(IllegalBlockSizeException ex)
		{
			System.out.println("IllegalBlockSizeException\t"+ex.getMessage());
		}catch(BadPaddingException ex){
			System.out.println("BadPaddingException\t"+ex.getMessage());
		}*/catch(NoSuchPaddingException ex){
			System.out.println("NoSuchPaddingException\t"+ex.getMessage());
		}catch(IOException ex){
			System.out.println("IOException\t"+ex.getMessage());
		}
		return null;
	}

	/**
	*@param keyByte -
	*
	*/
	public String encrypt3DES(byte[] keyBytes, String hexToEncrypt){
		
		try{
			//method  def in javadoc
			//arraycopy(Object src, int srcPos, Object dest, int destPos, int length)

			//Pad the key if not yet 24 bytes
			if(keyBytes.length == 8 ){
				System.arraycopy(keyBytes,0,keyBytes,8,8);
				System.arraycopy(keyBytes,0,keyBytes,16,8);
			}
			else if(keyBytes.length == 16){
				System.arraycopy(keyBytes,0,keyBytes,8,8);
			}

			SecretKey secretKey = null;
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
			DESedeKeySpec desedeKeySpec = new DESedeKeySpec(keyBytes);

			secretKey = keyFactory.generateSecret(desedeKeySpec);
			
			secretKey = keyFactory.translateKey(secretKey);

			Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE,secretKey);
			String hexToEncrypt = hexToEncrypt;
			//byte[] byteToEncrypt = wordToEncrypt.getBytes("UTF-8");
			byte[] byteToEncrypt = ConvertUtils.hexToBytes(hexToEncrypt);
			byte[] bytesEncrypted;
			String stringEncrypted;

			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			CipherOutputStream cipherOS = new CipherOutputStream(bos,cipher);
			cipherOS.write(byteToEncrypt);
			cipherOS.flush();
			cipherOS.close();
			
			bytesEncrypted = bos.toByteArray();
			stringEncrypted = ConvertUtils.bytesToHex(bytesEncrypted);

			//System.out.println("Encypted word is \t"+ new String(bytesEncrypted,"UTF-8"));
			System.out.println("Encypted\t"+wordToEncrypt+" to\t"+ stringEncrypted);
			return stringEncrypted;

		}catch(UnsupportedEncodingException ex){
			System.out.println("UnsupportedEncodingException\t"+ex.getMessage());
		}catch(NoSuchAlgorithmException ex){
			System.out.println("NoSuchAlgorithmException\t"+ex.getMessage());
		}catch(InvalidKeySpecException ex)
		{
			System.out.println("InvalidKeySpecException\t"+ex.getMessage());
		}catch(InvalidKeyException ex){
			System.out.println("InvalidKeyException\t"+ex.getMessage());
		}/*catch(IllegalBlockSizeException ex)
		{
			System.out.println("IllegalBlockSizeException\t"+ex.getMessage());
		}catch(BadPaddingException ex){
			System.out.println("BadPaddingException\t"+ex.getMessage());
		}*/catch(NoSuchPaddingException ex){
			System.out.println("NoSuchPaddingException\t"+ex.getMessage());
		}catch(IOException ex){
			System.out.println("IOException\t"+ex.getMessage());
		}
		return null;
	}

	/**
	*Used to validate the corectness of a key
	*@param key - The key Provided, Please provide correct length of the key </br>
	*because the function assumes to use DES when the 8 bytes(16 Hex Characters) Key is provided
	*
	*/
	public boolean validateKeyCheckValue(String key, String inKeyCheckValue){
		String keyCheckStdData = "0000000000000000";
		//byte[] bytesToEncrypt = ConvertUtils.hexToBytes(key);
		byte[] key = ConvertUtils.hexToBytes(key);
		//
		boolean correct = false;
		//Use 3DES if key length is more than 8 bytes 64 bits(16 Hex)
		String keyCheckValue = key.length() > 16 ? encryptDES(keyCheckStdData) : encrypt3DES(keyCheckStdData);
		//
		System.out.println("The Key Check value should be " +keyCheckValue);
		return inKeyCheckValue.equals(keyCheckValue);
	}


	public String decryptDES(byte[] keyByte, String hexToEncrypt){
		
		try{
			SecretKey secretKey = null;
			//byte[] keyByte = key.getBytes("UTF-8");
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
			DESKeySpec desKeySpec = new DESKeySpec(keyByte);

			secretKey = keyFactory.generateSecret(desKeySpec);
			
			secretKey = keyFactory.translateKey(secretKey);
			
			Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
            
			//Used as the Initialition vector for CBC mode
            IvParameterSpec ivp = new IvParameterSpec(ConvertUtils.hexToBytes("0000000000000000"));
			//CBC mode
			//cipher.init(Cipher.DECRYPT_MODE,secretKey,ivp);
			
			//ECB mode
			cipher.init(Cipher.DECRYPT_MODE,secretKey);
			
			ByteArrayOutputStream bos;
			CipherOutputStream cipherOS;
			
			byte[] bytesToDecrypt = ConvertUtils.hexToBytes(hexToEncrypt);
			byte[] bytesDecrypted;
			String stringDecrypted;

			bos = new ByteArrayOutputStream();
			cipherOS = new CipherOutputStream(bos,cipher);
			cipherOS.write(bytesToDecrypt);
			cipherOS.flush();
			cipherOS.close();
			
			bytesDecrypted = bos.toByteArray();
			stringDecrypted = ConvertUtils.bytesToHex(bytesDecrypted);

			System.out.println("Decrypted\t"+hexToEncrypt+ "\tback to\t"+ stringDecrypted);
			
			return stringDecrypted;
			//byteEncrypted = cipher.doFinal(byteEncrypted);

			//System.out.println("Decrypted word is \t"+ new String(byteEncrypted,"UTF-8"));

		}catch(UnsupportedEncodingException ex){
			System.out.println("Unsupppublic String decrypt(byte[] keyByte, String hexToEncrypt){
		
		try{
			SecretKey secretKey = null;
			//byte[] keyByte = key.getBytes("UTF-8");
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
			DESKeySpec desKeySpec = new DESKeySpec(keyByte);

			secretKey = keyFactory.generateSecret(desKeySpec);
			
			secretKey = keyFactory.translateKey(secretKey);
			
			Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
            
			//Used as the Initialition vector for CBC mode
            IvParameterSpec ivp = new IvParameterSpec(ConvertUtils.hexToBytes("0000000000000000"));
			//CBC mode
			//cipher.init(Cipher.DECRYPT_MODE,secretKey,ivp);
			
			//ECB mode
			cipher.init(Cipher.DECRYPT_MODE,secretKey);
			
			ByteArrayOutputStream bos;
			CipherOutputStream cipherOS;
			
			byte[] bytesToDecrypt = ConvertUtils.hexToBytes(hexToEncrypt);
			byte[] bytesDecrypted;
			String stringDecrypted;

			bos = new ByteArrayOutputStream();
			cipherOS = new CipherOutputStream(bos,cipher);
			cipherOS.write(bytesToDecrypt);
			cipherOS.flush();
			cipherOS.close();
			
			bytesDecrypted = bos.toByteArray();
			stringDecrypted = ConvertUtils.bytesToHex(bytesDecrypted);

			System.out.println("Decrypted\t"+hexToEncrypt+ "\tback to\t"+ stringDecrypted);
			
			return stringDecrypted;
			//byteEncrypted = cipher.doFinal(byteEncrypted);

			//System.out.println("Decrypted word is \t"+ new String(byteEncrypted,"UTF-8"));

		}catch(UnsupportedEncodingException ex){
			System.out.println("UnsupportedEncodingException\t"+ex.getMessage());
		}catch(NoSuchAlgorithmException ex){
			System.out.println("NoSuchAlgorithmException\t"+ex.getMessage());
		}catch(InvalidKeySpecException ex)
		{
			ex.printStackTrace(System.out);
			System.out.println("InvalidKeySpecException\t"+ex.getMessage());
		}catch(InvalidKeyException ex){
			System.out.println("InvalidKeyException\t"+ex.getMessage());
		}/*catch(IllegalBlockSizeException ex)
		{
			System.out.println("IllegalBlockSizeException\t"+ex.getMessage());
		}catch(BadPaddingException ex){
			System.out.println("BadPaddingException\t"+ex.getMessage());
		}*/catch(NoSuchPaddingException ex){
			System.out.println("NoSuchPaddingException\t"+ex.getMessage());
		}catch(IOException ex){
			System.out.println("IOException\t"+ex.getMessage());
		}
		return null;
	}ortedEncodingException\t"+ex.getMessage());
		}catch(NoSuchAlgorithmException ex){
			System.out.println("NoSuchAlgorithmException\t"+ex.getMessage());
		}catch(InvalidKeySpecException ex)
		{
			ex.printStackTrace(System.out);
			System.out.println("InvalidKeySpecException\t"+ex.getMessage());
		}catch(InvalidKeyException ex){
			System.out.println("InvalidKeyException\t"+ex.getMessage());
		}/*catch(IllegalBlockSizeException ex)
		{
			System.out.println("IllegalBlockSizeException\t"+ex.getMessage());
		}catch(BadPaddingException ex){
			System.out.println("BadPaddingException\t"+ex.getMessage());
		}*/catch(NoSuchPaddingException ex){
			System.out.println("NoSuchPaddingException\t"+ex.getMessage());
		}catch(IOException ex){
			System.out.println("IOException\t"+ex.getMessage());
		}
		return null;
	}

	/**
	*Function decrypts hexadecimal string using the key provided
	*/
	public String decrypt3DES(byte[] keyByte, String hexToEncrypt){
		
		try{
			SecretKey secretKey = null;
			//byte[] keyByte = key.getBytes("UTF-8");
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
			DESedeKeySpec desedeKeySpec = new DESedeKeySpec(keyByte);

			secretKey = keyFactory.generateSecret(desedeKeySpec);
			
			secretKey = keyFactory.translateKey(secretKey);
			
			Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
            
			//Used as the Initialition vector for CBC mode(variable no used)
			//gives the same result with ECB mode when 16 0s are used
            IvParameterSpec ivp = new IvParameterSpec(ConvertUtils.hexToBytes("0000000000000000"));
			//CBC mode
			//cipher.init(Cipher.DECRYPT_MODE,secretKey,ivp);
			
			//ECB mode
			cipher.init(Cipher.DECRYPT_MODE,secretKey);
			
			ByteArrayOutputStream bos;
			CipherOutputStream cipherOS;
			
			byte[] bytesToDecrypt = ConvertUtils.hexToBytes(hexToEncrypt);
			byte[] bytesDecrypted;
			String stringDecrypted;

			bos = new ByteArrayOutputStream();
			cipherOS = new CipherOutputStream(bos,cipher);
			cipherOS.write(bytesToDecrypt);
			cipherOS.flush();
			cipherOS.close();
			
			bytesDecrypted = bos.toByteArray();
			stringDecrypted = ConvertUtils.bytesToHex(bytesDecrypted);

			System.out.println("Decrypted\t"+hexToEncrypt+ "\tback to\t"+ stringDecrypted);
			
			return stringDecrypted;
			//byteEncrypted = cipher.doFinal(byteEncrypted);

			//System.out.println("Decrypted word is \t"+ new String(byteEncrypted,"UTF-8"));

		}catch(UnsupportedEncodingException ex){
			System.out.println("UnsupportedEncodingException\t"+ex.getMessage());
		}catch(NoSuchAlgorithmException ex){
			System.out.println("NoSuchAlgorithmException\t"+ex.getMessage());
		}catch(InvalidKeySpecException ex)
		{
			ex.printStackTrace(System.out);
			System.out.println("InvalidKeySpecException\t"+ex.getMessage());
		}catch(InvalidKeyException ex){
			System.out.println("InvalidKeyException\t"+ex.getMessage());
		}/*catch(IllegalBlockSizeException ex)
		{
			System.out.println("IllegalBlockSizeException\t"+ex.getMessage());
		}catch(BadPaddingException ex){
			System.out.println("BadPaddingException\t"+ex.getMessage());
		}*/catch(NoSuchPaddingException ex){
			System.out.println("NoSuchPaddingException\t"+ex.getMessage());
		}catch(IOException ex){
			System.out.println("IOException\t"+ex.getMessage());
		}
		return null;
	}

	/**
	*
	*/
	public static void main(String [] args) throws Exception{
		String dataToEncrypt, key1,key = null;
		byte[] keyBytes;
		try{
			dataToEncrypt = args[0];
			key1 = args[1];
			try{
				key = args[2];
				keyBytes = ConvertUtils.XORToBytes(key1,key);
				System.out.println("Two keys supplied, using two keys...");
			}catch(ArrayIndexOutOfBoundsException ex){
				keyBytes = ConvertUtils.hexToBytes(key1);
				System.out.println("One key supplied, using one key...");
			}
			
		}catch(ArrayIndexOutOfBoundsException ex){
			System.out.println("Usage: \n1. java KeyGen dataToEncrypt key1InHEX\t or \n. java KeyGen dataToEncrypt key1InHEX keyInHEX");
			return;
		}
		KeyGen keyGen;
		if(key != null){
			
		 	keyGen = new KeyGen(keyBytes,dataToEncrypt);
		}else{
			
			keyGen = new KeyGen(keyBytes,dataToEncrypt);
		}

		//System.out.println(keyGen.getkey());
	}

}