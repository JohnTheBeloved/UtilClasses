/**
 * TrippleDESTool.java
 * Purpose: Encrypts and Decrypts String of data.
 *using Tripple DES encryption 
 *Also used in generating pin block
 * @author JohnTheBeloved
 *
 *Note that you cannot Encypt a non Hexadecimal String 
 *So This Class concerts the data you pass in to hexadecimal
 *before encrypting it
 *
 *Likewise, it converts the the decrypted data back to a normal String
 *i.e Hex String is returned after a normal java cryptogram decryption
*/

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import java.security.MessageDigest;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import java.util.regex.*;

public class TrippleDESTool{
	
	

	/**
	*Constructor receives a String specifying the key to use for encryption
	*@param The Key to use for the Encryption
	*/
	public TrippleDESTool() {
		
	}

	/**
	*Encrypts a String of data and returns an Encrypted String
	*using the key specified during instantiation of this class
	*
	*Note that the String is first converted to Hexadecimal
	*
	*@throws UnsupportedEncodingException This will be due to the String Format supplied
	*/
	public  String encryptStringData2(byte[] rawkey, String stringToEncrypt) throws UnsupportedEncodingException{

		//Data to encypt should be an Hexadecimal
		String hexStringToEncrypt =  "";//ConvertUtils.stringToHex(stringToEncrypt);;

	//if(Pattern.matches("[0-9a-fA-F]",stringToEncrypt.subSequence(0,stringToEncrypt.length()))){
	//		System.out.println("Data to encrypt is an Hexadecimal String, not converting...");
	//		hexStringToEncrypt = stringToEncrypt;
	//}else{
	//		//Convert the String gotten to hexadecimal String
	//		 hexStringToEncrypt = ConvertUtils.stringToHex(stringToEncrypt);
	//		System.out.println("Data to encrypt is not an Hexadecimal String, converting String\t"+ stringToEncrypt+ " to Hex\t"+hexStringToEncrypt);
	//}

		//Declare Encrypted String here
		String encryptedString= "";
		//Encrypt call
		try{
		 encryptedString = Encrypt(rawkey, hexStringToEncrypt);
		 System.out.println("Encrypted Data From\t" +stringToEncrypt+  "\tto\t"+encryptedString);
		}catch(Exception ex)
		{
			System.out.println(ex);
		}

		//Test Decryption here
		//	String decryptedString = decryptData(encryptedString);
		//Try to test decryption here
		

		return encryptedString;
	}

	/**
	*Encrypts a String of data and returns an Encrypted String
	*using the key specified during instantiation of this class
	*
	*Note that the String is first converted to Hexadecimal
	*
	*@throws UnsupportedEncodingException This will be due to the String Format supplied
	*/
	public  String encryptStringData(byte[] rawkey, String stringToEncrypt) throws UnsupportedEncodingException{

		//Data to encypt should be an Hexadecimal
		String hexStringToEncrypt =  "";//ConvertUtils.stringToHex(stringToEncrypt);;

	//if(Pattern.matches("[0-9a-fA-F]",stringToEncrypt.subSequence(0,stringToEncrypt.length()))){
	//		System.out.println("Data to encrypt is an Hexadecimal String, not converting...");
	//		hexStringToEncrypt = stringToEncrypt;
	//}else{
	//		//Convert the String gotten to hexadecimal String
	//		 hexStringToEncrypt = ConvertUtils.stringToHex(stringToEncrypt);
	//		System.out.println("Data to encrypt is not an Hexadecimal String, converting String\t"+ stringToEncrypt+ " to Hex\t"+hexStringToEncrypt);
	//}

		//Declare Encrypted String here
		String encryptedString= "";
		//Encrypt call
		try{
		 encryptedString = Encrypt(rawkey, hexStringToEncrypt);
		 System.out.println("Encrypted Data From\t" +stringToEncrypt+  "\tto\t"+encryptedString);
		}catch(Exception ex)
		{
			System.out.println(ex);
		}

		//Test Decryption here
		//	String decryptedString = decryptData(encryptedString);
		//Try to test decryption here
		

		return encryptedString;
	}



	/**
	*Decrypts a String of data and returns a decrypted String
	*using the key specified during instantiation of this class
	*	
	*@param dataStringToEncrypt --shold be in hexadecimal format
	*Note the decrypted data is converted to string before returning - Hex String is returned during decyption
	*/
	public String decryptData(byte[] key, String dataStringToDecrypt){
			 String realDataString= "";
		try{
		String decryptedDataHex; decryptedDataHex = Decrypt(key, dataStringToDecrypt);
		realDataString = "";//ConvertUtils.hexToString(decryptedDataHex);

		}catch(Exception ex)
		{
			System.out.println(ex);
		}
		
		// System.out.println("Decrypted Data From" +dataStringToEncrypt+  "to"+realDataString);

		return  realDataString;
	}

	

	/**
	*This function Encrypts the an hexadecimal String using the java Secret Key Provided
	*@return Encrypted Hexadecimal String
	*@param key The Java SecretKey to use for the encryption
	*@param dataToEncryptInHex THe data to encrypt***In Hexadecimal Form****
	*/
	private String Encrypt(byte[] rawKey, String dataToEncryptInHex) throws NoSuchAlgorithmException, NoSuchPaddingException,InvalidKeySpecException, InvalidKeyException, IOException 
	{

		
		Cipher cipher;
		/**The Key being used for encryption*/
		Key cipherKey = readKey(rawKey);
		cipher = Cipher.getInstance("DESede/ECB/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, cipherKey);
		ByteArrayOutputStream bytes = new ByteArrayOutputStream();
		byte[] clearText = ConvertUtils.hexToBytes(dataToEncryptInHex);

		CipherOutputStream out = new CipherOutputStream(bytes, cipher);
		out.write(clearText);
		out.flush();
		out.close();
		byte[] ciphertext = bytes.toByteArray();
		bytes.flush();
		bytes.close();

		String encrypted = ConvertUtils.bytesToHex(ciphertext);
		java.util.Arrays.fill(clearText, (byte) 0);
		java.util.Arrays.fill(ciphertext, (byte) 0);
		return encrypted;

	}

	/**
	*This function Decrypts the an hexadecimal String using the java Secret Key Object Provided
	*@return Decrypted Hexadecimal String
	*@param key The Java SecretKey to use for the encryption
	*@param dataToEncryptInHex THe data to decrypt***In Hexadecimal Form****
	*/
	private  String Decrypt(byte[] rawKey, String dataToDecryptInHex) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException,InvalidKeySpecException, InvalidKeyException 
	{

		//Complicated issues here

		// Instantitae The Java Cryptogram Cipher Object specifying the Decryption Type to use
		Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
		/**The Key being used for encryption*/
		Key cipherKey = readKey(rawKey);
		//Initialise cipher using the secret key
		cipher.init(Cipher.DECRYPT_MODE, cipherKey);
		//Stream is used in the decryption
		ByteArrayOutputStream bytes = new ByteArrayOutputStream();
		//Convert data to decrypt to a byte array
		byte[] ciphertext = ConvertUtils.hexToBytes(dataToDecryptInHex);
		//This objects vomits the decrypted data
		CipherOutputStream out;
		//
		out = new CipherOutputStream(bytes, cipher);
		//Decrypt the data in byte Array form using the initilised cipher object
		out.write(ciphertext);
		out.flush();
		out.close();
		//
		byte[] deciphertext = bytes.toByteArray();
		bytes.flush();
		bytes.close();

		//Convert Decrypted data into Hexadecimal String
		String decryptedData = ConvertUtils.bytesToHex(deciphertext);



		//
		java.util.Arrays.fill(ciphertext, (byte) 0);
		java.util.Arrays.fill(deciphertext, (byte) 0);
		// Take your data
		return decryptedData;

	}

	public SecretKey readKey(byte[] rawkey) throws InvalidKeyException, InvalidKeySpecException,NoSuchAlgorithmException {

		// Read the raw bytes from the keyfile
	

			DESedeKeySpec keyspec = new DESedeKeySpec(rawkey);
			SecretKeyFactory keyfactory = SecretKeyFactory.getInstance("DESede");
			SecretKey key;
			key = keyfactory.generateSecret(keyspec);

			key = keyfactory.translateKey(key);
			return key;
		
	}


	/**
	*This method makes sures the key string length is 48
	*Cos Encryption uses se bytes key
	*Do your padding of the keys here, depending
	*/
	private String getRefinedKey(String keyString)
	{
		//Pad the key to make it 48 length
		switch(keyString.length())
		{
			case 16:
				//System.out.println("KEY========="+keyString+keyString+keyString);
				return keyString+keyString+keyString;
			
			case 32:
				return keyString+keyString;
		
			case 48:
				return keyString;
		
			default:
				return keyString;
			
		}
		
	}

	private String getRefinedPINFormat(String cardPIN){

		cardPIN = "0"+cardPIN.length()+cardPIN;
		while(cardPIN.length() <= 16)
		{
			cardPIN = cardPIN + "F";
		}
		System.out.println("PADDED CARD PIN==="+cardPIN);
		return cardPIN;
	}


	private String getRefinedPANFormat(String cardPAN){

		//Get two diffrent parts from the PAN
		//123 4567890123456
		String cardPANPart1 = cardPAN.substring(cardPAN.length() - 13, cardPAN.length());
		//456789012345
		String cardPANPart2 = cardPANPart1.substring(0, cardPANPart1.length() - 1);
		String paddedCardPAN = cardPANPart2;

		int length = cardPANPart2.length();

		//System.out.println("IN CARD PAN");
		//Loop to pad the result to become 16
		while(paddedCardPAN.length() <= 16)
		{
			paddedCardPAN = "0"+paddedCardPAN;
		}

		System.out.println("PADDED CARD PAN==="+paddedCardPAN);
		return paddedCardPAN;
		
	}




	public String getPINBlock(String PAN,String PIN,String iPEK1, String iPEK2) throws NoSuchAlgorithmException,InvalidKeySpecException,NoSuchPaddingException,InvalidKeyException,IOException{
		//Make sure that the Second Encryption Key is 48....By adding the last 16 digits of the PEK
		String PEK1 = iPEK1 + iPEK1.substring(0, 48 - iPEK1.length());
		//Make sure that the Second Encryption Key is 48....By adding the last 16 digits of the PEK
		String PEK2 = iPEK2 + iPEK2.substring(0, 48 - iPEK2.length());

		//Get XOR or the two keys
		byte[] PEK = getRawKey(PEK1,PEK2);

		//THe unencrypted pin block format
		String PINFORMAT = getPINFormat(PIN,PAN);

		return Encrypt(PEK,PINFORMAT);

	}

	public String getPINBlock(String PAN,String PIN,String iPEK) throws NoSuchAlgorithmException,InvalidKeySpecException,InvalidKeyException,NoSuchPaddingException,IOException{
		//Make sure that the Second Encryption Key is 48....By adding the last 16 digits of the PEK
		String PEK1 = iPEK + iPEK.substring(0, 48 - iPEK.length());
		
		//Get XOR or the two keys
		byte[] PEK = getRawKey(PEK1);

		//THe unencrypted pin block format
		String PINFORMAT = getPINFormat(PIN,PAN);

		return Encrypt(PEK,PINFORMAT);

	}

	//One Key Provided
	private byte[] getRawKey(String key){

		return ConvertUtils.hexToBytes(getRefinedKey(key));
	}

	//Two Keys Provided
	private byte[] getRawKey(String firstKey, String secondKey){

		return XOR(ConvertUtils.hexToBytes(getRefinedKey(firstKey)),ConvertUtils.hexToBytes(getRefinedKey(secondKey)));
		
	}

	/**
	*Gets the Final PIN format to encrpt in order to get the PIN BLOCK
	*@param PIN The PIN of the Card 
	*@param PAN The PAN of the Card
	*/
	private String getPINFormat(String PIN, String PAN){

		String PINFormat = getRefinedPINFormat(PIN);
		String PANFormat = getRefinedPANFormat(PAN);
		//Exclusive OR of the two formats for pin block
		byte[] rawPINBlockFormat = XOR(ConvertUtils.hexToBytes(PINFormat),ConvertUtils.hexToBytes(PANFormat));
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
		System.out.println("The xor is "+ConvertUtils.bytesToHex(xorResult));
		return xorResult;
	}



		/**
	*
	*Arguments 
	*0 = Card PAN
	*1 = Card PIN
	*2= Key 2
	*3= Key 3
	*
	*/
	public static void main(String [] args) throws Exception{

		try{
		//Instance of this class
		TrippleDESTool encryptor = new TrippleDESTool();
		//The PAN of the card
		String PAN = args[0];
		//THe PIN of the Card
		String PIN = args[1];
		//The First PEK-PIN Encryption Key
		String PEK1 = args[2];
		String PEK2 = "";
		try{ 
		//The second PEK-PIN Encryption Key
		PEK2 = args[3];

			System.out.println("Using two Keys for Encryption");
		}catch(Exception ex)
		{
			System.out.println("Using only one Key for Encryption");
		}
		
		
		
			//Java Hexadecimal Pattern class
			Pattern hexPattern = Pattern.compile("[0-9a-fA-F]*");
			if(hexPattern.matcher(PAN).matches() == false || hexPattern.matcher(PIN).matches() == false || hexPattern.matcher(PEK1).matches() == false || hexPattern.matcher(PEK2).matches() == false){
				System.out.println("Check Input Data......One or more of your input String is not an hexadecimal character");
				return;
			}


			if(PEK1 != null && PEK2  == "")
			{
				System.out.println("The PIN Block is " + encryptor.getPINBlock(PIN,PAN,PEK1));
			}else if(PEK1 != null && PEK2  != null)
			{
				System.out.println("The PIN Block is " + encryptor.getPINBlock(PIN,PAN,PEK1,PEK2));
			}else{
				 System.out.println("No PEK Provided.....");
				 return;
			}

		}catch(ArrayIndexOutOfBoundsException ex)
		{
			System.out.println("No Data to encrypt provided, \n Usage: \n 1: java TrippleDESTool CardPIN CardPAN PEK1 PEK2 \n \t\t or \n 2: java TrippleDESTool CardPIN CardPAN PEK1");
			return;
		}
		
	}
}