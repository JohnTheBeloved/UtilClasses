import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
public class DigestMessage{
	public String generateHash256Value(String key, String msg) { 
	       MessageDigest m = null; 
	       String hashText = null; 
	       byte[] actualKeyBytes = ConvertUtils.hexToBytes(key); 
	 
	       try { 
	           m = MessageDigest.getInstance("SHA-256"); 
	           m.update(actualKeyBytes, 0, actualKeyBytes.length); 
	           try { 
	               m.update(msg.getBytes("UTF-8"), 0, msg.length()); 
	           } catch (UnsupportedEncodingException ex) { 
	               ex.printStackTrace(System.out); 
	           } 
	           hashText = new BigInteger(1, m.digest()).toString(16); 
	       } catch (NoSuchAlgorithmException ex) { 
	           ex.printStackTrace(System.out); 
	       } 
	 
	       if (hashText.length() < 64) { 
	           int numberOfZeroes = 64 - hashText.length(); 
	           String zeroes = ""; 
	 
	           for (int i = 0; i < numberOfZeroes; i++) 
	               zeroes = zeroes + "0"; 
	 
	           hashText = zeroes + hashText; 
	 
	           System.out.println("Utility :: generateHash256Value :: HashValue with zeroes: " + hashText); 
	       } 
	 
	       return hashText; 
	 
	}

	/*
	*Usage 
	*/
	public static void main(String [] args){
		/*
		*
		*/
		String key, message = "";
		try{
			key = args[0];
			message = args[1];
		}catch(ArrayIndexOutOfBoundsException ex){
			System.out.println("Usage: \n1. java DigestMessage keyInHEX dataToEncrypt");
			return;
		}
		DigestMessage digestMessage = new DigestMessage();
		
		String digestedMessage = digestMessage.generateHash256Value(key,message);
		System.out.println("The Digested Message is "+digestedMessage);
	}
}