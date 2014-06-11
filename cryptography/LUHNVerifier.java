/**
*This class implements helps verify if a number obeys the LUHN Algorithm
*/
public class LUHNVerifier{
	
	/*
	*
	*/
	public boolean verifyPAN(long longPAN){
		String stringPAN = longPAN.toString();
		int checkDigit = Integer.parseInt(stringPAN.substring(stringPan.length() - 1, stringPan.length()));
		stringPAN = stringPAN.substring(0, stringPAN.length() - 1);
        
		//char[] fullPANChars =  realPAN.toCharArray();

		int luhnSum = 0;
		for(int i = 1; i < stringPAN.length(); i++){
			int currentNumber;
			luhnSum += i % 2 == 0  ? currentNumber : (currentNumber * 2);
		}
		return ((luhnSum +checkDigit)%10 == 0);
	}

	private static void main(String [] args){
		System.out.println("This PAN is valid?\t" + Long.parseLong(args[0]);
	}
}