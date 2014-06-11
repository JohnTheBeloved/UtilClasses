public class InvalidXCryptException extends Exception{
	String message;
	public InvalidXCryptException(String string){
		message = string + "\t is Invalid";
	}
	public String getMessage(){
		return message;
	}
}