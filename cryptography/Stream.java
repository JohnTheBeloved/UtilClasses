
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Stream{
	
	public Stream() throws IOException{
            try {
                String word = "John Alade wants to really understand how this works";
                byte[] wordInByte = word.getBytes("UTF-8");
                DataInputStream dis = new DataInputStream(new ByteArrayInputStream(wordInByte));
               // DataOutputStream os = new DataOutputStream(null)
                for(int i = 0;i < wordInByte.length;i++)
                {
                    dis.read();
                }
            } catch (UnsupportedEncodingException ex) {
                Logger.getLogger(Stream.class.getName()).log(Level.SEVERE, null, ex);
            }
	}

	public static void main(String [] args){

	}
}