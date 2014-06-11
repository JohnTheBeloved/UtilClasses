/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package cryptography;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CoderResult;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author johnthebeloved
 */
public class MyCharSetDecoder  extends CharsetDecoder{
    ByteBuffer byteBuffer ;
    CharBuffer charBuffer;
    
    public MyCharSetDecoder(byte[] byteArray){
        super(Charset.forName("UTF-8"),1.0f,1.0f);
        byteBuffer = ByteBuffer.wrap(byteArray);
        charBuffer = CharBuffer.allocate(200);
        
    }
    
    public static void main(String[] args) throws UnsupportedEncodingException {
        System.out.println("The charcters are"+new MyCharSetDecoder("John".getBytes("UTF-8")).getString()+"END");   
    }
    
    public String getString(){
        decodeLoop(byteBuffer, charBuffer);
        return charBuffer.toString();
    }
    
    @Override
    protected CoderResult decodeLoop(ByteBuffer in, CharBuffer out) {
        try {
            //reset();
            decode(in);
            CoderResult cdr = flush(out);
            System.out.println(cdr);
           
                charBuffer.put(out);
          
            return cdr;
        } catch (CharacterCodingException ex) {
            Logger.getLogger(MyCharSetDecoder.class.getName()).log(Level.SEVERE, null, ex);
       return null;
        }
       
    }
    
    
}
