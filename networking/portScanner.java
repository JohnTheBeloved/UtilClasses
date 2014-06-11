import java.net.*;
import java.io.*;
public class portScanner{
	public static void main(String [] args){
		String serverIP;
		boolean log = false;
	int minRange=0;int  maxRange=2000;
		try{
			 
				serverIP = args[0];
			
				minRange = Integer.valueOf(args[1]);
			
				maxRange = Integer.valueOf(args[2]);
			
				log = Boolean.valueOf(args[3]);

				System.out.println("Logging ...."+log);
			
		}catch(ArrayIndexOutOfBoundsException ex){
			System.out.println("Please Provide IP to scan...\n Usage: java portScanner serverIP minPortRange maxPoertRange log[true|false]");
			return;
		}

		Socket socket;
		SocketAddress socketAddress;
		int port = minRange -1;
		System.out.println("Scanning Server with IP..."+serverIP);
		while(port < maxRange)
		{
			try{
				socketAddress = new InetSocketAddress(serverIP,++port);
				socket = new Socket();
					if(log)System.out.print("PORT:"+ port);
				socket.connect(socketAddress);
				System.out.println("\n\nConnected to Port.................................. "+ port + "Succesfully\n\n");
				//socketAddress.finalize();
				//socket.finalize();
				socketAddress = null;
				socket = null;
			}catch(IOException ex){
				if(log)System.out.print("NO|");
			}
		}
	}
}