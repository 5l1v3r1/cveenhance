package CveCollector;

/**
 * >> This programm splits a CVE XML Database backup/file into seperated smaller files, so the extraction can be managed/splited/modified better.<<
 * @author TU Darmstadt KOM, TU Darmstadt STG
 * @version 0.1
 */

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.Writer;

public class CveCollector {

	public static void main(String[] args) {
		openFile(Konfig.XmlFile);
	}
	public static void openFile(String openfile){    

		try{
			  String text="";
			  String name="";
			  // Open the file that is the first 
			  // command line parameter
			  FileInputStream fstream = new FileInputStream(openfile);
			  // Get the object of DataInputStream
			  DataInputStream in = new DataInputStream(fstream);
			  BufferedReader br = new BufferedReader(new InputStreamReader(in));
			  Writer fw;
			  Writer bw;
			  PrintWriter pw = null;
			  String strLine;
			  //Read File Line By Line
			  while ((strLine = br.readLine()) != null)   {
				  if(strLine.contains("<entry ")){
					  name=strLine.substring(strLine.indexOf("id")+4, strLine.indexOf("\"", strLine.indexOf("id")+4));
				  }
				  
				  text+=strLine+"\n";
				  if(strLine.contains("</entry>"))
			  		{
					  fw = new FileWriter( Konfig.CveFolder+name+".xml" );
					  bw = new BufferedWriter( fw );
					  pw = new PrintWriter( bw );
					  pw.print(text);
					  System.out.println(name);
					  text="";
					  name="";
					  pw.close();
			  		}
			  }
			   //Close the input stream
			  in.close();
	  		
			  // System.out.println(text);
			    }catch (Exception e){//Catch exception if any
			  System.err.println("Error: " + e.getMessage());
			  }
	}	
// Source: http://www.roseindia.net/java/beginners/java-read-file-line-by-line.shtml , 17.09.2013	
	
	
}
