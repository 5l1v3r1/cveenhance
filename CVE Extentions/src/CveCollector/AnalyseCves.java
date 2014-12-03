package CveCollector;
/**
 * >> This Java program analyzes a folder, which contains several separated XML files extracted of the NVD. <<
 * I/O variables are declared in konfig.java
 * @author TU Darmstadt KOM, TU Darmstadt STG
 * @version 0.1
 */
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.Writer;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Vector;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AnalyseCves {
	
	private static Vector<String> filelist = new Vector<String>(); 		// list of file directories
	private static Vector<CveItem> itemList = new Vector<CveItem>(); 	// list of CVE items (abstract representation of an CVE entry)
	private static String DumpDir = konfig.CveDump; 					// directory, which contains CVE XML files FOR CODE TESTING (recommendation: <= 1000 files)
	private static String CveFolder = konfig.CveFolder; 				// directory, which contains all CVE XML files for information extraction
	private static String Datatype = konfig.Datatype; 					// data type of CVE XML files 
	private static String CvePrint = konfig.CvePrint;					// file which should contain the analysis results
	private static boolean Testmode = konfig.Testmode; 					// switches the test mode ON/OFF
	private static int MessageTime = konfig.MessageTime;				// default time for displaying a message
	private int anzFiles=0;	
	
	
	public static void main(String[] args) {
		AnalyseCves ana = new AnalyseCves();		
		String analyseDir = "";						// directory of containing CVE XML files for current analysis 
		if(Testmode) analyseDir = DumpDir;			// checks if test mode is active and sets the current directory 
		else analyseDir = CveFolder;
		
		System.out.println("\nSelected Folder: "+System.getProperty("user.dir")+"\\"+analyseDir+"\n");
		ana.walk(analyseDir);						// analyzes the structure of the current folder and adds all XML files to the file list
		System.out.println("\n"+filelist.size()+" analyzable XML files found in "+analyseDir+"\n"); 	// message of XML file number
		ana.stopfor();								// time of result presentation; default by konfig
		ana.analyse();								// information extraction of all files in the file list		
	}
	
	
	/**
	 * This method "walks" recursive through the current directory (path) and collects all analyzable files in the file list.
	 * @param path path which should be analyzed and found files be saved in filelist
	 */
	public void walk( String path ) {
        File root = new File( path );
        File[] list = root.listFiles();

        for ( File f : list ) {										// For every file of folder in a directory:
            if ( f.isDirectory() ) {								// Check if it's a dir or file.
                walk( f.getAbsolutePath() );						// If it's a dir: recursively call the walk method
                System.out.println( "Dir:" + f.getAbsoluteFile() ); // and print the result.
            }
            else {																		// If it's a file:
            	anzFiles++;																
            	String fileresult = f.getAbsoluteFile().toString();						// Check if it has the right data type (only by filename).
            	String parseName = fileresult.substring(fileresult.lastIndexOf("\\"));
            	if(parseName.toLowerCase().contains(Datatype)){							// If it has the right data type:
            		filelist.add(f.getAbsolutePath());  								// Add the absolute path to the filelist
					String line="";
					String innerText="";
            		FileInputStream fstream;											// and create a CVE item by reading the file.
					try {
						fstream = new FileInputStream(f.getAbsolutePath());
						DataInputStream in = new DataInputStream(fstream);
						BufferedReader br = new BufferedReader(new InputStreamReader(in));			       
						while((line=br.readLine()) != null) {
							innerText+=line;
						}
						
					} catch (Exception e) {
						e.printStackTrace();
					}
					CveItem curItem = new CveItem(innerText);							
            		itemList.add(curItem);												// Finally add the created CVE item to the item list.
            		System.out.println( "File:" + f.getAbsoluteFile() );
            		
            	}
            	else System.out.println( "No XML File:" + f.getAbsoluteFile() ); 		// Message, if a file does not match to the required data type.
            }
        }
    }
	
	
	/**
	 * The real information extraction part of the program. It analyzes all found files and saves the results in a text file.
	 * 
	 */
	private void analyse(){
		int resultCouter=0;							// counts the results
		int successful_item_counter=0;				// counts successful results
		int validData=0;							// counts valid files
		Iterator<CveItem> it = itemList.iterator();	// item iterator
		CveItem item = it.next();					// first CVE item
		Writer fw;								
		Writer bw;									// Writer for result text file:
		PrintWriter pw = null;
		
		try {
			fw = new FileWriter(CvePrint);

		bw = new BufferedWriter( fw );
		pw = new PrintWriter( bw );
		int save_Counter=0;							// buffer for current result number
		for(;it.hasNext();item=it.next()){					// for every CVE item:
			System.out.println(item.getCVEID()+":");
			String [] Versions=item.getFixedVersion();		// extraction of fixed versions
			String [] Software=item.getSoftware();			// allocation of Software
			save_Counter=0;
			for(int i=0;i<Versions.length; i++){			// displaying an saving of results
				System.out.println(Software[i]+" Fixed Version:"+Versions[i]);
				String concatVersion=Versions[i].trim();
				if(Versions[i].indexOf(" ")!=-1){
					concatVersion=Versions[i].replace(" ", ":");
				}
				else{
					Matcher mo;
					mo=Pattern.compile("\\p{Alpha}\\p{Alpha}+").matcher(Versions[i]);
					if(mo.find() && mo.start()!=0){
						concatVersion=Versions[i].substring(0, mo.start())+":"+Versions[i].substring(mo.start());
					}
				}				
				pw.println(item.getCVEID()+"; "+Software[i]+"; "+concatVersion);
				save_Counter++;
				if(Software[i]!="Software not allocatable!") validData++;
			}
			if(save_Counter>0) successful_item_counter++;
			resultCouter+=save_Counter;

		}
		 pw.close();		// extraction process completed
		 System.out.println("\n\nIn "+successful_item_counter+" von "+itemList.size()+" CVE Einträgen wurden "+ resultCouter+" gefixte Versionen (davon "+validData+" valide und "+(resultCouter-validData)+" unvalide Datensätze) gefunden!");
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	
	/*
	 * Sets a timeout for displaying a message. 
	 */
	private void stopfor(int milliseconds){
		try {
		    Thread.sleep(milliseconds);
		} catch(InterruptedException ex) {
		    Thread.currentThread().interrupt();
		}
	}
	
	private void stopfor(){
		int milliseconds = MessageTime;
		stopfor(milliseconds);
	}

}
