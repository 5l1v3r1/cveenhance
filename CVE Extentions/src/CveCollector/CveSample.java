package CveCollector;

/**
 * >> This programm generates a random subset of the whole CVE database created by CveCollector.java.<<
 * @author TU Darmstadt KOM, TU Darmstadt STG
 * @version 0.1
 */

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.ArrayList;

public class CveSample {

	private static ArrayList<String> filelist = new ArrayList<String>(); 	// filelist, where all files paths are saved
	private static String SourceDir = Konfig.CveFolder;	   					// directory, which contains the whole splitted CVE database
	private static String DumpDir = Konfig.CveDump; 						// directory, which is used to copy a subset of the database
	private static int anzStichprobe=Konfig.DumpNumber; 					// number of subset elements
	private int anzFiles=0;								   					// number of found CVE entrys
	
	public static void main(String[] args) {
		CveSample sp = new CveSample();
		  sp.walk(SourceDir);		  									// searching for splitted CVE XML files 
		  System.out.println( filelist.size()+" Dateien gefunden!");
		  
		  																// generating a random subset:
		  int gezogeneFiles=0;
		  int checklength=0;
		  do{
			  for(;gezogeneFiles<anzStichprobe;gezogeneFiles++){
			  	String sFile=filelist.get(randomNr(filelist.size())); 	// A random file is copied into the subset folder (Dumpdir)
			  		try {
			  			Runtime rt = Runtime.getRuntime();
			  			System.out.println("copy \""+sFile+"\" \""+DumpDir+"\"");
			  			Process pr = rt.exec("cmd /c copy \""+sFile+"\" \""+DumpDir+"\""); 	// command line command to copy a file
			  			BufferedReader input = new BufferedReader(new InputStreamReader(pr.getInputStream()));
			  			String line=null;
			  			while((line=input.readLine()) != null) {
			  				System.out.println(line);
			  			}

			  		} catch(Exception e) {
			  			System.out.println(e.toString());
			  			e.printStackTrace();
			  		}
		 		  
		  		}
			  File root = new File(DumpDir);
			  checklength = root.listFiles().length;
			  if(gezogeneFiles > checklength) gezogeneFiles=checklength;
		  }
		  while(checklength<anzStichprobe); 												// Task : Repeat until the required size of the subset is reached 
	      
		  
		  System.out.println( "Zusammenstellen beendet. Es wurden "+gezogeneFiles+" Stichproben aus "+filelist.size()+" gezogen!");
	}
	
	
	/**
	 * This method "walks" recursive through the current directory (path) and collects all analyzable files in the file list. (similar to the walk method of AnalyseCves.java)
	 * @param path path which should be analyzed and found files be saved in filelist
	 */
	public void walk( String path ) {
        File root = new File( path );
        File[] list = root.listFiles();
        

        for ( File f : list ) { 										// For every file of folder in a directory:
            if ( f.isDirectory() ) {									// Check if it's a dir or file.
                walk( f.getAbsolutePath() );							// If it's a dir: recursively call the walk method
                System.out.println( "Dir:" + f.getAbsoluteFile() );		// and print the result.
            }
            else {																		// If it's a file:
            	anzFiles++;
            	String fileresult = f.getAbsoluteFile().toString();						// Check if it has the right data type (only by filename).
            	String parseName = fileresult.substring(fileresult.lastIndexOf("\\"));
            	if(parseName.toLowerCase().contains(".xml")){							// If it has the right data type:
            		filelist.add(f.getAbsolutePath());         							// Add the absolute path to the filelist and print the result
            		System.out.println( "File:" + f.getAbsoluteFile() );
            	}
            	else System.out.println( "No XML File:" + f.getAbsoluteFile() ); // gefundenes File ist kein PDF-Dokument
            }
        }
    }
	
	/**
	 * Retruns a random int number between 1 and "oben".
	 * @param oben upper limit of ramdom number
	 * @return random int number between 1 and "oben"
	 */
	public static int randomNr(int oben) {
		int unten = 1;
		oben++;
		return (int) (Math.random() * (oben - unten) + unten);
	}


}
