package cveextractor;

/*
 * ============ CREATIVE COMMONS LICENSE (CC BY 4.0) ============
 * This work is licensed under the Creative Commons Attribution 4.0 International License. 
 * To view a copy of this license, visit http://creativecommons.org/licenses/by/4.0/. 
 *  
 * authors: Technische Universität Darmstadt - Multimedia Communication Lab (KOM), Technische Universität Darmstadt - Software Technology Group (STG)
 * websites: http://www.kom.tu-darmstadt.de/, http://www.stg.tu-darmstadt.de/
 * contact: Leonid Glanz (STG), Sebastian Schmidt (KOM), Sebastian Wollny (KOM), Ben Hermann (STG)
 * name: CVE Version Information Extractor
 *
 */

/**
 * >> This programm splits a CVE XML Database backup/file into seperated smaller files, so the extraction can be managed/splited/modified better.<<
 * @author TU Darmstadt KOM, TU Darmstadt STG
 * @version 0.1
 */

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.Writer;

/**
 * >> This class splits all CVE Database XMLs to single files and stores it in
 * the CVE item folder <<
 * 
 * @author TU Darmstadt KOM, TU Darmstadt STG
 * @version 0.1
 */

public class CveCollector {

	public static void main(String[] args) {
		File dir = new File(Config.XmlFolder);
		for (File file : dir.listFiles())
			if (file.getName().endsWith(Config.Datatype))
				splitCVExml(file.getAbsolutePath());
	}

	/**
	 * splits a CVE database XML to seperated CVE entry files
	 * 
	 * @param filePath
	 *            path to CVE database XML
	 */
	public static void splitCVExml(String filePath) {

		try {
			FileInputStream fileInputStream = new FileInputStream(filePath);
			DataInputStream dataInputStream = new DataInputStream(
					fileInputStream);
			BufferedReader br = new BufferedReader(new InputStreamReader(
					dataInputStream));
			Writer fw;
			Writer bw;
			PrintWriter pw = null;
			String line;
			String entryContent = "";
			String fileName = "";
			while ((line = br.readLine()) != null) {
				if (line.contains("<entry ")) {
					fileName = line.substring(line.indexOf("id") + 4,
							line.indexOf("\"", line.indexOf("id") + 4));
				}
				if (!line.startsWith("<?xml") && !line.startsWith("<nvd")) {
					entryContent += line + "\n";
				}

				if (line.contains("</entry>")) {
					File folder = new File(Config.CveFolder);
					if (!folder.exists())
						folder.mkdirs();
					fw = new FileWriter(Config.CveFolder + fileName + ".xml");
					bw = new BufferedWriter(fw);
					pw = new PrintWriter(bw);
					pw.print(entryContent);
					System.out.println(fileName);
					entryContent = "";
					fileName = "";
					pw.close();
				}
			}
			dataInputStream.close();
		} catch (Exception e) {
			System.err.println("File Read Error: " + e.getMessage());
		}
	}

}
