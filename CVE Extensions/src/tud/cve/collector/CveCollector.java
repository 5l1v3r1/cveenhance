package tud.cve.collector;

/*
 * This work is licensed under the MIT License. 
 * The MIT License (MIT)

 * Copyright (c) 2015  Leonid Glanz (STG), Sebastian Schmidt (KOM), Sebastian Wollny (KOM), 
 * Ben Hermann (STG), Technische Universität Darmstadt

 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:

 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
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

import tud.cve.extractor.Config;

/**
 * >> This class splits all CVE Database XMLs to single files and stores it in the CVE item folder <<
 * 
 * @author TU Darmstadt KOM, TU Darmstadt STG
 * @version 0.1
 */

public class CveCollector {

	public static void main(String[] args) {
		File dir = new File(Config.XML_FOLDER);
		File[] list = dir.listFiles();
		if (list != null)
			for (File file : list)
				if (file.getName().endsWith(Config.DATA_TYPE))
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
			DataInputStream dataInputStream = new DataInputStream(fileInputStream);
			BufferedReader br = new BufferedReader(new InputStreamReader(dataInputStream));
			String line;
			String entryContent = "";
			String fileName = "";
			while ((line = br.readLine()) != null) {
				if (line.contains("<entry ")) {
					fileName = line.substring(line.indexOf("id") + 4, line.indexOf("\"", line.indexOf("id") + 4));
				}
				if (!line.startsWith("<?xml") && !line.startsWith("<nvd")) {
					entryContent += line + "\n";
				}

				if (line.contains("</entry>")) {
					File folder = new File(Config.CVE_FOLDER);
					if (!folder.exists())
						folder.mkdirs();
					Writer fw = new FileWriter(Config.CVE_FOLDER + fileName + ".xml");
					Writer bw = new BufferedWriter(fw);
					PrintWriter pw = new PrintWriter(bw);
					pw.print(entryContent);
					System.out.println(fileName);
					entryContent = "";
					fileName = "";
					pw.close();
				}
			}
			br.close();
		} catch (Exception e) {
			System.err.println("File Read Error: " + e.getMessage());
		}
	}

}
