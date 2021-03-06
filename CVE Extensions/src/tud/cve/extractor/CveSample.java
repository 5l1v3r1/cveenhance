package tud.cve.extractor;

/*
 * This work is licensed under the MIT License. 
 * The MIT License (MIT)

 * Copyright (c) 2015  Leonid Glanz (STG), Sebastian Schmidt (KOM), Sebastian Wollny (KOM), 
 * Ben Hermann (STG), Technische Universitšt Darmstadt

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
 * >> This programm generates a random subset of the whole CVE database created by CveCollector.java.<<
 * @author TU Darmstadt KOM, TU Darmstadt STG
 * @version 0.1
 */

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.ArrayList;

/**
 * >> This class creates a subset of the CVE item Folder by copying the desired number of subset files to the subset
 * folder. <<
 * 
 * @author TU Darmstadt KOM, TU Darmstadt STG
 * @version 0.1
 */

public class CveSample {

	private static ArrayList<String> filelist = new ArrayList<String>(); // filelist, where all files paths are saved
	private static String itemDir = Config.CVE_FOLDER; // directory, which contains the whole splitted CVE database
	private static String subsetDir = Config.CVE_SUBSET_FOLDER; // directory, which is used to copy a subset of the
																// database
	private static int desiredSamples = Config.DUMP_NUMBER; // number of subset elements

	public static void main(String[] args) {
		CveSample sp = new CveSample();
		sp.walk(itemDir); // searching for splitted CVE XML files
		System.out.println(filelist.size() + " CVE entries found!");

		// generating a random subset:
		int sampleCount = 0;
		int checklength = 0;
		do {
			for (; sampleCount < desiredSamples; sampleCount++) {
				String sFile = filelist.get(randomNr(filelist.size())); // A random file is copied into the subset
																		// folder (Dumpdir)
				try {
					Runtime rt = Runtime.getRuntime();
					System.out.println("copy \"" + sFile + "\" \"" + subsetDir + "\"");
					Process pr = rt.exec("cmd /c copy \"" + sFile + "\" \"" + subsetDir + "\""); // command line command
																									// to copy a file
					BufferedReader input = new BufferedReader(new InputStreamReader(pr.getInputStream()));
					String line = null;
					while ((line = input.readLine()) != null) {
						System.out.println(line);
					}

				} catch (Exception e) {
					System.out.println(e.toString());
					e.printStackTrace();
				}

			}
			File root = new File(subsetDir);
			File[] list = root.listFiles();
			if (list != null)
				checklength = list.length;
			if (sampleCount > checklength)
				sampleCount = checklength; // If samples are accidently double chosen
		} while (checklength < desiredSamples);
		System.out
				.println(sampleCount + " samples out of " + filelist.size() + " cve entries copied to sample folder!");
	}

	/**
	 * This method "walks" recursive through the current directory (path) and collects all analyzable files in the file
	 * list. (similar to the walk method of AnalyseCves.java)
	 * 
	 * @param path
	 *            path which should be analyzed and found files be saved in filelist
	 */
	public void walk(String path) {
		File root = new File(path);
		File[] list = root.listFiles();
		if (list != null)
			for (File f : list) {
				if (f.isDirectory()) {
					walk(f.getAbsolutePath());
					System.out.println("Dir:" + f.getAbsoluteFile());
				} else {
					String fileresult = f.getAbsoluteFile().toString();
					String parseName = fileresult.substring(fileresult.lastIndexOf("\\"));
					if (parseName.toLowerCase().contains(".xml")) {
						filelist.add(f.getAbsolutePath());
						System.out.println("File:" + f.getAbsoluteFile());
					} else
						System.out.println("No XML File:" + f.getAbsoluteFile());
				}
			}
	}

	/**
	 * Retruns a random int number between 1 and "upperLimit".
	 * 
	 * @param upperLimit
	 *            upper limit of ramdom number
	 * @return random int number between 1 and "upperLimit"
	 */
	public static int randomNr(int upperLimit) {
		int lowerLimit = 1;
		upperLimit++;
		return (int) (Math.random() * (upperLimit - lowerLimit) + lowerLimit);
	}

}
