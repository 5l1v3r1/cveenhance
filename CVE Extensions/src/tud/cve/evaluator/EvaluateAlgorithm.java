package tud.cve.evaluator;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.PrintWriter;
import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.Vector;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.plaf.basic.BasicInternalFrameTitlePane.RestoreAction;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;

import org.apache.commons.lang3.StringEscapeUtils;

import tud.cve.extractor.AnalyseCves;
import tud.cve.extractor.Config;
import tud.cve.extractor.CveItem;

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
 * Please make sure, that CVE extraction already took place!
 */

public class EvaluateAlgorithm {

	private static String annotatedFolder = Config.ANNOTATED_FOLDER;
	private static String analyseResults = Config.UNANNOTATED_FOLDER;
	// evaluation result vector: 0=correct start information
	// 1=correct end information
	// 2=correct fix information
	// 3=false neg start
	// 4=false neg end
	// 5=false neg fix
	// 6=false pos start
	// 7=false pos end
	// 8=false pos fix
	private static int[] evalResult = new int[9];

	public static void main(String[] args) {
		evalResult = new int[9];
		evaluatePath(analyseResults);
	}

	private static void evaluatePath(String path) {

		File root = new File(path);
		File[] list = root.listFiles();
		int anzFiles=0;
		boolean allFilesChecked=true;
		
		try{	
			if (list != null)
				for (File resultFile : list) {
					if (resultFile.isDirectory()) {
						evaluatePath(resultFile.getAbsolutePath());
						System.out.println("Dir:" + resultFile.getAbsoluteFile());
					} else {
						String fileName = resultFile.getName();
						if (fileName.length() > 8 && fileName.startsWith("CVE")) {
							String parseName = resultFile.getName();
							if (parseName.toLowerCase().endsWith(Config.DATA_TYPE.toLowerCase())) {
								File annotatedFile = findAnnotatedFile(resultFile);
								if (annotatedFile.exists()) {
									analyzeResults(resultFile, annotatedFile);
									anzFiles++;
									System.out.println(anzFiles+" Files evaluated. Precision:"+generalPrecision()+" Recall:"+generalRecall()+" F-Measure:"+generalFMeasure());
								}
								else {
									allFilesChecked=false;
									throw new Exception("File "+parseName+" does not exist in annotated Folder!");
								}
														
							} else
								System.out.println("No XML File:" + resultFile.getAbsoluteFile());
						}
					}
				}
		}
		catch (Exception e){
			e.printStackTrace();
		}
		System.out.println("evaluation results:\n\n");
		System.out.println("Precision Range-Start: "+roundScale(precision(0)));
		System.out.println("Recall Range-Start: "+roundScale(recall(0)));
		System.out.println("F-Measure Range-Start"+roundScale(fMeasure(0))+"\n");
		
		System.out.println("Precision Range-End: "+roundScale(precision(1)));
		System.out.println("Recall Range-End: "+roundScale(recall(1)));
		System.out.println("F-Measure Range-End"+roundScale(fMeasure(1))+"\n");
		
		System.out.println("Precision Range-Fix: "+roundScale(precision(2)));
		System.out.println("Recall Range-Fix: "+roundScale(recall(2)));
		System.out.println("F-Measure Range-Fix"+roundScale(fMeasure(2))+"\n");

		System.out.println("Overall Precision: "+roundScale(generalPrecision()));
		System.out.println("Overall Recall: "+roundScale(generalRecall()));
		System.out.println("Overall F-Measure"+roundScale(generalFMeasure())+"\n");

		
		System.out.println(Arrays.toString(evalResult));
	}

	public static void analyzeResults(File resultFile, File annotatedFile) {
		AnalyseCves extractor = new AnalyseCves();
		String resultXMLString = AnalyseCves.getOutputToXMLFile(extractor.extractItem(new CveItem(AnalyseCves.getInnerText(resultFile))));
		String annotatedXMLString = extractRangeXMLData(annotatedFile);
				
		Vector<String> firstTagsResultFile = extractTagContent(0, resultXMLString);
		Vector<String> firstTagsAnnotatedFile = extractTagContent(0, annotatedXMLString);
		checkResults(0, firstTagsResultFile, firstTagsAnnotatedFile);
		
		Vector<String> endTagsResultFile = extractTagContent(1, resultXMLString);
		Vector<String> endTagsAnnotatedFile = extractTagContent(1, annotatedXMLString);
		checkResults(1, endTagsResultFile, endTagsAnnotatedFile);
		
		Vector<String> fixedTagsResultFile = extractTagContent(2, resultXMLString);
		Vector<String> fixedTagsAnnotatedFile = extractTagContent(2, annotatedXMLString);
		checkResults(2, fixedTagsResultFile, fixedTagsAnnotatedFile);

	}
	
	/**
	 * 0=First-Information, 1=End-Information, 2=Fix-Information
	 * 
	 */
	private static Vector<String> extractTagContent(int informationType, String xmlCode){	
		String typeName="";
		if(informationType==0)typeName="start";
		if(informationType==1)typeName="end";
		if(informationType==2)typeName="fix";
		Vector<String> returnArray = tagSubstr(Config.XML_EXTENSION_TAG+":"+typeName, xmlCode);		
		return returnArray;
	}
	
	public static Vector<String> tagSubstr(String tagname, String xmlCode) {
		Vector<String> vec = new Vector<String>();
		String innerNoTagText;
		Matcher ma, mo;
		ma = Pattern.compile("<" + tagname + ">").matcher(xmlCode.toLowerCase());
		mo = Pattern.compile("</" + tagname + ">").matcher(xmlCode.toLowerCase());
		while (ma.find()) {
			if (mo.find(ma.end())) {
				innerNoTagText="";
				innerNoTagText = StringEscapeUtils.unescapeXml(xmlCode.substring(ma.start(), mo.end()));
				innerNoTagText = innerNoTagText.replaceAll("[\\t\\n\\f\\r]", "");
				vec.add(innerNoTagText);
			} else {
				System.out.println("FEHLER: Der Tag </" + tagname + "> konnte nicht gefunden werden!");
			}
		}
		return vec;
	}
	
	private static String extractRangeXMLData(File xmlFile){			
		StringBuilder data = new StringBuilder();
		boolean addToString = false;
				try {
					BufferedReader br = new BufferedReader(new FileReader(xmlFile));
					String line;
					while ((line = br.readLine()) != null) {
						if((addToString||line.contains("<"+Config.XML_EXTENSION_TAG+":ranges>"))&&(!line.contains("</"+Config.XML_EXTENSION_TAG+":ranges>"))){
							addToString=true;
							data.append(line);
							data.append("\n");
						}
						else addToString=false;
					}
					br.close();

				} catch (Exception e) {
					e.printStackTrace();
				}
				return data.toString();
	}

	private static File findAnnotatedFile(File resultFile){
		File returnFile = new File(annotatedFolder+resultFile.getName());
		return returnFile;
	}

	private static void checkResults(int informationType, Vector<String> resultsVector, Vector<String> annotationsVector) {
		String[] results = resultsVector.toArray(new String[resultsVector.size()]);
		String[] annotations = annotationsVector.toArray(new String[annotationsVector.size()]);
		boolean[] resultsMatched = new boolean[results.length];
		boolean[] annotationsMatched = new boolean[annotations.length];
		
		for(int i = 0; i<results.length; i++){
			
			for(int j = 0; j<annotations.length; j++){
				if(annotations[j].equals(results[i])&&!annotationsMatched[j]){
					resultsMatched[i]=true;
					annotationsMatched[j]=true;
					correctResult(informationType);
				}
			}
		}
		for(int k=0; k<resultsMatched.length;k++){
			if(!resultsMatched[k]) falsePositiveResult(informationType);
		}
			
		for(int l=0; l<annotationsMatched.length;l++){
			if(!annotationsMatched[l]) falseNegativeResult(informationType); 
		}

	}

	/**
	 * 0=First-Information, 1=End-Information, 2=Fix-Information
	 * 
	 */
	private static void falseNegativeResult(int informationType) {
		evalResult[informationType + 3] += 1;
	}

	private static void falsePositiveResult(int informationType) {
		evalResult[informationType + 6] += 1;
	}

	private static void correctResult(int informationType) {
		evalResult[informationType] += 1;
	}

	public static double precision(int informationType) {
		double precision = 0.0;
		precision = (double) evalResult[informationType]
				/ ((double) evalResult[informationType] + (double) evalResult[informationType + 6]);
		return precision;
	}

	public static double recall(int informationType) {
		double recall = 0.0;
		recall = (double) evalResult[informationType]
				/ ((double) evalResult[informationType] + (double) evalResult[informationType + 3]);
		return recall;
	}

	public static double fMeasure(int informationType) {
		return fMeasure(informationType, 1.0);
	}

	public static double fMeasure(int informationType, double beta) {
		double f = 0.0;
		f = (1.0 + (beta * beta))
				* (precision(informationType) * recall(informationType))
				/ ((beta * beta * precision(informationType)) + recall(informationType));
		return f;
	}

	public static double generalPrecision() {
		double precision = 0.0;
		precision = ((double) (evalResult[0] + evalResult[1] + evalResult[2]))
				/ ((double) (evalResult[0] + evalResult[1] + evalResult[2]) + (double) (double) (evalResult[6]
						+ evalResult[7] + evalResult[8]));
		return precision;
	}

	public static double generalRecall() {
		double recall = 0.0;
		recall = ((double) (evalResult[0] + evalResult[1] + evalResult[2]))
				/ ((double) (evalResult[0] + evalResult[1] + evalResult[2]) + (double) (evalResult[3]
						+ evalResult[4] + evalResult[5]));
		return recall;
	}

	public static double generalFMeasure() {
		return generalFMeasure(1.0);
	}

	public static double generalFMeasure(double beta) {
		double f = 0.0;
		f = (1.0 + (beta * beta)) * (generalPrecision() * generalRecall())
				/ ((beta * beta * generalPrecision()) + generalRecall());
		return f;
	}
	
	private static double roundScale( double d )
	  {
	    return Math.rint( d * 10000 ) / 10000.;
	  }

}
