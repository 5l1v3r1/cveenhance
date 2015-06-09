package tud.cve.evaluator;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;

import tud.cve.extractor.Config;
/**
 * Please make sure, that CVE extraction already took place!
 */

public class EvaluateAlgorithm {

	private static String annotatedFolder = Config.ANNOTATED_FOLDER;
	private static String unannotatedFolder = Config.UNANNOTATED_FOLDER;
	private static String analyseResults = Config.OUTPUT_FOLDER;
	
	public static void main(String[] args) {
		
		evaluatePath(unannotatedFolder);
	}
	
	protected static void evaluatePath(String path) {
		
	}
	
	
}
