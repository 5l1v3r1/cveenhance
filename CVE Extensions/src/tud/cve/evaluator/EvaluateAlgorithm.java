package tud.cve.evaluator;

import java.io.File;
import tud.cve.extractor.Config;
/**
 * Please make sure, that CVE extraction already took place!
 */

public class EvaluateAlgorithm {

	private static String annotatedFolder = Config.ANNOTATED_FOLDER;
	private static String analyseResults = Config.OUTPUT_FOLDER;
	// evaluation result vector: 	0=correct start information
	//								1=correct end information
	//								2=correct fix information
	//								3=false neg start
	//								4=false neg end
	//								5=false neg fix
	//								6=false pos start
	//								7=false pos end
	//								8=false pos fix
	private static int[] evalResult=new int[9];
	
	public static void main(String[] args) {
		evalResult=new int[9];
		evaluatePath(analyseResults);
	}
	
	private static void evaluatePath(String path) {

		File root = new File(path);
		File[] list = root.listFiles();
		int anzFiles=0;
		
		if (list != null)
				for (File f : list) {
					if (f.isDirectory()) {
						evaluatePath(f.getAbsolutePath());
						System.out.println("Dir:" + f.getAbsoluteFile());
					} else {
						String fileName = f.getName();
						if (fileName.length() > 8 && fileName.startsWith("CVE")) {
							String parseName = f.getName();
							if (parseName.toLowerCase().endsWith(Config.DATA_TYPE.toLowerCase())) {
								
								
							} else
								System.out.println("No XML File:" + f.getAbsoluteFile());
						}
					}
				}

	}
	
	/**
	 * 0=First-Information, 1=End-Information, 2=Fix-Information
	 * 
	 */
	private void falseNegativeResult(int informationType){
		evalResult[informationType+3]+=1;
	}
	
	private void falsePositiveResult(int informationType){
		evalResult[informationType+6]+=1;
	}
	
	private void correctResult(int informationType){
		evalResult[informationType]+=1;		
	}
	
	public double precision(int informationType){
		double precision=0.0;
		precision=(double)evalResult[informationType]/((double)evalResult[informationType]+(double)evalResult[informationType+6]);   
		return precision;
	}
	
	public double recall(int informationType){
		double recall=0.0;
		recall=(double)evalResult[informationType]/((double)evalResult[informationType]+(double)evalResult[informationType+3]);
		return recall;
	}
	
	public double fMeasure(int informationType){
		return fMeasure(informationType, 1.0);
	}
	
	public double fMeasure(int informationType, double beta){
		double f=0.0;
		f=(1.0+(beta*beta))*(precision(informationType)*recall(informationType))/((beta*beta*precision(informationType))+recall(informationType));
		return f;
	}
	
	public double generalPrecision(){
		double precision=0.0;
		precision =((double)(evalResult[0]+evalResult[1]+evalResult[2]))/((double)(evalResult[0]+evalResult[1]+evalResult[2])+(double)(double)(evalResult[6]+evalResult[7]+evalResult[8]));
		return precision;
	}
	
	public double generalRecall(){
		double recall=0.0;
		recall=((double)(evalResult[0]+evalResult[1]+evalResult[2]))/((double)(evalResult[0]+evalResult[1]+evalResult[2])+(double)(evalResult[3]+evalResult[4]+evalResult[5]));
		return recall;
	}
	
	public double generalFMeasure(){
		return generalFMeasure(1.0);
	}
	
	public double generalFMeasure(double beta){
		double f=0.0;
		f=(1.0+(beta*beta))*(generalPrecision()*generalRecall())/((beta*beta*generalPrecision())+generalRecall());
		return f;
	}
	
}
