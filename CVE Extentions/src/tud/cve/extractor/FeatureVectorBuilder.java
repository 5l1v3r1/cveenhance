package tud.cve.extractor;

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


import java.util.HashMap;

/**
 * >> This class creates an empty snippet feature vector <<
 * @author TU Darmstadt KOM, TU Darmstadt STG
 * @version 0.1
 */

public class FeatureVectorBuilder {
	
	public static final HashMap<String, Boolean> defaultVector(){
		String[] featureArray = Config.SNIPPET_FEATURES;
		HashMap<String, Boolean> returnVector = new HashMap<String, Boolean>();
		for(String featureName: featureArray){
			returnVector.put(featureName, false);
		}
		
		return returnVector;
	}
	
	public FeatureVectorBuilder() {
		
	}

}
