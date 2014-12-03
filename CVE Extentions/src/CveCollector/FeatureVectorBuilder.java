package CveCollector;

import java.util.HashMap;

public class FeatureVectorBuilder {
	
	public static final HashMap<String, Boolean> defaultVector(){
		String[] featureArray = Konfig.SnippetFeatures;
		HashMap<String, Boolean> returnVector = new HashMap<String, Boolean>();
		for(String featureName: featureArray){
			returnVector.put(featureName, false);
		}
		
		return returnVector;
	}
	
	public FeatureVectorBuilder() {
		
	}

}
