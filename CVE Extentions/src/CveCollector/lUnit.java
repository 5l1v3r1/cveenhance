package CveCollector;

import java.util.Vector;

public class lUnit {
	
	private String[] possibleUnits=konfig.logicalUnits;
	private final String unitType;
	private boolean valid=false;

	public lUnit(String newUnitType) {
		if(isValidType(newUnitType.trim().toLowerCase())) {
			unitType=newUnitType;
			valid=true;
		}
		else unitType=null;
	}
	
	public boolean isValidType(String type){
		for(int i=0;i<possibleUnits.length;i++){
			if(type==possibleUnits[i]) return true;
		}
		return false;
	}
	
	public Vector<String[]> getCorrespondingConditions(){
		String[][] conditions = konfig.meltingConditions;
		Vector<String[]> resultvector = new Vector<String[]>();
		for (int i=0; i<conditions.length; i++){
			if(conditions[i][0].toLowerCase()==type().toLowerCase()) resultvector.add(conditions[i]);
		}
		return resultvector;
	}
	
	public boolean isValid(){ return (valid && unitType!=null);}
	
	public String type(){
		return unitType;
	}
	
	public boolean isType(String checkType){
		return checkType==type();
	}
	
	public String toString(){
		if(isValid()) return unitType;
		else return "";
	}

}
