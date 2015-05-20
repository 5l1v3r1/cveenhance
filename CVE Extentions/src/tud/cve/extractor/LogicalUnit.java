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

import java.util.Vector;

/**
 * >> An object of this class represents an entity type <<
 * 
 * @author TU Darmstadt KOM, TU Darmstadt STG
 * @version 0.1
 */

public class LogicalUnit {

	private final String unitType;
	private boolean valid = false;
	public String comment = "";

	public LogicalUnit(String newUnitType) {
		if (Config.isValidType(newUnitType.trim().toLowerCase())) {
			unitType = newUnitType;
			valid = true;
		} else
			unitType = null;
	}

	/**
	 * filters all snippet combination rules to the corresponding subset
	 * 
	 * @return corresponding subset of combination rules
	 */
	public Vector<String[]> getCorrespondingConditions() {
		return Config.getConditionsByType(type());
	}

	

	/**
	 * Checks if the logical type really exists
	 */
	public boolean isValid() {
		return (valid && unitType != null);
	}

	/**
	 * @return logical type value
	 */
	public String type() {
		return unitType;
	}

	/**
	 * @return If a logical type matches
	 */
	public boolean isType(String checkType) {
		return checkType.equals(type());
	}

	public String toString() {
		if (isValid())
			return unitType;
		else
			return "";
	}

}
