package tud.cve.extractor;

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

import java.util.Vector;

/**
 * >> An object of this class represents an entity type <<
 * 
 * @author TU Darmstadt KOM, TU Darmstadt STG
 * @version 0.1
 */

public class LogicalUnit {

	private String[] possibleUnits = Config.lOGICAL_UNITS;
	private final String unitType;
	public String comment = "";

	public LogicalUnit(String newUnitType) {
		if (isValidType(newUnitType.trim())) {
			unitType = newUnitType;
		} else
			unitType = null;
	}

	/**
	 * Checks if a logical Unit type may be created
	 * 
	 * @param type
	 */
	public boolean isValidType(String type) {
		for (int i = 0; i < possibleUnits.length; i++) {
			if (type.equals(possibleUnits[i]))
				return true;
		}
		return false;
	}

	/**
	 * filters all snippet combination rules to the corresponding subset
	 * 
	 * @return corresponding subset of combination rules
	 */
	public Vector<String[]> getCorrespondingConditions() {
		String[][] conditions = Config.COMBINATION_CONDITIONS;
		Vector<String[]> resultvector = new Vector<String[]>();
		for (int i = 0; i < conditions.length; i++) {
			if (conditions[i][0].equalsIgnoreCase(type()))
				resultvector.add(conditions[i]);
		}
		return resultvector;
	}

	/**
	 * Checks if the logical type really exists
	 */
	public boolean isValid() {
		return (unitType != null);
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
