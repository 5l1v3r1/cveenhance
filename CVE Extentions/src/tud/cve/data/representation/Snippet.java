package tud.cve.data.representation;

/*
 * ============ CREATIVE COMMONS LICENSE (CC BY 4.0) ============
 * This work is licensed under the Creative Commons Attribution 4.0 International License. 
 * To view a copy of this license, visit http://creativecommons.org/licenses/by/4.0/. 
 *  
 * authors: Technische Universitšt Darmstadt - Multimedia Communication Lab (KOM), Technische Universitšt Darmstadt - Software Technology Group (STG)
 * websites: http://www.kom.tu-darmstadt.de/, http://www.stg.tu-darmstadt.de/
 * contact: Leonid Glanz (STG), Sebastian Schmidt (KOM), Sebastian Wollny (KOM), Ben Hermann (STG)
 * name: CVE Version Information Extractor
 *
 */

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map.Entry;
import java.util.Vector;
import java.util.regex.Pattern;

import tud.cve.extractor.Config;
import tud.cve.extractor.FeatureVectorBuilder;
import tud.cve.extractor.LogicalUnit;

/**
 * This class should represent a part of a floating text e.g. a token / combined tokens. Furthermore a Snippet should represents a logical unit e.g. a
 * software name, a version number or a stopword.
 * 
 * @author TU Darmstadt KOM, TU Darmstadt STG
 * @version 0.1
 */

public class Snippet {

	// features:
	private static final HashMap<String, Boolean> defaultVector = FeatureVectorBuilder.defaultVector();

	private HashMap<String, Boolean> features;
	// handling vars:
	private String text; // floating text part
	private String lowerCaseText;
	private int length = 0;
	private int tokenValue = 1;
	private LogicalUnit logicalUnit = null;

	// connections to neighbor Snippets
	public Snippet next = null;
	public Snippet prev = null;

	public int getTokenValue() {
		return tokenValue;
	}

	/**
	 * Checks if the snippet is the last of a sentence or clause
	 */
	public boolean islogicalEnd() {
		try {
			return getFeatureValue("logicalend") || !hasNext();
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
	}

	public boolean islogicalStart() {
		try {
			return getFeatureValue("logicalstart");
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
	}

	public int length() {
		return length;
	}

	// Constructor:
	public Snippet(String innerText) {
		setText(innerText);
	}

	// Init:

	public void initialize() {
		features = new HashMap<String, Boolean>();
		for (Entry<String, Boolean> entry : defaultVector.entrySet()) {
			features.put(entry.getKey(), entry.getValue());
		}
		try {
			setFeature("comma", matchesLowerCase(".*,"));
			setFeature("possibleversion", matchesLowerCase(".*\\d.*"));
			setFeature("word", (text.length() >= 3));
			setFeature("bigletter", matchesExpression("[A-Z]+.*"));
			setFeature("versionext", keywordCheck(lowerCaseText, Config.VERION_KEYWORDS));
			setFeature("version", (matchesLowerCase("[\\d]+[\\p{Punct}\\w]*") && !(matchesLowerCase(""))));
			setFeature("os", keywordCheck(lowerCaseText, Config.OS_KEYWORDS));
			setFeature("osext", keywordCheck(lowerCaseText, Config.OS_EXTENSIONS));
			setFeature("stopword", keywordCheck(lowerCaseText, Config.STOP_WORDS));
			setFeature("concatword", keywordCheck(lowerCaseText, Config.CONCAT_WORDS));
			setFeature("comparingword", keywordCheck(lowerCaseText, Config.COMPARING_WORDS));
			setFeature("seperator", keywordCheck(lowerCaseText, Config.SEPERATING_WORDS));
			setFeature("namestart", keywordCheck(lowerCaseText, Config.SOFTWARE_NAME_START_WORDS));
			setFeature("versionstart", keywordCheck(lowerCaseText, Config.SOFTWARE_NAME_STOP_WORDS));
			setFeature("cuebefore", keywordCheck(lowerCaseText, Config.SOFTWARE_NAME_STOP_WORDS));
			setFeature("cueearlier", keywordCheck(lowerCaseText, Config.SOFTWARE_VERSION_ENDS));
			setFeature("cuebegin", keywordCheck(lowerCaseText, Config.SOFTWARE_BEGIN_IND));
			setFeature("cuebetween", keywordCheck(lowerCaseText, Config.SOFTWARE_RANGE_IND));

			if ((getFeatureValue("comma") || matchesLowerCase(".+[" + createRegexpFromStrings(Config.SEPERATING_CHARS, "") + "]"))) {
				setFeature("logicalend", true);
				text = text.substring(0, text.length() - 1);
			}
			if (prev != null && matchesLowerCase("[" + createRegexpFromStrings(Config.SEPERATING_CHARS) + "]"))
				prev.setFeature("logicalend", true);

			if (hasPrev())
				setFeature("logicalstart", prev.islogicalEnd());
			else
				setFeature("logicalstart", true);

			if (getFeatureValue("version"))
				setLogicalUnit("version");
			else if (getFeatureValue("bigletter") && !getFeatureValue("stopword"))
				setLogicalUnit("softwarename");
			else if (getFeatureValue("versionext"))
				setLogicalUnit("versionExtention");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	// Methods:

	private void setFeature(String featureName, boolean newValue) throws Exception {
		features.put(featureName, newValue);
		if (features.size() != defaultVector.size())
			throw new Exception("Feature \"" + featureName + "\" is not defined in konfig!");
	}

	public String createRegexpFromStrings(String[] keywords, String seperator) {
		String regexp = "";
		if (keywords.length >= 1)
			regexp += Pattern.quote(keywords[0]);
		for (int i = 1; i < keywords.length; i++) {
			regexp += Pattern.quote(seperator + keywords[i]);
		}
		return regexp;
	}

	public String createRegexpFromStrings(String[] keywords) {
		return createRegexpFromStrings(keywords, " | ");
	}

	/**
	 * Checks, if the last character of the snippet content matches with the input character
	 */
	public boolean endsWith(char checkChar) {
		return lowerCaseText.endsWith(""+checkChar);
	}

	/**
	 * Checks, if a regular expression matches to the snippet content (case sensitve)
	 */
	private boolean matchesLowerCase(String regex) {
		// lower case regex check
		return lowerCaseText.matches(regex);
	}

	/**
	 * Checks, if a regular expression matches to the snippet content (case sensitve)
	 */
	private boolean matchesExpression(String regex) {
		// regex check
		return text.matches(regex);
	}

	/**
	 * Checks, if the content of the Snippet matches with an entry of a keyword list
	 */
	private boolean keywordCheck(String checkword, HashSet<String> keywordList) {
		// checks weather a Snippet matches a keyword, listed in keywordList
		checkword = checkword.replaceAll("\\p{Punct}", "");
		return keywordList.contains(checkword);
	}

	/**
	 * combines the Snippet with the next Snippet
	 */
	public void mergeWithNextSnippet() {
		if (hasNext()) {

			HashMap<String, Boolean> mergeFeatures = next.features;
			for (String featureName : features.keySet()) {
				features.put(featureName, features.get(featureName) || mergeFeatures.get(featureName));
			}

			tokenValue++;

			setText(text + Config.SEPERATOR + next.getText());
			Snippet delSnip = next;

			next = next.next;
			if (next != null)
				next.prev = this;
			delSnip.prev = null;
			delSnip.next = null;

		}

	}

	/**
	 * @return true, if the snippet has a next snippet in the summary
	 */
	public boolean hasNext() {
		return (next != null);
	}

	/**
	 * @return true, if the snippet has a previous snippet in the summary
	 */
	public boolean hasPrev() {
		return (prev != null);
	}

	/**
	 * Sets a logical unit
	 */
	public void setLogicalUnit(String newUnit) {
		logicalUnit = new LogicalUnit(newUnit);

	}

	/**
	 * Sets a new logical unit
	 * 
	 * @param newUnit
	 */
	public void setLogicalUnit(LogicalUnit newUnit) {
		logicalUnit = newUnit;
	}

	/**
	 * @return The logical type of the Snippet
	 */
	public String logicalUnit() {
		if (logicalUnit == null || !logicalUnit.isValid())
			return null;
		else
			return logicalUnit.type();
	}

	/**
	 * Checks, if the logical unit name of the Snippet matches to imput String
	 * 
	 * @param type
	 *            Name of a logical type
	 * @return true, if the name of the set logical unit of the snippet machtes to the input string
	 */
	public boolean isLogicalType(String type) {
		if (logicalUnit == null || !logicalUnit.isValid())
			return false;
		return logicalUnit.type().equals(type);
	}

	/**
	 * @return If a logical type is already set in this Snippet
	 */
	public boolean hasLogicalUnit() {
		return logicalUnit() != null;
	}

	public void setLogicalUnitComment(String unitComment) {
		if (hasLogicalUnit())
			logicalUnit.comment = unitComment;
	}

	public String logicalUnitComment() {
		return logicalUnit.comment;
	}

	/**
	 * @return the part of the floating text
	 */
	public String getText() {
		return text;
	}

	/**
	 * @return the end of the floating text subset
	 */
	public void setText(String newText) {
		text = newText.trim();
		length = text.length();
		lowerCaseText = text.toLowerCase();
	}

	/**
	 * toString method for simple output in messages
	 */
	public String toString() {
		return getText();
	}

	public void combine() {

		int combinationLength = combinationLen();
		for (int i = 0; i < combinationLength; i++)
			mergeWithNextSnippet();
	}

	/**
	 * Checks weather a Snippet matches to a condition. This is needed for checking a combination rule.
	 * 
	 * @param requestCondition
	 *            Check-Condition Example: !possibleVersion;/os/osext;
	 * @return true if condition matches
	 */
	public boolean condition(String requestCondition) throws Exception {
		String[] conditions = requestCondition.split(";");
		if (conditions.length == 0)
			return false;
		for (String condition : conditions) {
			switch (condition.charAt(0)) {
			case '!': {
				if (!getFeatureValue(condition.substring(1)))
					return false;
			}
				break;
			case '-': {
				if (getFeatureValue(condition.substring(1)))
					return false;
			}
				break;
			case '/': {
				if (!hasSettedFeatures(condition.split("/")))
					return false;
			}
				break;
			default:
				if (logicalUnit == null)
					return false;
				else if (Config.isValidType(condition)) {
					if (!logicalUnit.isType(condition))
						return false;
				} else
					throw new Exception("Snippet condition: \"" + requestCondition + "\" NOT VALID!");

			}

		}
		return true;
	}

	public boolean hasSettedFeatures(String[] orConditions) throws Exception {
		boolean returnvalue = false;
		for (String orCondition : orConditions) {
			if (getFeatureValue(orCondition)) {
				returnvalue = true;
				break;
			}
		}
		return returnvalue;
	}

	/**
	 * @return The number of tokens in the Snippet
	 */
	public int value() {
		return tokenValue;
	}

	/**
	 * 
	 * @param featureName
	 *            Feature name (have to be mentioned in Config)
	 * @return Value of the desired feature
	 */
	private boolean getFeatureValue(String featureName) throws Exception {
		if (!features.containsKey(featureName)) {
			throw new Exception("Snippet feature value can not be determined: fature name\"" + featureName + "\" NOT VALID");
		}
		return features.get(featureName);
	}

	/**
	 * @return Maximum number of combinations, which are possible by the defined combination rules
	 */
	private int combinationLen() {
		if (logicalUnit == null)
			return 0;

		Vector<String[]> correspondingConditions = logicalUnit.getCorrespondingConditions();
		int combinationLen = -1;
		Snippet curSnip = this;
		while (!curSnip.islogicalEnd() && correspondingConditions.size() != 0) {
			List<String[]> removeList = new ArrayList<String[]>();
			for (String[] condition : correspondingConditions) {
				try {
					if (condition.length <= combinationLen + 1 || !curSnip.condition(condition[combinationLen + 1])) {
						removeList.add(condition);
					}
				} catch (Exception e) {
					removeList.add(condition);
					e.printStackTrace();
				}
			}
			correspondingConditions.removeAll(removeList);
			if (correspondingConditions.size() != 0) {
				combinationLen++;
			} else
				break;
			curSnip = curSnip.next;
		}
		return combinationLen;
	}

}
