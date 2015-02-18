package tud.cve.data.representation;

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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map.Entry;
import java.util.Vector;
import java.util.regex.Pattern;

import tud.cve.extractor.Config;
import tud.cve.extractor.FeatureVectorBuilder;
import tud.cve.extractor.LogicalUnit;

/**
 * This class should represent a part of a floating text e.g. a Token / combined
 * Tokens. Furthermore a Snippet should represents a logical unit e.g. a
 * software name, a version number or a stopword.
 * 
 * @author TU Darmstadt KOM, TU Darmstadt STG
 * @version 0.1
 */

public class Snippet {

	// features:
	private static final HashMap<String, Boolean> defaultVector = FeatureVectorBuilder
			.defaultVector();

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
			setFeature(
					"version",
					keywordCheck(lowerCaseText, Config.VERION_KEYWORDS)
							|| (matchesLowerCase("[\\d]+[\\p{Punct}\\w]*") && !(matchesLowerCase(""))));
			setFeature("os", keywordCheck(lowerCaseText, Config.OS_KEYWORDS));
			setFeature("osext",
					keywordCheck(lowerCaseText, Config.OS_EXTENSIONS));
			setFeature("stopword",
					keywordCheck(lowerCaseText, Config.STOP_WORDS));
			setFeature("concatword",
					keywordCheck(lowerCaseText, Config.CONCAT_WORDS));
			setFeature("comparingword",
					keywordCheck(lowerCaseText, Config.COMPARING_WORDS));
			setFeature("seperator",
					keywordCheck(lowerCaseText, Config.SEPERATING_WORDS));
			setFeature(
					"namestart",
					keywordCheck(lowerCaseText,
							Config.SOFTWARE_NAME_START_WORDS));
			setFeature(
					"versionstart",
					keywordCheck(lowerCaseText, Config.SOFTWARE_NAME_STOP_WORDS));
			setFeature(
					"cuebefore",
					keywordCheck(lowerCaseText, Config.SOFTWARE_NAME_STOP_WORDS));
			setFeature("cueearlier",
					keywordCheck(lowerCaseText, Config.SOFTWARE_VERSION_ENDS));
			setFeature("cuebegin",
					keywordCheck(lowerCaseText, Config.SOFTWARE_BEGIN_IND));
			setFeature("cuebetween",
					keywordCheck(lowerCaseText, Config.SOFTWARE_RANGE_IND));

			if ((getFeatureValue("comma") || matchesLowerCase(".+["
					+ createRegexpFromStrings(Config.SEPERATING_CHARS, "")
					+ "]"))) {
				setFeature("logicalend", true);
				text = text.substring(0, text.length() - 1);
			}
			if (prev != null
					&& matchesLowerCase("["
							+ createRegexpFromStrings(Config.SEPERATING_CHARS)
							+ "]"))
				prev.setFeature("logicalend", true);

			if (hasPrev() == false)
				setFeature("logicalstart", true);
			else {
				if (prev.islogicalEnd())
					setFeature("logicalstart", true);
				else
					setFeature("logicalstart", false);
			}

			if (getFeatureValue("version"))
				setLogicalUnit("version");
			else if (getFeatureValue("bigletter"))
				setLogicalUnit("softwarename");

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	// Methods:

	private void setFeature(String featureName, boolean newValue)
			throws Exception {
		features.put(featureName, newValue);
		if (features.size() != defaultVector.size())
			throw new Exception("Feature \"" + featureName
					+ "\" is not defined in konfig!");
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

	public boolean endsWith(char checkChar) {
		char lastChar = lowerCaseText.charAt(lowerCaseText.length());
		if (checkChar == lastChar)
			return true;
		return false;
	}

	private boolean matchesLowerCase(String regex) {
		// lower case regex check
		return lowerCaseText.matches(regex);
	}

	private boolean matchesExpression(String regex) {
		// regex check
		return text.matches(regex);
	}

	private boolean keywordCheck(String checkword, String[] keywordList) {
		// checks weather a Snippet matches a keyword, listed in keywordList
		checkword = checkword.replaceAll("\\p{Punct}", "");
		for (int i = 0; i < keywordList.length; i++) {
			if (checkword.equalsIgnoreCase(keywordList[i]))
				return true;
		}
		return false;
	}

	public void mergeWithNextSnippet() {
		if (hasNext()) {

			HashMap<String, Boolean> mergeFeatures = next.features;
			java.util.Iterator<String> featuresIterator = features.keySet()
					.iterator();
			String featureName = "";
			while (featuresIterator.hasNext()) {
				featureName = featuresIterator.next();
				features.put(featureName, features.get(featureName)
						|| mergeFeatures.get(featureName));
			}

			tokenValue++;

			setText(text + Config.SEPERATOR + next.getText());
			if (getText().contains("Gor"))
				System.out.println();
			Snippet delSnip = next;

			next = next.next;
			if (next != null)
				next.prev = this;
			delSnip.prev = null;
			delSnip.next = null;

		}

	}

	// public void mergeWithPrevSnippet(){

	// }

	public boolean hasNext() {
		return (next != null);
	}

	public boolean hasPrev() {
		return (prev != null);
	}

	public void setLogicalUnit(String newUnit) {
		logicalUnit = new LogicalUnit(newUnit);

	}

	public void setLogicalUnit(LogicalUnit newUnit) {
		logicalUnit = newUnit;
	}

	public String logicalType() {
		if (logicalUnit == null || !logicalUnit.isValid())
			return null;
		else
			return logicalUnit.type();
	}

	public boolean isLogicalType(String type) {
		if (logicalUnit == null || !logicalUnit.isValid())
			return false;
		else if (logicalUnit.type().equals(type))
			return true;
		return false;
	}

	public boolean hasLogicalType() {
		return logicalType() != null;
	}

	public void setLogicalUnitComment(String unitComment) {
		if (hasLogicalType())
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
		newText = newText.trim();
		text = newText;
		length = newText.length();
		lowerCaseText = newText.toLowerCase();
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

	public boolean condition(String requestCondition) throws Exception {
		// Condition Syntax: !possibleVersion;/os/osext;

		String[] conditions = requestCondition.split(";");
		if (conditions.length == 0)
			return false;
		for (String condition : conditions) {
			String indicator = condition.substring(0, 1);
			if (indicator.equals("!")) {
				condition = condition.substring(1);
				if (!getFeatureValue(condition))
					return false;
			} else if (indicator.equals("-")) {
				condition = condition.substring(1);
				if (getFeatureValue(condition))
					return false;
			} else if (indicator.equals("/")) {
				String[] orConditions = condition.split("/");
				boolean returnvalue = false;
				for (String orCondition : orConditions) {
					returnvalue = returnvalue | getFeatureValue(orCondition);
					if (returnvalue)
						break;
				}
				if (!returnvalue)
					return false;
			} else if (logicalUnit == null)
				return false;
			else if (logicalUnit.isValidType(condition)) {
				if (!logicalUnit.isType(condition))
					return false;
			} else {
				throw new Exception("Snippet condition: \"" + requestCondition
						+ "\" NOT VALID!");
			}

		}
		return true;
	}

	public int value() {
		return tokenValue;
	}

	private boolean getFeatureValue(String featureName) throws Exception {
		if (!features.containsKey(featureName)) {
			throw new Exception(
					"Snippet feature value can not be determined: fature name\""
							+ featureName + "\" NOT VALID");
		}
		return features.get(featureName);
	}

	private int combinationLen() {

		if (logicalUnit == null)
			return 0;

		Vector<String[]> correspondingConditions = logicalUnit
				.getCorrespondingConditions();
		int combinationLen = -1;
		Snippet curSnip = this;
		while (!curSnip.islogicalEnd() && correspondingConditions.size() != 0) {
			List<String[]> removeList = new ArrayList<String[]>();
			for (String[] condition : correspondingConditions) {
				try {
					if (condition.length <= combinationLen + 1
							|| !curSnip
									.condition(condition[combinationLen + 1])) {
						removeList.add(condition);
					}
				} catch (Exception e) {
					removeList.add(condition);
					e.printStackTrace();
				}
			}
			correspondingConditions.removeAll(removeList);
			// Check the next Snippet for a specific condition
			if (correspondingConditions.size() != 0) {
				combinationLen++;
			} else
				break;
			curSnip = curSnip.next;
		}
		return combinationLen;
	}

}
