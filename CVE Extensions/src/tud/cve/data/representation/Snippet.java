package tud.cve.data.representation;

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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map.Entry;
import java.util.Vector;
import java.util.regex.Pattern;

import tud.cve.extractor.Config;
import tud.cve.extractor.FeatureVectorBuilder;
import tud.cve.extractor.LogicalUnit;

/**
 * This class should represent a part of a floating text e.g. a token / combined tokens. Furthermore a Snippet should
 * represents a logical unit e.g. a software name, a version number or a stopword.
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
		return text.length();
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
		String lowerCaseText = text.toLowerCase().replaceAll("\\p{Punct}", "");
		try {
			setFeature("comma", matchesLowerCase(".*,"));
			setFeature("possibleversion", matchesLowerCase(".*\\d.*"));
			setFeature("word", (text.length() >= 3));
			setFeature("bigletter", matchesExpression("[A-Z]+.*"));
			setFeature("versionext", Arrays.asList(Config.VERION_KEYWORDS).contains(lowerCaseText));
			setFeature("version", (matchesLowerCase("[\\d]+[\\p{Punct}\\w]*") && !(matchesLowerCase("") )));
			setFeature("os", Arrays.asList(Config.OS_KEYWORDS).contains(lowerCaseText));
			setFeature("osext", Arrays.asList(Config.OS_EXTENSIONS).contains(lowerCaseText));
			setFeature("stopword", Arrays.asList(Config.STOP_WORDS).contains(lowerCaseText));
			setFeature("concatword", Arrays.asList(Config.CONCAT_WORDS).contains(lowerCaseText));
			setFeature("comparingword", Arrays.asList(Config.COMPARING_WORDS).contains(lowerCaseText));
			setFeature("seperator", Arrays.asList(Config.SEPERATING_WORDS).contains(lowerCaseText));
			setFeature("namestart", Arrays.asList(Config.SOFTWARE_NAME_START_WORDS).contains(lowerCaseText));
			setFeature("versionstart", Arrays.asList(Config.SOFTWARE_NAME_STOP_WORDS).contains(lowerCaseText));
			setFeature("cuebefore", Arrays.asList(Config.SOFTWARE_NAME_STOP_WORDS).contains(lowerCaseText));
			setFeature("cueearlier", Arrays.asList(Config.SOFTWARE_VERSION_ENDS_AND).contains(lowerCaseText));
			setFeature("cuebegin", Arrays.asList(Config.SOFTWARE_BEGIN_IND).contains(lowerCaseText));
			setFeature("cuebetween", Arrays.asList(Config.SOFTWARE_RANGE_IND_BETW).contains(lowerCaseText));
			setFeature("endsafter", Arrays.asList(Config.SOFTWARE_VERSION_ENDS_IND).contains(lowerCaseText));

			if ((getFeatureValue("comma") || matchesLowerCase(".+["
					+ createRegexpFromStrings(Config.SEPERATING_CHARS, "") + "]"))) {
				setFeature("logicalend", true);
				text = text.substring(0, text.length() - 1);
			}
			if (prev != null && matchesLowerCase("[" + createRegexpFromStrings(Config.SEPERATING_CHARS) + "]"))
				prev.setFeature("logicalend", true);

			if (!hasPrev())
				setFeature("logicalstart", true);
			else {
				if (prev.islogicalEnd())
					setFeature("logicalstart", true);
				else
					setFeature("logicalstart", false);
			}

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

	public void setFeature(String featureName, boolean newValue) throws Exception {
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
		return text.toLowerCase().endsWith("" + checkChar);
	}

	/**
	 * Checks, if a regular expression matches to the snippet content (case sensitve)
	 */
	private boolean matchesLowerCase(String regex) {
		// lower case regex check
		return text.toLowerCase().matches(regex);
	}

	/**
	 * Checks, if a regular expression matches to the snippet content (case sensitve)
	 */
	private boolean matchesExpression(String regex) {
		// regex check
		return text.matches(regex);
	}

	/**
	 * combines the Snippet with the next Snippet
	 */
	public void mergeWithNextSnippet() {
		if (hasNext()) {

			HashMap<String, Boolean> mergeFeatures = next.features;
			java.util.Iterator<String> featuresIterator = features.keySet().iterator();
			String featureName = "";
			while (featuresIterator.hasNext()) {
				featureName = featuresIterator.next();
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
		if (newText != null)
			text = newText.trim();
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
		if (conditions.length == 1 && conditions[0].isEmpty())
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
				String[] orConditions = condition.substring(1).split("/");
				boolean returnvalue = false;
				for (String orCondition : orConditions) {
					returnvalue |= getFeatureValue(orCondition);
					if (returnvalue)
						break;
				}
				if (!returnvalue)
					return false;
			}
				break;
			default: {
				if (logicalUnit == null)
					return false;
				else if (logicalUnit.isValidType(condition)) {
					if (!logicalUnit.isType(condition))
						return false;
				} else {
					throw new Exception("Snippet condition: \"" + requestCondition + "\" NOT VALID!");
				}
			}
				break;

			}
		}
		return true;
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
			throw new Exception("Snippet feature value can not be determined: fature name\"" + featureName
					+ "\" NOT VALID");
		}
		return features.get(featureName);
	}

	/**
	 * @return Maximum number of combinations, which are possible by the defined combination rules
	 */
	public int combinationLen() {
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
