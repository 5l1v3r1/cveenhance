package CveCollector;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Vector;
import java.util.regex.Pattern;

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
	/*
	 * private boolean comma = false; private boolean word = false; private
	 * boolean possibleVersion = false; private boolean bigLetter = false;
	 * private boolean notToUse = false; private boolean used = false; private
	 * boolean version = false; private boolean os = false; private boolean
	 * osExt = false; private boolean stopword = false; private boolean
	 * concatword = false; private boolean seperator = false; private boolean
	 * nameStart = false; private boolean versionStart = false; private boolean
	 * versionEnd = false;
	 */

	// handling vars:
	private boolean logicalEnd = false;
	private boolean logicalStart = false;
	private String text; // floating text part
	private String lowerCaseText;
	private int length = 0;
	private int tokenValue = 1;
	private boolean singleToken = true;
	private lUnit logicalUnit = null;
	private Section section = null;

	// connections to neighbor Snippets
	public Snippet next = null;
	public Snippet prev = null;

	// Getters:
	/*
	 * public boolean hasComma() {return comma;} public boolean
	 * isMoreThanTwoChar() {return word;} public boolean isPossibleVersion()
	 * {return possibleVersion;} public boolean startsWithBigLetter() {return
	 * bigLetter;} public boolean isNotUsed() {return notToUse;} public boolean
	 * isUsed() {return used;} public boolean isVersion() {return version;}
	 * public boolean isOs() {return os;} public boolean isOsExt() {return
	 * osExt;} public boolean isStopword() {return stopword;} public boolean
	 * isConcatWord() {return concatword;} public boolean isSeperator() {return
	 * seperator;} public boolean isNameStartKeyword() {return nameStart;}
	 * public boolean getVersionStart() {return versionStart;} public boolean
	 * getVersionEnd() {return versionEnd;} public boolean isSingleToken()
	 * {return singleToken;} public boolean isPartOfName() {return name;}
	 */

	public int getTokenValue() {
		return tokenValue;
	}

	public boolean islogicalEnd() {
		return logicalEnd || !hasNext();
	}

	public boolean islogicalStart() {
		return logicalStart;
	}

	public int length() {
		return length;
	}

	// Constructor:
	public Snippet(String innerText) {
		setText(innerText);
	}

	// Init:

	public void init() {
		features = defaultVector;
		try {
			setFeature("comma", lcheck(".*,"));
			setFeature("possibleversion", lcheck(".*\\d.*"));
			setFeature("word", (text.length() >= 3));
			setFeature("bigletter", check("[A-Z]+.*"));
			setFeature(
					"version",
					keywordCheck(lowerCaseText, Konfig.versionKeywords)
							|| (lcheck("[\\d]+[\\p{Punct}\\w]*") && !(lcheck(""))));
			setFeature("os", keywordCheck(lowerCaseText, Konfig.osKeywords));
			setFeature("osext",
					keywordCheck(lowerCaseText, Konfig.osExctentions));
			setFeature("stopword",
					keywordCheck(lowerCaseText, Konfig.stopWords));
			setFeature("cancatword",
					keywordCheck(lowerCaseText, Konfig.concatWords));
			setFeature("seperator",
					keywordCheck(lowerCaseText, Konfig.seperatingWord));
			setFeature("namestart",
					keywordCheck(lowerCaseText, Konfig.softwareNameStartWords));
			setFeature("versionstart",
					keywordCheck(lowerCaseText, Konfig.softwareNameStopWords));
			setFeature("versionend",
					keywordCheck(lowerCaseText, Konfig.softwareVersionEnd));
			setFeature(
					"logicalend",
					(getFeatureValue("comma") | lcheck(".+["
							+ createRegexpFromStrings(Konfig.seperatingChar, "")
							+ "]")));
			if (prev != null
					&& lcheck("["
							+ createRegexpFromStrings(Konfig.seperatingChar)
							+ "]"))
				prev.setFeature("logicalend", true);

			// if(getFeatureValue("version")) System.out.println(getText());

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
			if (getFeatureValue("bigletter"))
				setLogicalUnit("softwarename");

		} catch (Exception e) {
			e.printStackTrace();
		}
		/*
		 * // TODO: Check the efficiency of all regex comma= lcheck(".*,");
		 * if(comma){ setText(text.substring(0, text.length()-1)); } // also
		 * Point chars possibleVersion=lcheck(".*\\d.*"); word=
		 * (text.length()>=3); bigLetter= check("[A-Z]+.*"); version=
		 * keywordCheck(lowerCaseText,
		 * konfig.versionKeywords)||(lcheck("[\\d]+[\\p{Punct}\\w]*"
		 * )&&!(lcheck("")));
		 * 
		 * //TODO: Insert Regex for Dates os= keywordCheck(lowerCaseText,
		 * konfig.osKeywords); osExt= keywordCheck(lowerCaseText,
		 * konfig.osExctentions); stopword= keywordCheck(lowerCaseText,
		 * konfig.stopWords); concatword= keywordCheck(lowerCaseText,
		 * konfig.concatWords); seperator= keywordCheck(lowerCaseText,
		 * konfig.seperatingWord); nameStart= keywordCheck(lowerCaseText,
		 * konfig.softwareNameStartWords); versionStart=
		 * keywordCheck(lowerCaseText, konfig.softwareNameStopWords);
		 * versionEnd= keywordCheck(lowerCaseText, konfig.softwareVersionEnd);
		 * if(comma)setLogicalEnd(true); // Point Chars also have to be
		 * mentioned
		 * if(lcheck(".+["+createRegexpFromStrings(konfig.seperatingChar)+"]"))
		 * setLogicalEnd(true); else if (prev!=null &&
		 * lcheck("["+createRegexpFromStrings(konfig.seperatingChar )+"]"))
		 * prev.setLogicalEnd(true);
		 * 
		 * if(version) System.out.println(getText());
		 * 
		 * if(hasPrev()==false) logicalStart=true; else{
		 * if(prev.islogicalEnd())logicalStart=true; else logicalStart=false; }
		 */
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

	private boolean lcheck(String regex) {
		// lower case regex check
		return lowerCaseText.matches(regex);
	}

	private boolean check(String regex) {
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
		// TODO: Update and validate the merging process! (length and new
		// variables)
		if (hasNext()) {
			singleToken = false;

			HashMap<String, Boolean> mergeFeatures = next.features;
			java.util.Iterator<String> featuresIterator = features.keySet()
					.iterator();
			String featureName = "";
			while (featuresIterator.hasNext()) {
				featureName = featuresIterator.next();
				features.put(featureName, features.get(featureName)
						|| mergeFeatures.get(featureName));
			}
			/*
			 * comma = next.hasComma(); word = word ||next.isMoreThanTwoChar();
			 * possibleVersion = possibleVersion||next.isPossibleVersion();
			 * bigLetter = bigLetter||next.startsWithBigLetter(); notToUse =
			 * (notToUse && next.isNotUsed()); used = used || next.isUsed();
			 * version = version || next.isVersion(); os = os || next.isOs();
			 * osExt = osExt || next.isOsExt(); stopword = stopword ||
			 * next.isStopword(); concatword = concatword ||
			 * next.isConcatWord(); seperator = seperator || next.isSeperator();
			 * nameStart = nameStart || next.isNameStartKeyword(); versionStart
			 * = versionStart || next.versionStart; versionEnd = versionEnd ||
			 * next.getVersionEnd();
			 */

			tokenValue++;

			setText(text + Konfig.seperator + next.getText());
			Snippet delSnip = next;
			delSnip.prev = null;
			delSnip.next = null;
			next = next.next;
			if (next != null)
				next.prev = this;

		}

	}

	// public void mergeWithPrevSnippet(){
	// TODO: Implement merge process

	// }

	// public Object getValue(String varName) throws Exception{
	// if(varName=="comma") return comma;
	//
	// TODO
	//
	// throw new Exception("Var "+varName+ " could not be found!");
	// }

	public boolean hasNext() {
		return (next != null);
	}

	public boolean hasPrev() {
		return (prev != null);
	}

	public void setLogicalUnit(String newUnit) {
		logicalUnit = new lUnit(newUnit);

	}

	public void setLogicalUnit(lUnit newUnit) {
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

	public boolean hasLogicalType(String checklogicalType) {
		return checklogicalType.equals(logicalType());
	}

	public void addToSection(Section newSection) {
		newSection.addSnippet(this);
		section = newSection;
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

	public void melt() {

		int meltingNumber = meltable();
		for (int i = 0; i < meltingNumber; i++)
			mergeWithNextSnippet();
		// adjustSnippetFeatures();
	}

	/*
	 * private void adjustSnippetFeatures() { // Adjust Features (if required)
	 * 
	 * }
	 */

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

	private boolean getFeatureValue(String featureName) throws Exception {
		if (!features.containsKey(featureName)) {
			throw new Exception(
					"Snippet feature value can not be determined: fature name\""
							+ featureName + "\" NOT VALID");
		}
		return features.get(featureName);
	}

	private int meltable() {
		// returns the maximal Number of following snippets, which can be melted
		// with the current snippet
		if (logicalUnit == null)
			return 0;

		Vector<String[]> correspondingConditions = logicalUnit
				.getCorrespondingConditions();
		int meltingNumber = 0;
		Snippet curSnip = this;
		if (curSnip.text.startsWith("Gor"))
			System.out.println();
		while (!curSnip.islogicalEnd() && correspondingConditions.size() != 0) {
			List<String[]> removeList = new ArrayList<String[]>();
			for (String[] condition : correspondingConditions) {
				try {
					if (condition.length < meltingNumber + 1
							|| !curSnip.condition(condition[meltingNumber])) {
						removeList.add(condition);

					}
				} catch (Exception e) {
					removeList.add(condition);
					e.printStackTrace();
				}
			}
			correspondingConditions.removeAll(removeList);
			// Check the next Snippet for a specific condition
			if (correspondingConditions.size() != 0)
				meltingNumber++;
			else
				break;
			curSnip = curSnip.next;
		}
		return meltingNumber;
	}

}
