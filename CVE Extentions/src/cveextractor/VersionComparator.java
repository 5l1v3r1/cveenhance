package cveextractor;

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
import java.util.List;
import java.util.StringTokenizer;

public class VersionComparator {

	public static void main(String[] args) {

		String vers1 = "1b";

		String vers2 = "11b";
		System.out.println(compareTo(vers2, vers1));

	}

	public static String getSmallestMatch(List<String> cpes) {
		String smallest = cpes.get(0);
		for (int i = 1; i < cpes.size(); i++) {
			if (compareTo(smallest, cpes.get(i)) >= 1) {
				smallest = cpes.get(i);
			}
		}
		return smallest;
	}

	public static String getGreatestMatch(List<String> cpes) {
		String greatest = cpes.get(0);
		for (int i = 1; i < cpes.size(); i++) {
			if (compareTo(greatest, cpes.get(i)) <= -1) {
				greatest = cpes.get(i);
			}
		}
		return greatest;
	}

	public static String getGreatestUnderFix(List<String> cpes, String fixVersion) {
		List<String> smallerThanFix = new ArrayList<String>();
		for (String cpe : cpes) {
			if (compareTo(cpe, fixVersion) <= -1) {
				smallerThanFix.add(cpe);
			}
		}
		if(smallerThanFix.size()==0) return "";
		return getGreatestMatch(smallerThanFix);
	}

	public static int compareTo(String arg0, String arg1) {

		StringTokenizer st1 = new StringTokenizer(arg0, "._-/()");
		StringTokenizer st2 = new StringTokenizer(arg1, "._-/()");
		int countSt1 = st1.countTokens();
		int countSt2 = st2.countTokens();
		int minTokens = Math.min(countSt1, countSt2);
		for (int i = 0; i < minTokens; i++) {
			String token1 = st1.nextToken();
			String token2 = st2.nextToken();
			int token1Len = token1.length();
			int token2Len = token2.length();
			int minLen = Math.min(token1Len, token2Len);
			for (int j = 0; j < minLen; j++) {
				Character c1 = token1.charAt(j);
				Character c2 = token2.charAt(j);
				int cmp = new Character(c1).compareTo(c2);
				if (cmp != 0) {
					if ((Character.isLetter(c1) && Character.isDigit(c2)))
						return -1;
					else if ((Character.isLetter(c2) && Character.isDigit(c1)))
						return 1;
					return cmp;
				}
			}
			if (token1Len > token2Len)
				return 1;
			else if (token2Len > token1Len)
				return -1;

		}
		if (countSt1 > countSt2) {
			return 1;
		} else if (countSt2 > countSt1)
			return -1;

		return 0;
	}

}
