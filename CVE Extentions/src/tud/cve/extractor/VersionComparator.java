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

import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;

/**
 * >> Compares version strings and CPE strings and defines an order.<<
 * 
 * @author TU Darmstadt KOM, TU Darmstadt STG
 * @version 0.1
 */

public class VersionComparator {

	public static String getGreatestMatch(List<String> cpes, String product,
			String prefix) {
		List<String> cleanedList = new ArrayList<String>();
		for (String cpe : cpes)
			if (cpe.startsWith(product) && cpe.split(":").length > 4
					&& cpe.split(":")[4].startsWith(prefix))
				cleanedList.add(cpe);
		if (cleanedList.size() > 0) {
			String greatest = cleanedList.get(0);
			for (int i = 1; i < cleanedList.size(); i++) {
				String version = cleanedList.get(i).split(":")[4];
				if (compareTo(greatest.split(":")[4], version) <= -1) {
					greatest = cleanedList.get(i);
				}
			}
			List<String> greaterThanGreat = new ArrayList<String>();
			for (String cpe : cleanedList) {
				if (cpe.startsWith(greatest)
						&& cpe.length() > greatest.length()) {
					greaterThanGreat.add(cpe);
				}
			}
			if (greaterThanGreat.size() == 0)
				return greatest;
			else if (greaterThanGreat.size() == 1) {
				return greaterThanGreat.get(0);
			} else {
				int len = greatest.length();
				greatest = greaterThanGreat.get(0);
				for (int i = 1; i < greaterThanGreat.size(); i++) {
					String[] version = convertExtToNumbers(
							greaterThanGreat.get(i).substring(len)).split(" ");
					String[] gre = convertExtToNumbers(greatest.substring(len))
							.split(" ");
					int minLen = Math.min(version.length, gre.length);
					for (int j = 0; j < minLen; j++)
						if (new Integer(gre[j]).compareTo(new Integer(
								version[j])) <= -1) {
							greatest = greaterThanGreat.get(i);
						}
				}
				return greatest;
			}
		}
		return "";
	}

	public static String convertExtToNumbers(String cpe) {
		String result = cpe;
		boolean isLastEmptySpace = false;
		String line = "";
		if (result != null)
			for (int i = 0; i < result.length(); i++) {
				char c = result.charAt(i);
				if (Character.isDigit(c)) {
					line += c;
					isLastEmptySpace = false;
				} else if (!isLastEmptySpace) {
					line += " ";
					isLastEmptySpace = true;
				}
			}
		return line.trim();
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
			if (token1Len > token2Len)
				return 1;
			else if (token2Len > token1Len)
				return -1;
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

		}
		if (countSt1 > countSt2) {
			return 1;
		} else if (countSt2 > countSt1)
			return -1;

		return 0;
	}

}
