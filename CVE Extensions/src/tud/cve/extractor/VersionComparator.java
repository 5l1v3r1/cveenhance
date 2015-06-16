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

	public static String getGreatestMatch(List<String> cpes, String product, String prefix) {
		List<String> cleanedList = new ArrayList<String>();
		for (String cpe : cpes)
			if (cpe.startsWith(product) && cpe.split(":").length > 4 && cpe.split(":")[4].startsWith(prefix))
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
				if (cpe.startsWith(greatest) && cpe.length() > greatest.length()) {
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
					String[] version = convertExtToNumbers(greaterThanGreat.get(i).substring(len)).split(" ");
					String[] gre = convertExtToNumbers(greatest.substring(len)).split(" ");
					int minLen = Math.min(version.length, gre.length);
					for (int j = 0; j < minLen; j++)
						if (new Integer(gre[j]).compareTo(new Integer(version[j])) <= -1) {
							greatest = greaterThanGreat.get(i);
						}
				}
				return greatest;
			}
		}
		return "";
	}

	public static String convertExtToNumbers(String cpe) {
		boolean isLastEmptySpace = false;
		String line = "";
		if (cpe != null)
			for (int i = 0; i < cpe.length(); i++) {
				char c = cpe.charAt(i);
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

			int res = new Integer(token1Len).compareTo(token2Len);
			if (res != 0)
				return res;

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

		}
		return new Integer(countSt1).compareTo(countSt2);
	}

}
