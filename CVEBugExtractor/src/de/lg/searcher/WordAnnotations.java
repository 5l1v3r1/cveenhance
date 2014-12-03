package de.lg.searcher;

import java.util.List;

public class WordAnnotations {

	private boolean comma = false;
	private boolean possibleVersion = false;
	private boolean bigLetter = false;
	private boolean notToUse = false;
	private boolean used = false;
	private String word;

	public WordAnnotations next = null;
	public WordAnnotations prev = null;

	public WordAnnotations(String word) {

		this.word = word;
	}

	public boolean isUsed() {
		return used;
	}

	public void setUsed() {
		used = true;
	}

	public String getWord() {
		return word;
	}

	public boolean isComma() {
		return comma;
	}

	public void setComma(boolean comma) {
		word = word.replace(",", "");
		this.comma = comma;
	}

	public boolean isPossibleVersion() {
		return possibleVersion;
	}

	public void setPossibleVersion(boolean possibleVersion) {
		this.possibleVersion = possibleVersion;
	}

	public boolean isBigLetter() {
		return bigLetter;
	}

	public void setBigLetter(boolean bigLetter) {
		this.bigLetter = bigLetter;
	}

	public boolean isNotToUse() {
		return notToUse;
	}

	public void setNotToUse(boolean notToUse) {
		this.notToUse = notToUse;
	}

	public String searchForVersionDetails() {
		String result = this.word;
		this.setUsed();
		WordAnnotations curr = this;
		while (curr.prev != null) {
			if (!curr.isComma()
					&& (curr.prev.isBigLetter() || curr.prev
							.isPossibleVersion())) {
				result += " " + curr.prev.getWord();
				curr.prev.setUsed();
			} else {
				break;
			}
			curr = curr.prev;
		}
		return result;
	}

	/**
	 * 
	 * @param searchTerms
	 * @returns the shortest search term from the list of search terms if it matches with the current word and its successors
	 */
	public String searchForProductDetails(List<String> searchTerms) {
		String result = "";
		for (String searchTerm : searchTerms) {
			String[] subTerms = searchTerm.split(" ");
			if (word.equalsIgnoreCase(subTerms[0])) { 

				int count = 0;

				for (String subTerm : subTerms) { 
					WordAnnotations curr = this;
					
					while(curr!=null){
						if (curr.getWord().equalsIgnoreCase(subTerm)) {
							count++;
						}
						else break;
					
						if (count != subTerms.length)
							curr = curr.next;
						else break;
						}
					
				}
				if (count == subTerms.length) {
					WordAnnotations curr = this;
					for (int i = 0; i < count; i++) {
						curr.isUsed();
						result += curr.getWord() + " ";
						curr = curr.next;
					}
				}
			}
		}
		return result;
	}

	/**
	 * 
	 * @returns all direct connected words, which start with an upper case character
	 */
	public String searchBigLetterSuccessors() {
		String result = "";
		this.setUsed();
		WordAnnotations curr = this;
		while (curr.next != null) {
			if (!curr.isComma()
					&& curr.next.isBigLetter()) {
				result += " " + curr.next.getWord();
				curr.next.setUsed();
			} else {
				break;
			}
			curr = curr.next;
		}
		return result;
	}
	

}
