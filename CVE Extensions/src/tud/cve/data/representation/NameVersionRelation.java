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

/**
 * >> An object of this class represents a related software name and software version <<
 * 
 * @author TU Darmstadt KOM, TU Darmstadt STG
 * @version 0.1
 */

public class NameVersionRelation implements Comparable<NameVersionRelation> {
	private Snippet name;
	private Snippet version;
	private String cpe;

	public NameVersionRelation(Snippet softwareName, Snippet softwareVersion) {
		name = softwareName;
		version = softwareVersion;
		cpe = "";
	}

	/**
	 * @return software name
	 */
	public Snippet name() {
		return name;
	}

	/**
	 * @return software version
	 */
	public Snippet version() {
		return version;
	}

	/**
	 * Sets a related software name
	 * 
	 * @param newName
	 *            new software name
	 */
	public void setName(Snippet newName) {
		name = newName;
	}

	/**
	 * Sets a related software version
	 * 
	 * @param newVersion
	 *            new software version
	 */
	public void setVersion(Snippet newVersion) {
		version = newVersion;
	}

	/**
	 * Sets a CPE String
	 * 
	 * @param newCPE
	 *            new CPE String
	 */
	public void setCPE(String newCPE) {
		cpe = newCPE;
	}

	/**
	 * @return CPE String
	 */
	public String cpe() {
		return cpe;
	}

	public String toString() {
		String versioninfo = "";
		if (!version.logicalUnitComment().equals(""))
			versioninfo = " (" + version.logicalUnitComment() + ")";
		return name + " " + version + versioninfo;
	}

	/**
	 * @return trimmed version information
	 */
	public String trimmedVersion() {
		return trimVersion(version.getText());
	}

	/**
	 * trims a version and replaces placeholders
	 */
	public String trimVersion(String version) {
		version = version.trim();
		if (version.contains(" "))
			version = version.substring(0, version.indexOf(" "));
		version = version.trim();
		return optimizeVersion(version);
	}

	public String optimizeVersion(String version) {
		if (version.length() > 1 && version.substring(version.length() - 2).equals(".x"))
			version = version.substring(0, version.length() - 2);
		else if (version.length() > 1 && version.substring(version.length() - 2).equals(".0"))
			version = version.substring(0, version.length() - 2);
		return version;
	}

	/**
	 * Checks, if two NameVersionRelations refer to the same software name
	 */
	public boolean refersSameSoftware(NameVersionRelation otherRel) {
		return name().getText().equalsIgnoreCase(otherRel.name().getText());
	}

	/**
	 * Checks, if a software version is a parent software version
	 */
	public boolean versionIsMoreGeneral(NameVersionRelation otherRel) {
		return otherRel.version().getText().contains(trimmedVersion());
	}

	/**
	 * Checks, if two NameVersionRelations refer to the same parent version
	 */
	public boolean hasSameSuperversion(NameVersionRelation otherRel) {
		String[] splittedVersion = version.getText().split("\\.");
		String[] splittedOtherVersion = otherRel.version().getText().split("\\.");

		if (splittedVersion.length < 2 || splittedOtherVersion.length < 2) {
			return splittedVersion[0].equals(splittedOtherVersion[0]);
		} else {
			for (int i = 0; (i < (splittedVersion.length - 1)) && (i < splittedOtherVersion.length - 1); i++) {
				if (!splittedVersion[i].equals(splittedOtherVersion[i]))
					return false;
			}
			return true;
		}
	}

	public boolean equals(NameVersionRelation otherRelation) {
		return hashCode() == otherRelation.hashCode();
	}

	@Override
	public int hashCode() {
		return (name.getText() + trimmedVersion()).hashCode();
	}

	@Override
	public int compareTo(NameVersionRelation otherNVR) {
		if (otherNVR.trimmedVersion() == null && this.trimmedVersion() == null) {
			return 0;
		}
		if (this.trimmedVersion() == null) {
			return 1;
		}
		if (otherNVR.trimmedVersion() == null) {
			return -1;
		}
		String[] versionSplit = this.trimmedVersion().split("\\.");
		String[] otherVersionSplit = otherNVR.trimmedVersion().split("\\.");
		if (versionSplit.length > 1 && otherVersionSplit.length > 1) {
			try { // Try to convert version number into Integer and compare it
				for (int i = 0; i < versionSplit.length; i++) {
					if (i >= otherVersionSplit.length)
						return 1;
					int res = new Integer(versionSplit[i]).compareTo(new Integer(otherVersionSplit[i]));
					if (res != 0)
						return res;
				}
				if (otherVersionSplit.length > versionSplit.length)
					return -1;
				else if (this.version().getText().indexOf(" ") == -1 && otherNVR.version().getText().indexOf(" ") == -1)
					return 0;
			} catch (Exception e) {

			}
		}

		String version = optimizeVersion(this.version().getText());
		String otherVersion = optimizeVersion(otherNVR.version.getText());

		for (int i = 0; i < version.length() && i < otherVersion.length(); i++) { // character-wise compare
			int res = new Character(version.charAt(i)).compareTo(otherVersion.charAt(i));
			if (res != 0)
				return res;
		}
		return new Integer(version.length()).compareTo(otherVersion.length());
	}

	public String getVersionWithoutX() {
		return version().getText().replaceFirst("\\.x", ".0");
	}

}
