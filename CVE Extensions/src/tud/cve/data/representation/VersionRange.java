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
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import tud.cve.extractor.Config;
import tud.cve.extractor.VersionComparator;

public class VersionRange {

	private String firstDetectedVer = "";
	private String lastDetectedVer = "";
	private String softwareName = "";
	private String generalCpeString = "";
	private Snippet fixedSoftware;
	private boolean empty;
	private boolean first;
	private boolean last;
	private boolean fixed;

	private ArrayList<NameVersionRelation> versions;

	public ArrayList<NameVersionRelation> versionList() {
		return versions;
	}

	public void updateSoftwareName(String newSoftwareName) {
		softwareName = newSoftwareName;
	}

	public void setCPE(String newCPE) {
		try {
			if (!newCPE.matches("cpe:/[aho]:[a-z|_|\\-|\\d|\\.|%]+:[a-z|_|\\-|\\d|\\.|%]+:"))
				throw new Exception("CPE String " + newCPE + " is not valid!");
		} catch (Exception e) {
			e.printStackTrace();
		}
		generalCpeString = newCPE;
	}

	public String cpe() {
		return generalCpeString;
	}

	public VersionRange() {
		empty = true;
		versions = new ArrayList<NameVersionRelation>();
		fixed = false;
		last = false;
		first = false;
	}

	public VersionRange(NameVersionRelation nvr) {
		empty = true;
		versions = new ArrayList<NameVersionRelation>();
		fixed = false;
		last = false;
		first = false;
		add(nvr);
	}

	public VersionRange(Set<NameVersionRelation> set) {
		empty = true;
		versions = new ArrayList<NameVersionRelation>();
		fixed = false;
		last = false;
		first = false;
		addAll(set);
	}

	public boolean hasFirst() {
		return first;
	}

	public boolean hasLast() {
		return last;
	}

	public boolean hasFix() {
		return fixed;
	}

	public void setLast(String newLast) {
		lastDetectedVer = newLast;
		last=true;
	}

	public void setFirst(String newFirst) {
		firstDetectedVer = newFirst;
		first=true;
	}
	
	public void setFix(String newFix) {
		firstDetectedVer = newFix;
		fixed=true;
	}

	public String getSoftwareName() {
		return softwareName;
	}

	/**
	 * @return The first version of the version range; Returns a string, if it is not set
	 */
	public String firstDetectedVersion() {
		return firstDetectedVer;
	}

	/**
	 * @return The last version of the version range; Returns an empty string, if it is not set
	 */
	public String lastDetectedVersion() {
		if (!fixed)
			return lastDetectedVer;
		else
			return "";
	}

	/**
	 * @return The fixed version of the version range; Returns an empty string, if it is not set
	 */
	public String fixedVersion() {
		if (fixed)
			return fixedSoftware().getText();
		else
			return "";
	}

	/**
	 * Updates the relevant versions (first, last fix)
	 */
	private void updateRelevantVersions() {
		searchFirst();
		searchLast();
		if (versions.get(versions.size() - 1).version().logicalUnitComment().equals("fixed")) {
			if (versions.size() == 1) {
				firstDetectedVer = "";
				lastDetectedVer = "";
			} else if (versions.size() == 2) {
				firstDetectedVer = shortest().getVersionWithoutX();
				lastDetectedVer = "";
			} else {
				firstDetectedVer = shortest().getVersionWithoutX();
				lastDetectedVer = versions.get(versions.size() - 2).getVersionWithoutX();
			}
		} else {
			if (versions.get(versions.size() - 1).version().logicalUnitComment().equals("last detected vulnerability")) {
				if (versions.size() > 1)
					firstDetectedVer = shortest().getVersionWithoutX();
				else
					firstDetectedVer = "";
				lastDetectedVer = biggest().getVersionWithoutX();
			} else {
				if (versions.size() == 1
						&& versions.get(0).version().logicalUnitComment().equals("first detected vulnerability")) {
					firstDetectedVer = shortest().getVersionWithoutX();
					lastDetectedVer = "";
				} else {
					firstDetectedVer = shortest().getVersionWithoutX();
					lastDetectedVer = biggest().getVersionWithoutX();
				}
			}

		}
	}

	public boolean hasVersionData() {
		return !firstDetectedVersion().isEmpty() || !lastDetectedVersion().isEmpty() || !fixedVersion().isEmpty();
	}

	/**
	 * @return Returns the first released version in the list
	 */
	public NameVersionRelation shortest() {
		return versions.get(0);
	}

	/**
	 * 
	 * @return Returns the last released version in the list
	 */
	public NameVersionRelation biggest() {
		return versions.get(versions.size() - 1);
	}

	private void isFixed() {
		if (!fixed) {
			for (NameVersionRelation nvr : versions) {
				Snippet version = nvr.version();
				if (version.logicalUnitComment().equals("fixed")) {
					fixed = true;
					fixedSoftware = version;
					break;
				}
			}
		}
	}

	private void searchLast() {
		for (NameVersionRelation nvr : versions) {
			Snippet version = nvr.version();
			if (version.logicalUnitComment().equals("last detected vulnerability")) {
				last = true;
				lastDetectedVer = version.getText();
			}
		}
	}

	private void searchFirst() {
		for (NameVersionRelation nvr : versions) {
			Snippet version = nvr.version();
			if (version.logicalUnitComment().equals("first detected vulnerability")) {
				first = true;
				firstDetectedVer = version.getText();
				break;
			}
		}
	}

	public boolean fixed() {
		return fixed;
	}

	public Snippet fixedSoftware() {
		return fixedSoftware;
	}

	/**
	 * Adds a single NameVersionRelation
	 */
	public void add(NameVersionRelation nvr) {
		if (empty) {
			softwareName = nvr.name().getText();
			empty = false;
		}
		versions.add(nvr);
		Collections.sort(versions);
		updateRelevantVersions();
		isFixed();
	}

	/**
	 * Adds NameVersionRelations to the VersionRange and inserts+orders it in the internal NameVersionRelation list
	 */
	public void addAll(Collection<NameVersionRelation> c) {
		if (c.size() > 0) {
			if (empty) {
				softwareName = c.iterator().next().name().getText();
				empty = false;
			}
			versions.addAll(c);
			Collections.sort(versions);
			updateRelevantVersions();
			isFixed();
		}
	}

	/**
	 * @return The XML Code of the first version information
	 */
	public String firstXMLTag() {
		StringBuilder sb = new StringBuilder();
		sb.append("\t\t\t<");
		sb.append(Config.XML_EXTENSION_TAG);
		sb.append(":");
		sb.append("start>");
		sb.append(generalCpeString);
		sb.append(firstDetectedVersion());
		sb.append("</");
		sb.append(Config.XML_EXTENSION_TAG);
		sb.append(":");
		sb.append("start>");
		return sb.toString();
	}

	/**
	 * @return The XML Code of the last version information
	 */
	public String lastXMLTag() {
		if (lastDetectedVersion().length() != 0) {
			StringBuilder sb = new StringBuilder();
			sb.append("\t\t\t<");
			sb.append(Config.XML_EXTENSION_TAG);
			sb.append(":");
			sb.append("end>");
			sb.append(generalCpeString);
			sb.append(lastDetectedVersion().substring(generalCpeString.length()));
			sb.append("</");
			sb.append(Config.XML_EXTENSION_TAG);
			sb.append(":");
			sb.append("end>");
			return sb.toString();
		}
		return "";
	}

	/**
	 * @return The XML Code of the fixed version information
	 */
	public String fixedXMLTag() {
		if (fixedVersion().length() != 0) {
			StringBuilder sb = new StringBuilder();
			sb.append("\t\t\t<");
			sb.append(Config.XML_EXTENSION_TAG);
			sb.append(":");
			sb.append("fix>");
			sb.append(generalCpeString);
			sb.append(fixedVersion());
			sb.append("</");
			sb.append(Config.XML_EXTENSION_TAG);
			sb.append(":");
			sb.append("fix>");
			return sb.toString();
		}
		return "";
	}

	/**
	 * @return The XML Code of the version range
	 */
	public String getXMLRange() {
		StringBuilder sb = new StringBuilder();
		sb.append("\t\t<");
		sb.append(Config.XML_EXTENSION_TAG);
		sb.append(":");
		sb.append("range>\n");

		if (firstDetectedVersion().length() != 0) {
			sb.append(firstXMLTag());
			sb.append("\n");
		}

		if (!lastDetectedVersion().isEmpty() && lastDetectedVersion().length() > generalCpeString.length()) {
			sb.append(lastXMLTag());
			sb.append("\n");
		}

		if (!fixedVersion().isEmpty()) {
			sb.append(fixedXMLTag());
			sb.append("\n");
		}

		sb.append("\t\t</");
		sb.append(Config.XML_EXTENSION_TAG);
		sb.append(":");
		sb.append("range>\n");
		return sb.toString();
	}

	public String toString() {
		if (softwareName.isEmpty())
			softwareName = generalCpeString;
		String returnStr = softwareName + " vulnerable between " + firstDetectedVer + " and " + lastDetectedVer;
		if (fixed)
			returnStr += " fix:" + fixedVersion();
		else
			returnStr += " no fix found";
		if (!generalCpeString.isEmpty() && Config.TEST_MODE)
			returnStr += " |  " + generalCpeString;
		return returnStr;

	}

	/**
	 * Creates a machine readable text output of extraction results
	 * 
	 * @param cveId
	 *            CVE id
	 * @return machine readable output string
	 */
	public StringBuilder getMachineReadableOutput(String cveId) {
		StringBuilder output = new StringBuilder();
		output.append(cveId);
		output.append(";");
		output.append(cpe());
		output.append(";");
		output.append(firstDetectedVersion());
		output.append(";");
		output.append(lastDetectedVersion());
		output.append(";");
		output.append(fixedVersion());
		output.append(";");
		return output.append(toString());
	}

	/**
	 * Creates a human readable text output of extraction results
	 * 
	 * @param cveId
	 *            CVE id
	 * @return human readable output string
	 */
	public StringBuilder getHumanReviewOutput(String cveId) {
		StringBuilder output = new StringBuilder();
		output.append(cveId);
		output.append("  ");
		output.append(toString());
		output.append("  ");
		output.append(cpe());
		return output;
	}

	public void findLast(String cpename, List<String> remaining, List<String> filteredRemainings) {

		if (!hasLast()) {
			if (filteredRemainings.size() != 0)
				remaining = filteredRemainings;

			String greatest = "";
			String versionText = shortest().version().getText();

			if (!fixed() && hasFirst() && versionText.endsWith(".x"))
				greatest = VersionComparator.getGreatestMatch(remaining, cpename,
						versionText.substring(0, versionText.length() - 2));

			if (!greatest.isEmpty())
				setLast(greatest);
		}
	}

}
