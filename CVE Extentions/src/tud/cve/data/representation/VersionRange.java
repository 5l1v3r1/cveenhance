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

import tud.cve.extractor.Config;

public class VersionRange {

	private String firstDetectedVer = "0.0";
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
		if(!newCPE.matches("cpe:/[aho]:[a-z|_|\\-|\\d|\\.|%]+:[a-z|_|\\-|\\d|\\.|%]+:"))	throw new Exception("CPE String "+newCPE+" is not valid!");
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
	}

	public void setFirst(String newFirst) {
		firstDetectedVer = newFirst;
	}
	
	public String getSoftwareName(){
		return softwareName;
	}

	/**
	 * @return The first version of the version range; Returns a string "0.0", if it is not set
	 */
	public String firstDetectedVersion() {
		return firstDetectedVer;
	}

	/**
	 * @return The last version of the version range; Returns an empty string, if it is not set
	 */
	public String lastDetectedVersion() {
		return lastDetectedVer;
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
				firstDetectedVer = "0.0";
				lastDetectedVer = "";
			} else if (versions.size() == 2) {
				firstDetectedVer = shortest().version().getText().replaceFirst("\\.x", ".0");
				lastDetectedVer = "";
			} else {
				firstDetectedVer = shortest().version().getText().replaceFirst("\\.x", ".0");
				lastDetectedVer = versions.get(versions.size() - 2).version().getText().replaceFirst("\\.x", ".0");
			}
		} else {
			if (versions.get(versions.size() - 1).version().logicalUnitComment().equals("last detected vulnerability")) {
				if (versions.size() > 1)
					firstDetectedVer = shortest().version().getText().replaceFirst("\\.x", ".0");
				else
					firstDetectedVer = "0.0";
				lastDetectedVer = biggest().version().getText().replaceFirst("\\.x", ".0");
			} else {
				if (versions.size() == 1 && versions.get(0).version().logicalUnitComment().equals("first detected vulnerability")) {
					firstDetectedVer = shortest().version().getText().replaceFirst("\\.x", ".0");
					lastDetectedVer = "";
				} else {
					firstDetectedVer = shortest().version().getText().replaceFirst("\\.x", ".0");
					lastDetectedVer = biggest().version().getText().replaceFirst("\\.x", ".0");
				}
			}

		}
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

	/**
	 * @return The XML Code of the fixed version information
	 */
	public String fixedXMLTag() {
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

	/**
	 * @return The XML Code of the version range
	 */
	public String getXMLRange() {
		StringBuilder sb = new StringBuilder();
		sb.append("\t\t<");
		sb.append(Config.XML_EXTENSION_TAG);
		sb.append(":");
		sb.append("range>\n");

		if (!firstDetectedVersion().equals("0.0")) {
			sb.append(firstXMLTag());
			sb.append("\n");
		}

		if (!lastDetectedVersion().isEmpty()&&lastDetectedVersion().length()>generalCpeString.length()) {
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

}
