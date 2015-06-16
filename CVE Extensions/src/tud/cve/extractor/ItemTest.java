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

import static org.junit.Assert.*;

import java.util.Iterator;
import java.util.Vector;

import org.junit.Test;

import tud.cve.data.representation.NameVersionRelation;
import tud.cve.data.representation.Snippet;
import tud.cve.data.representation.VersionRange;

public class ItemTest {/*
	
	private static Vector<VersionRange> desiredResults = new Vector<VersionRange>();
	private static Vector<String> allFixes = new Vector<String>();
	private static Vector<String> allCveIDs = new Vector<String>();
	private static CveItem[] testItems = new CveItem[10];

	private static String intoString="  <entry><vuln:vulnerable-configuration id=\"http://nvd.nist.gov/\"><cpe-lang:logical-test operator=\"OR\" negate=\"false\"></cpe-lang:logical-test></vuln:vulnerable-configuration><vuln:vulnerable-software-list>";
	private static String secondString=" </vuln:vulnerable-software-list><vuln:cve-id>";
	private static String thirdString="</vuln:cve-id><vuln:published-datetime>1999-12-30T00:00:00.000-05:00</vuln:published-datetime><vuln:last-modified-datetime>2010-12-16T00:00:00.000-05:00</vuln:last-modified-datetime><vuln:cvss><cvss:base_metrics><cvss:score>5.0</cvss:score><cvss:access-vector>NETWORK</cvss:access-vector><cvss:access-complexity>LOW</cvss:access-complexity><cvss:authentication>NONE</cvss:authentication><cvss:confidentiality-impact>NONE</cvss:confidentiality-impact><cvss:integrity-impact>NONE</cvss:integrity-impact><cvss:availability-impact>PARTIAL</cvss:availability-impact><cvss:source>http://nvd.nist.gov</cvss:source><cvss:generated-on-datetime>2004-01-01T00:00:00.000-05:00</cvss:generated-on-datetime></cvss:base_metrics></vuln:cvss><vuln:cwe id=\"CWE-20\"/><vuln:references reference_type=\"UNKNOWN\" xml:lang=\"en\"><vuln:source>OSVDB</vuln:source><vuln:reference href=\"http://www.osvdb.org/5707\" xml:lang=\"en\">5707</vuln:reference></vuln:references><vuln:references reference_type=\"UNKNOWN\" xml:lang=\"en\"><vuln:source>CONFIRM</vuln:source><vuln:reference href=\"http://www.openbsd.org/errata23.html#tcpfix\" xml:lang=\"en\">http://www.openbsd.org/errata23.html#tcpfix</vuln:reference></vuln:references><vuln:summary>";
	private static String lastString=" </vuln:summary></entry>";
	
	

	@Test
	public void tokenCombinationTest(){
		try {
			testItems[1] = new CveItem(intoString+"<vuln:product>cpe:/a:macromedia:flashplayer:7.1</vuln:product><vuln:product>cpe:/a:macromedia:flashplayer:7.2</vuln:product><vuln:product>cpe:/a:macromedia:flashplayer:7.0</vuln:product>"+secondString+"CVE-2000-0001"+thirdString+"In the Macromedia Flash Player 7.2 and earlier a cross side vunerability occours. It is often used to gather bank account data. "+lastString);
			addPartResult("Macromedia Flash Player", "", "7.2", "", "cpe:/a:macromedia:flashplayer:", "CVE-2000-0001");
			assertTrue(checkItemResult(testItems[1], "earlier keyword check"));
		} catch (Exception e) {
			e.printStackTrace();
			fail("AnalyseTest failed: thrown exception");
		}
	}
	
	// -----------------------------------------
	

	
	
		private void addPartResult(String softwareName, String versionStart, String versionEnd, String versionFix, String cpe, String cveID){
			VersionRange curVersionRange = new VersionRange();
			curVersionRange.updateSoftwareName(softwareName);
			curVersionRange.setCPE(cpe);
			curVersionRange.setFirst(versionStart);
			curVersionRange.setLast(versionEnd);
			desiredResults.add(curVersionRange);
			allFixes.add(versionFix);
			allCveIDs.add(cveID);
		}
		
		private void clearCurrentDesiredResult(){
			desiredResults.removeAllElements();
			allFixes.clear();
			allCveIDs.removeAllElements();
		}
		

		private boolean checkItemResult(CveItem testItem, String testTitle){
			
			boolean returnBool=true;
				String extractedCveID=testItem.getCVEID();
					
				AnalyseCves analyseTestUnit = new AnalyseCves();
				Vector<Snippet> versions = testItem.getSnippetsWithLogicalUnits("version");
				Vector<NameVersionRelation> relations = new Vector<NameVersionRelation>();

				analyseTestUnit.fillRelations(testItem, versions, relations);
				//
				Vector<VersionRange> results = analyseTestUnit.createResult(relations, testItem);
				
				System.out.println("===== Analyzing "+extractedCveID+" \""+testTitle+"\" =====");
				Iterator<String> fixIterator = allFixes.iterator();
				
				
				for (VersionRange desiredResult:desiredResults) {
					String fix = fixIterator.next();
					int resultCheckedCounter=0;	
					System.out.println(desiredResult.getSoftwareName()+" ("+desiredResult.firstDetectedVersion()+"->"+desiredResult.lastDetectedVersion()+"), fix: "+fix+":");
					boolean partResultCorrect=false;
					
					for(VersionRange result : results){
						System.out.println("\nComparing desired result with extracted result no. "+(resultCheckedCounter+1));
						if(desiredResult.getSoftwareName().equals(result.getSoftwareName())&&desiredResult.firstDetectedVersion().equals(result.firstDetectedVersion())&&desiredResult.lastDetectedVersion().equals(result.lastDetectedVersion())&&desiredResult.cpe().equals(result.cpe())){
							System.out.println("Ckecked: SW-Name OK, First OK, Last OK, CPE OK");
							if(result.fixedVersion().equals(fix)){
								System.out.println("Note: Fix OK");
								if(extractedCveID.equals(allCveIDs.get(resultCheckedCounter))) {
									partResultCorrect=true;
									break;
								}
								else System.out.println("Warning: CVE-ID not correct");
							}
							else System.out.println("Warning: Fix "+result.fixedVersion()+" not correct. Desired: "+fix);
						}
						else{
							String failString="";
							System.out.print("Checked: ");
							if(!desiredResult.getSoftwareName().equals(result.getSoftwareName())){
								System.out.print("SW-Name NG,");
								failString+="SW-Name desired: "+desiredResult.getSoftwareName()+", found: "+result.getSoftwareName()+"\n";
							}
							else System.out.print("SW-Name OK,");
							
							if(!desiredResult.firstDetectedVersion().equals(result.firstDetectedVersion())){
								System.out.print(" First NG,");
								failString+="First desired: "+desiredResult.firstDetectedVersion()+", found: "+result.firstDetectedVersion()+"\n";
							}
							else System.out.print(" First OK,");
							
							if(!desiredResult.lastDetectedVersion().equals(result.lastDetectedVersion())){
								System.out.print(" Last NG,");
								failString+="Last desired: "+desiredResult.lastDetectedVersion()+", found: "+result.lastDetectedVersion()+"\n";
							}
							else System.out.print(" Last OK,");
							
							if(!desiredResult.cpe().equals(result.cpe())){
								System.out.println(" CPE NG");
								failString+="CPE desired: "+desiredResult.cpe()+", found: "+result.cpe()+"\n";
							}
							else System.out.println(" CPE OK");
							if(!failString.isEmpty())System.out.print(failString);
						}
						resultCheckedCounter++;
					}
					if(partResultCorrect)System.out.println("Check: OK \n");
					else{
						System.out.println("Check: FAILED\n");
						returnBool=false;
					}
				}
			clearCurrentDesiredResult();
			if(returnBool)System.out.println("=> "+testTitle+": ==== OK ====\n");
			else System.out.println("=> "+testTitle+": !!!!! FAILED !!!!!\n");
			return returnBool;
		}
*/
}
