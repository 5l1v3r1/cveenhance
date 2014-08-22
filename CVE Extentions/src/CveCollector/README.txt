Technische Universität Darmstadt
Multimedia Communications Lab
Sebastian Wollny, Sebastian Schmidt

GERMAN DESCRIPTION:

Das hier vorliegende Programm ist dazu gedacht, um Daten aus der NVD (National Vulnerability Database) auszulesen. 
Die NVD ist eine Datenbank mit Einträgen, die bekannte Schwachstellen von Software auflistet und mögliche Lösungen 
aufzeigt. Interessant wäre es, wenn ein Programm automatich aus dieser Datenbank eine Update-Liste erstellen würde, 
die dann genutzt werden kann, um Inselsysteme und integrierte Software von Schwachstellen zu befreien. Genau dies
ist die Aufgabe dieses Programms. 
Es ist notwendig, dass aus der Datenbank der Name und die Version, ab der eine Schwachstelle 
nicht mehr auftritt, der jeweiligen Software ausgelesen werden. Diese Daten liegen allerdings zunächst in Form 
eines Fließtextes vor und müssen deshalb erst extrahiert werden. Als Dateninput dient das erweiterte XML-Abbild 
der NVD (NVD/CVE XML Feed with CVSS and CPE mappings). 
Dieses wird im ersten Schritt in viele einzelne CVE-Cases zerlegt und danach wird versucht aus jedem der Cases 
(falls vorhanden) die gewünschten Daten zu extrahieren. 

Die Datei CVECollector.java zerlegt das XML-Abbild in einzelne CVE-Dateien, damit die Datenbank in kleinen 
handhabbaren Teilen vorliegt. 
Der Pfad zum Abbild muss darüber hinaus in der konfig.java als "XMLFile" angegeben werden.
Der Pfad zum Ordner, in den die einzelnen Cases kopiert werden muss als "CveFolder" angegeben werden.

Sind die CVE-Cases erstellt worden, so kann nun die Extraktion der Daten beginnen. Dies geschieht mit der Datei 
AnalyseCves.java. Diese erstellt das s.g. CvePrint-File. Dieses Textfile ist das Ergebnis der Analyse.
Es Beinhaltet je Zeile ein Ergebnis der Extraktion mit folgender Struktur: 

"CVE-Number"; "CPE-Software-ID"; "Fixed Version"

Dabei kann es dazu kommen, dass es pro CVE Case zu mehreren Ergebnissen kommt, da Softwareversionen in verschiedenen
Betriebssystemen unterschiedliche Nummerierungen haben können. 

Es gibt zwei "Betriebsmodi" der Software:

1. Normalmodus zum Betrieb und Analyse aller vorliegenden CVE-Files
2. Test-Modus zur Auswertung lediglich einer kleinen Testmenge

Für den Testmodus muss ein seperater Ordner, ein s.g. "CveDump" erstellt werden und in der konfig.java angegeben
werden. Die Anzahl der gewünschten Test-Files wird über die Variable DumpNumber bestimmt.
Zur automatisierten Erstellung der Test-Ordners kann die Datei "CveSample.java" benutzt werden. Diese zieht aus 
dem CveFolder die gewünschte Anzahl an Cases und kopiert diese in den CveDump. 
Dabei ist zu beachten, dass doppelt gezogene Cases vernachlässigt werden.

Für den Normalmodus muss der CveDump in der konfig.java identisch mit dem CveFolder sein! 