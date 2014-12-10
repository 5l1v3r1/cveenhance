package CveCollector;

public class NameVersionRelation {
	private Snippet name;
	private Snippet version;

	
	public NameVersionRelation(Snippet softwareName, Snippet softwareVersion) {
		name=softwareName;
		version=softwareVersion;
	} 
	
	public Snippet name(){
		return name;
	}
	
	public Snippet version(){
		return version;
	}
	
	public void setName(Snippet newName){
		name=newName;
	}
	
	public void setVersion(Snippet newVersion){
		version=newVersion;
	}
	
	public String toString(){
		String versioninfo="";
		if(!version.logicalUnitComment().equals("")) versioninfo=" ("+version.logicalUnitComment()+")";
		return name+" "+version+versioninfo;
	}
	
	private String trimVersion (String version){
		if(version.contains(" "))version=version.substring(0, version.indexOf(" "));
		version=version.trim();
		if(version.substring(version.length()-2).equals(".x"))version=version.substring(0, version.length()-2);
		return version;
	}
	
	public boolean equals (NameVersionRelation otherRelation){
		return this.hashCode()==otherRelation.hashCode();
	}
	@Override
	public int hashCode (){
		return (name.getText()+version.getText()).hashCode();
	}
	
	
}
