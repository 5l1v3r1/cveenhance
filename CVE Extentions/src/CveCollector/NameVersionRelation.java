package CveCollector;

public class NameVersionRelation implements Comparable<NameVersionRelation>{
	private Snippet name;
	private Snippet version;
	private String cpe;

	
	public NameVersionRelation(Snippet softwareName, Snippet softwareVersion) {
		name=softwareName;
		version=softwareVersion;
		cpe="";
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
	
	public void setCPE(String newCPE){
		cpe=newCPE;
	}
	
	public String cpe(){
		return cpe;
	}
	
	public String toString(){
		String versioninfo="";
		if(!version.logicalUnitComment().equals("")) versioninfo=" ("+version.logicalUnitComment()+")";
		return name+" "+version+versioninfo;
	}
	
	public String trimmedVersion(){
		return trimVersion(version.getText());
	}
	
	private String trimVersion (String version){
		if(version.contains(" "))version=version.substring(0, version.indexOf(" "));
		version=version.trim();
		if(version.length()>1 && version.substring(version.length()-2).equals(".x"))version=version.substring(0, version.length()-2);
		else if(version.length()>1 && version.substring(version.length()-2).equals(".0"))version=version.substring(0, version.length()-2);
		return version;
	}
	
	public boolean refersSameSoftware(NameVersionRelation otherRel){
		return name().getText().equalsIgnoreCase(otherRel.name().getText());
	}
	
	public boolean versionIsMoreGeneral(NameVersionRelation otherRel){
		if(otherRel.version().getText().contains(trimmedVersion())) return true;
		else return false;
	}
	
	public boolean equals (NameVersionRelation otherRelation){
		return this.hashCode()==otherRelation.hashCode();
	}
	@Override
	public int hashCode (){
		return (name.getText()+trimmedVersion()).hashCode();
	}

	@Override
	public int compareTo(NameVersionRelation otherNVR) {	
	    if (otherNVR.version().getText() == null && this.version().getText() == null) {
	        return 0;
	      }
	      if (this.version().getText() == null) {
	        return 1;
	      }
	      if (otherNVR.version().getText() == null) {
	        return -1;
	      }
	      CharSequence version = this.version().getText();
	      CharSequence otherVersion = otherNVR.version().getText();
	      Character versionCharater;
	      Character otherVersionCharacter;
	      for (int i = 0; i<version.length() && i<otherVersion.length() ; i++){
	    	  versionCharater=new Character(version.charAt(i));
	    	  otherVersionCharacter= new Character(otherVersion.charAt(i));// Was passiert mit 4.10.3 und 4.9.0 ?
	    	  // Checken, ob "." kleiner oder größer als "a" bzw. "A" ist.
	    	  if(versionCharater.compareTo(otherVersionCharacter)!=0) return versionCharater.compareTo(otherVersionCharacter);
	      }
	      if(version.length()==otherVersion.length()) return 0;
	      if(version.length()<otherVersion.length()) return -1;
	      else return 1;
	}
	
	
}
