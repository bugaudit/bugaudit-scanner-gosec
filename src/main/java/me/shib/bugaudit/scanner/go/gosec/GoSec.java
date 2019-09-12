package me.shib.bugaudit.scanner.go.gosec;

public class GoSec {
    private int severity;
    private int confidence;
    private int rank;
    private String details;
    private String file;
    private String code;
    private String line;
    private String instanceHash;

    public int getRank() {
        return rank;
    }

    public int getSeverity() {
        return severity;
    }

    public int getConfidence() {
        return confidence;
    }

    public String getDetails() {
        return details;
    }

    public String getFile() {
        return file;
    }

    public String getCode() {
        return code;
    }

    public String getLine() {
        return line;
    }

    public String getInstanceHash() {
        return instanceHash;
    }

    public void setRank(int rank) {
        this.rank = rank;
    }

    public void setSeverity(String severity) {
        if(severity.equalsIgnoreCase("High"))
            this.severity = 1;
        else if(severity.equalsIgnoreCase("Medium"))
            this.severity = 2;
        else if(severity.equalsIgnoreCase("Low"))
            this.severity = 3;
    }

    public void setConfidence(String confidence) {
        if(confidence.equalsIgnoreCase("High"))
            this.confidence = 1;
        else if(confidence.equalsIgnoreCase("Medium"))
            this.confidence = 2;
        else if(confidence.equalsIgnoreCase("Low"))
            this.confidence = 3;


    }

    public void setDetails(String details) {
        this.details = details;
    }

    public void setFile(String file) {
        this.file = file;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public void setLine(String line) {
        this.line = line;
    }

    public void setInstanceHash(String instanceHash) {
        this.instanceHash = instanceHash;
    }
}
