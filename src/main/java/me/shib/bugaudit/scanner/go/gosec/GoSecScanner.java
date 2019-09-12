package me.shib.bugaudit.scanner.go.gosec;

import me.shib.bugaudit.commons.BugAuditContent;
import me.shib.bugaudit.scanner.Bug;
import me.shib.bugaudit.scanner.BugAuditScanResult;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import me.shib.bugaudit.commons.BugAuditException;
import me.shib.bugaudit.scanner.BugAuditScanner;
import me.shib.bugaudit.scanner.Lang;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public final class GoSecScanner extends BugAuditScanner {

    private static transient final Lang lang = Lang.GoLang;
    private static transient final String tool = "GoSec";

    private BugAuditScanResult result;

    public GoSecScanner() throws BugAuditException {
        super();
        this.getBugAuditScanResult().addKey("SAST-Warning");
        this.result = getBugAuditScanResult();
    }

    private Integer getRank(int severity, int confidence) {
        Integer[][] severityMatrix = {
                {1, 1, 2},
                {1, 2, 3},
                {2, 3, 3}
        };

        return severityMatrix[severity-1][confidence-1];
    }

    private void runGoSec() throws IOException, InterruptedException {
        System.out.println("Running GoSec");

        String command = "gosec -fmt=json -out=results.json ./...";
        String goSecResponse = runCommand(command);
    }

    private List<GoSec> parseFromJsonResult() throws IOException, ParseException {
        List<GoSec> issueList = new ArrayList<GoSec>();

        JSONParser jsonParser = new JSONParser();
        FileReader reader = new FileReader("results.json");  //Needs to be changed
        Object obj = jsonParser.parse(reader);

        JSONObject jo = (JSONObject) obj;

        JSONArray ja = (JSONArray) jo.get("Issues");

        for(Object o : ja)
        {
            GoSec goSecObject = new GoSec();

            JSONObject issue = (JSONObject) o;
            goSecObject.setSeverity((String)issue.get("severity"));
            goSecObject.setConfidence((String) issue.get("confidence"));
            goSecObject.setRank(getRank(goSecObject.getSeverity(),goSecObject.getConfidence()));
            goSecObject.setDetails((String) issue.get("details"));
            goSecObject.setFile((String) issue.get("file"));
            goSecObject.setCode((String) issue.get("code"));
            goSecObject.setLine((String) issue.get("line"));
            goSecObject.setInstanceHash(Double.toString(Math.random()));   //Need to be handled

            issueList.add(goSecObject);
        }

        return issueList;
    }

    public String getDescription(GoSec issue) {
        StringBuilder description = new StringBuilder();

        description.append("The following insecure code bugs were found in ").append("**[").append(issue.getFile()).append("](").append(this.getBugAuditScanResult().getRepo().getWebUrl()).append("/tree/").append(this.getBugAuditScanResult().getRepo().getCommit()).append("/").append(issue.getFile()).append("):**\n");
        description.append(" * **Line:** ").append(issue.getLine()).append("\n");
        description.append(" * **Type:** ");
        description.append(issue.getDetails());
        description.append("\n");
        description.append(" * **Confidence:** ").append(issue.getSeverity());

        return description.toString();
    }

    private void addKeys(Bug bug, GoSec findBugs) throws BugAuditException {
        bug.addKey(findBugs.getFile());
        bug.addKey(getBugAuditScanResult().getRepo() + "-" + findBugs.getInstanceHash());
    }

    private void parseGoSecResult() throws BugAuditException, IOException, ParseException {
       List<GoSec> issueList = parseFromJsonResult();

       for(GoSec issue : issueList){
           String title = "GoSec (" + issue.getDetails() + ") found in " + issue.getFile() + getBugAuditScanResult().getRepo();
           Bug bug = new Bug(title,issue.getSeverity());
           bug.setDescription(new BugAuditContent(this.getDescription(issue)));
           bug.addType(issue.getDetails().replace(" ", "-"));
           addKeys(bug, issue);
           result.addBug(bug);
       }
    }

    @Override
    protected Lang getLang() {
        return lang;
    }

    @Override
    public String getTool() {
        return tool;
    }

    @Override
    public void scan() throws Exception {
        if (!isParserOnly()) {
            runGoSec();
        }
        parseGoSecResult();
    }
}
