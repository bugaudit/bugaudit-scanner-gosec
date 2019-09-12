package me.shib.bugaudit.scanner.go.gosec;

import me.shib.bugaudit.commons.BugAuditException;
import me.shib.bugaudit.scanner.BugAuditScanner;
import me.shib.bugaudit.scanner.Lang;

import java.io.IOException;

public final class GoSecScanner extends BugAuditScanner {

    private static transient final Lang lang = Lang.GoLang;
    private static transient final String tool = "GoSec";

    public GoSecScanner() throws BugAuditException {
        super();
        this.getBugAuditScanResult().addKey("SAST-Warning");
    }

    private void parseBundlerAuditResult() throws BugAuditException, IOException {
        //TODO Parse Logic
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
            //TODO Scan Logic
        }
        parseBundlerAuditResult();
    }
}
