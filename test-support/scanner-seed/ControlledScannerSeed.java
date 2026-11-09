import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import javax.swing.*;
import java.awt.BorderLayout;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/** TEST ONLY. Never loaded by preparation. No network, audit, scope or MCP APIs. */
public final class ControlledScannerSeed implements BurpExtension {
    public static final String PREFIX="MCPB-20261107-155141";
    public static final String ALLOWED="http://127.0.0.1:8000/test-post";
    public static final String EXCLUDED="http://127.0.0.1:8000/";
    public record Attachment(String path,String marker,boolean binary) {}
    public record Definition(String marker,String root,List<Attachment> attachments) {}
    private final AtomicBoolean attempted=new AtomicBoolean();
    public static List<Definition> definitions() {
        return List.of(
            new Definition(PREFIX+"-ALLOW-A",ALLOWED+"?p%61ssword="+PREFIX+"-CRED-URL",
                List.of(new Attachment("/test-post",PREFIX+"-ALLOW-ATTACH",true),new Attachment("/",PREFIX+"-EXCLUDED-ATTACH",false))),
            new Definition(PREFIX+"-EXCLUDED-ROOT",EXCLUDED,List.of(new Attachment("/",PREFIX+"-EXCLUDED-ROOT-BODY",false))),
            new Definition(PREFIX+"-ALLOW-B",ALLOWED,List.of(new Attachment("/test-post",PREFIX+"-ALLOW-B-ATTACH",false))));
    }
    @Override public void initialize(MontoyaApi api) {
        api.extension().setName("TEST ONLY - "+PREFIX+" controlled Scanner records");
        JPanel panel=new JPanel(new BorderLayout());
        JTextArea info=new JTextArea("Not seeded. Loading only registers this panel.\n"
            +"Separate approval required before Seed. Creates exactly 3 synthetic audit issues, 0 HTTP requests.\n"
            +"No Scanner audit, scope change, grant, session or interception.\n"
            +"Unloading does NOT delete findings. Remove ONLY these 3 named synthetic issues manually after approval.\n");
        info.setEditable(false);panel.add(info,BorderLayout.CENTER);
        JButton button=new JButton("Seed exactly three "+PREFIX+" issues (separate approval required)");
        panel.add(button,BorderLayout.SOUTH);
        button.addActionListener(event->{
            if(attempted.get())return;
            int choice=JOptionPane.showConfirmDialog(panel,"Create only the three reviewed synthetic "+PREFIX
                +" audit records?\n0 network requests. No scope or Scanner engine changes.\n"
                +"Cleanup requires manual removal of only the three owned issue names.","Controlled synthetic seed",JOptionPane.YES_NO_OPTION);
            if(choice!=JOptionPane.YES_OPTION)return;
            if(!attempted.compareAndSet(false,true))return;
            button.setEnabled(false);
            try {
                if(!api.scope().isInScope(ALLOWED)||api.scope().isInScope(EXCLUDED))throw new IllegalStateException("Scope gate failed");
                if(api.siteMap().issues().stream().anyMatch(i->i.name()!=null&&i.name().contains(PREFIX)))
                    throw new IllegalStateException("Owned markers already exist; no reseeding");
                HttpService service=HttpService.httpService("127.0.0.1",8000,false);
                List<AuditIssue> prepared=new ArrayList<>();
                for(Definition d:definitions()) {
                    List<HttpRequestResponse> pairs=new ArrayList<>();
                    for(Attachment a:d.attachments()) {
                        String request="GET "+a.path()+" HTTP/1.1\r\nHost: 127.0.0.1:8000\r\n"
                            +"X-MCP-B-Case: "+a.marker()+"\r\nAuthorization: Bearer SYNTHETIC_ONLY\r\n"
                            +"Cookie: mcp_test=SYNTHETIC_ONLY\r\nContent-Length: 0\r\n\r\n";
                        String body=a.binary()?"\u0000\u0001\u0002\u0003":a.marker();
                        String response="HTTP/1.1 200 OK password="+PREFIX+"-CRED-REASON\r\nContent-Type: "
                            +(a.binary()?"application/octet-stream":"text/plain")+"; password="+PREFIX+"-CRED-META\r\n"
                            +"X-MCP-B-Case: "+a.marker()+"\r\nContent-Length: "+body.getBytes(StandardCharsets.UTF_8).length+"\r\n\r\n"+body;
                        pairs.add(HttpRequestResponse.httpRequestResponse(HttpRequest.httpRequest(service,request),HttpResponse.httpResponse(response)));
                    }
                    prepared.add(AuditIssue.auditIssue(d.marker()+" password="+PREFIX+"-CRED-NAME",
                        d.marker()+" detail password="+PREFIX+"-CRED-DETAIL",
                        "Synthetic remediation password="+PREFIX+"-CRED-REMEDIATION",d.root(),
                        AuditIssueSeverity.INFORMATION,AuditIssueConfidence.CERTAIN,
                        "Synthetic background password="+PREFIX+"-CRED-BACKGROUND",
                        "Synthetic remediation background password="+PREFIX+"-CRED-REMEDIATION-BG",
                        AuditIssueSeverity.INFORMATION,pairs));
                }
                int added=0;
                for(AuditIssue issue:prepared){api.siteMap().add(issue);added++;}
                long owned=api.siteMap().issues().stream().filter(i->i.name()!=null&&i.name().contains(PREFIX)).count();
                info.append("Registration calls="+added+"; observed owned issues="+owned+".\n");
                info.append("Expected ALLOW-A, EXCLUDED-ROOT, ALLOW-B; confirm each locally before Batch B.\n");
                api.logging().logToOutput(PREFIX+" registration calls="+added+" owned count="+owned);
            } catch(Exception error) {
                info.append("STOP: "+error.getClass().getSimpleName()+"; inspect only owned markers. No retry. Partial registration possible.\n");
                api.logging().logToError(PREFIX+" failed: "+error.getClass().getSimpleName());
            }
        });
        api.userInterface().registerSuiteTab("Controlled B seed (TEST)",panel);
    }
}
