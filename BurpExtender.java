package burp;

import java.io.PrintWriter;
import java.net.URL;
import java.net.MalformedURLException;

public class BurpExtender implements IBurpExtender, IHttpListener {
    private IExtensionHelpers helpers;
    private PrintWriter stderr;
    private PrintWriter stdout;
    private IBurpExtenderCallbacks callbacks;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;

        callbacks.setExtensionName("Hello world extension");

        // obtain our output and error streams
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        helpers = callbacks.getHelpers();

        // write a message to our output stream
        stdout.println("Hello output");

        // write a message to our error stream
        stderr.println("Hello errors");

        // write a message to the Burp alerts tab
        callbacks.issueAlert("Hello alerts");
        callbacks.registerHttpListener(this);

        try {
            byte[] req = helpers.buildHttpRequest(new URL("http://www.columbia.edu/~fdc/sample.html"));
            byte[] resp = callbacks.makeHttpRequest("www.columbia.edu", 80, false, req);

            stdout.println(helpers.bytesToString(req));
            stdout.println(helpers.bytesToString(resp));
        } catch (MalformedURLException e) {
            stdout.println("Malformed: " + e);
        }
    }



    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        stdout.println(
                (messageIsRequest ? "HTTP request to " : "HTTP response from ") +
                        messageInfo.getHttpService() +
                        " [" + callbacks.getToolName(toolFlag) + "]");
        IRequestInfo resp = helpers.analyzeRequest(messageInfo);
        //stdout.println(helpers.analyzeResponseKeywords(resp.getHeaders(), 0
        //stdout.println("Whew lad");
    }

}
