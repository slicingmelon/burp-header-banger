package slicingmelon.burpheaderbanger;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.ArrayList;
import java.util.List;

public class AuditIssueBuilder {
    private final BurpHeaderBanger extension;
    private final MontoyaApi api;

    public AuditIssueBuilder(BurpHeaderBanger extension, MontoyaApi api) {
        this.extension = extension;
        this.api = api;
    }

    public void createSqlInjectionIssue(InterceptedResponse interceptedResponse, long responseTime) {
        api.logging().logToOutput("POSSIBLE SQL INJECTION DETECTED!");
        api.logging().logToOutput("═══════════════════════════════════════════════════════════");
        api.logging().logToOutput("Attack Vector: SQL injection via regular headers");
        api.logging().logToOutput("URL: " + interceptedResponse.request().url());
        api.logging().logToOutput("Response Time: " + responseTime + " ms");
        api.logging().logToOutput("Expected Sleep Time: " + extension.getSqliSleepTime() + " seconds");
        api.logging().logToOutput("Detected: " + new java.util.Date());
        
        // Create proper audit issue using the original request with injected headers
        try {
            // Use the initiating request that contains the SQL injection payloads
            HttpRequestResponse evidenceRequestResponse = HttpRequestResponse.httpRequestResponse(
                interceptedResponse.initiatingRequest(),
                interceptedResponse
            );
            
            // Get markers for the SQL injection payload in request and response
            List<Marker> requestMarkers = getRequestMarkersForSqli(interceptedResponse.initiatingRequest(), extension.getSqliPayload());
            List<Marker> responseMarkers = getResponseMarkers(evidenceRequestResponse, extension.getSqliPayload());
            
            HttpRequestResponse markedEvidence = evidenceRequestResponse;
            if (!requestMarkers.isEmpty()) {
                markedEvidence = markedEvidence.withRequestMarkers(requestMarkers);
            }
            if (!responseMarkers.isEmpty()) {
                markedEvidence = markedEvidence.withResponseMarkers(responseMarkers);
            }
            
            AuditIssue issue = AuditIssue.auditIssue(
                "Time-based SQL Injection via Headers",
                "Time-based SQL injection vulnerability detected through header injection. The application "
                + "responded with a delay of " + responseTime + " ms, which suggests that the injected "
                + "time-based SQL payload was executed. This indicates that user input is being directly "
                + "incorporated into SQL queries without proper sanitization. "
                + "Payload: " + extension.getSqliPayload(),
                "Fix this vulnerability by properly validating and sanitizing all user input, especially in HTTP headers. "
                + "Implement proper input validation and use parameterized queries to prevent SQL injection attacks.",
                interceptedResponse.request().url(),
                AuditIssueSeverity.HIGH,
                AuditIssueConfidence.FIRM,
                "This vulnerability allows attackers to execute arbitrary SQL commands on the database server, "
                + "potentially leading to data theft, data manipulation, or complete system compromise.",
                "The application processes user-controlled header values without proper validation or sanitization, "
                + "allowing SQL injection attacks through HTTP header injection.",
                AuditIssueSeverity.HIGH,
                markedEvidence
            );
            
            api.siteMap().add(issue);
            api.logging().logToOutput("Audit issue created successfully: Time-based SQL Injection via Headers");
        } catch (Exception e) {
            api.logging().logToError("Failed to create SQL injection audit issue: " + e.getMessage());
        }
        
        api.logging().logToOutput("═══════════════════════════════════════════════════════════");
    }

    public void createSensitiveHeaderSqlIssue(HttpRequestResponse response, long responseTime) {
        api.logging().logToOutput("POSSIBLE SQL INJECTION VIA SENSITIVE HEADERS DETECTED!");
        api.logging().logToOutput("═══════════════════════════════════════════════════════════");
        api.logging().logToOutput("Attack Vector: SQL injection via sensitive headers");
        api.logging().logToOutput("  • URL: " + response.request().url());
        api.logging().logToOutput("  • Response Time: " + responseTime + " ms");
        api.logging().logToOutput("  • Expected Sleep Time: " + extension.getSqliSleepTime() + " seconds");
        api.logging().logToOutput("Detected: " + new java.util.Date());
        
        // Create proper audit issue using the original request with injected headers
        try {
            // Get markers for the SQL injection payload in request and response
            List<Marker> requestMarkers = getRequestMarkersForSqli(response.request(), extension.getSqliPayload());
            List<Marker> responseMarkers = getResponseMarkers(response, extension.getSqliPayload());
            
            // Add markers to the evidence
            HttpRequestResponse markedEvidence = response;
            if (!requestMarkers.isEmpty()) {
                markedEvidence = markedEvidence.withRequestMarkers(requestMarkers);
            }
            if (!responseMarkers.isEmpty()) {
                markedEvidence = markedEvidence.withResponseMarkers(responseMarkers);
            }
            
            AuditIssue issue = AuditIssue.auditIssue(
                "Time-based SQL Injection via Sensitive Headers",
                "Time-based SQL injection vulnerability detected through sensitive header injection. The application "
                + "responded with a delay of " + responseTime + " ms, which suggests that the injected "
                + "time-based SQL payload was executed. This indicates that user input from sensitive headers is being "
                + "directly incorporated into SQL queries without proper sanitization. "
                + "Payload: " + extension.getSqliPayload(),
                "Fix this vulnerability by properly validating and sanitizing all user input, especially in HTTP headers. "
                + "Implement proper input validation and use parameterized queries to prevent SQL injection attacks.",
                response.request().url(),
                AuditIssueSeverity.HIGH,
                AuditIssueConfidence.FIRM,
                "This vulnerability allows attackers to execute arbitrary SQL commands on the database server, "
                + "potentially leading to data theft, data manipulation, or complete system compromise.",
                "The application processes user-controlled header values without proper validation or sanitization, "
                + "allowing SQL injection attacks through HTTP header injection.",
                AuditIssueSeverity.HIGH,
                markedEvidence
            );
            
            api.siteMap().add(issue);
            api.logging().logToOutput("Audit issue created successfully: Time-based SQL Injection via Sensitive Headers");
        } catch (Exception e) {
            api.logging().logToError("Failed to create SQL injection audit issue: " + e.getMessage());
        }
        
        api.logging().logToOutput("═══════════════════════════════════════════════════════════");
    }

    public void createXssIssue(Interaction interaction, PayloadCorrelation correlation) {
        api.logging().logToOutput("XSS VULNERABILITY CONFIRMED!");
        api.logging().logToOutput("Attack Vector: Header injection via " + correlation.headerName);
        api.logging().logToOutput("URL: " + correlation.requestUrl);
        api.logging().logToOutput("Method: " + correlation.requestMethod);
        api.logging().logToOutput("Impact: Cross-Site Scripting (XSS) execution detected");
        api.logging().logToOutput("Detected: " + new java.util.Date());
        api.logging().logToOutput("Interaction ID: " + interaction.id());
        
        // Find the original request from proxy history using interaction ID
        String interactionId = interaction.id().toString();
        List<burp.api.montoya.proxy.ProxyHttpRequestResponse> proxyHistory = api.proxy().history(
            requestResponse -> requestResponse.finalRequest().toString().contains(interactionId)
        );
        
        if (!proxyHistory.isEmpty()) {
            // Use the first matching request from proxy history
            burp.api.montoya.proxy.ProxyHttpRequestResponse originalRequestResponse = proxyHistory.get(0);
            
            try {
                // Create audit issue using the original request/response from proxy history
                HttpRequestResponse evidenceRequestResponse = HttpRequestResponse.httpRequestResponse(
                    originalRequestResponse.finalRequest(), 
                    originalRequestResponse.originalResponse()
                );
                
                // Get markers for the XSS payload in request (response markers not needed for blind XSS)
                String collaboratorDomain = interaction.id().toString();
                List<Marker> requestMarkers = getRequestMarkersForHeader(originalRequestResponse.finalRequest(), correlation.headerName, collaboratorDomain);
                
                // Add markers to the evidence
                HttpRequestResponse markedEvidence = evidenceRequestResponse;
                if (!requestMarkers.isEmpty()) {
                    markedEvidence = markedEvidence.withRequestMarkers(requestMarkers);
                }
                
                AuditIssue issue = AuditIssue.auditIssue(
                    "Header Injection XSS via " + correlation.headerName,
                    "Cross-Site Scripting (XSS) vulnerability detected through header injection in the " 
                    + correlation.headerName + " header. The payload was successfully executed as confirmed by "
                    + "collaborator interaction " + interaction.id() + ". This allows attackers to inject arbitrary "
                    + "JavaScript code that will be executed in the context of other users' browsers. "
                    + "Collaborator domain: " + collaboratorDomain,
                    "Fix this vulnerability by properly validating and sanitizing all user input, especially in HTTP headers. "
                    + "Implement proper output encoding when reflecting user-controlled data in responses.",
                    originalRequestResponse.finalRequest().url(),
                    AuditIssueSeverity.HIGH,
                    AuditIssueConfidence.CERTAIN,
                    "This vulnerability allows attackers to execute arbitrary JavaScript in the victim's browser, "
                    + "potentially leading to session hijacking, defacement, or other malicious activities.",
                    "The application reflects user-controlled header values without proper validation or encoding, "
                    + "allowing XSS attacks through HTTP header injection.",
                    AuditIssueSeverity.HIGH,
                    markedEvidence
                );
                
                api.siteMap().add(issue);
                api.logging().logToOutput("Audit issue created successfully: Header Injection XSS via " + correlation.headerName);
            } catch (Exception e) {
                api.logging().logToError("Failed to create audit issue: " + e.getMessage());
            }
        } else {
            api.logging().logToOutput("Could not find original request in proxy history for interaction: " + interactionId);
            
            // Fallback to creating a new request
            try {
                HttpRequest issueRequest = HttpRequest.httpRequestFromUrl(correlation.requestUrl);
                HttpRequestResponse issueRequestResponse = api.http().sendRequest(issueRequest);
                
                // Get markers for the XSS payload in request (response markers not needed for blind XSS)
                String collaboratorDomain = interaction.id().toString();
                List<Marker> requestMarkers = getRequestMarkersForHeader(issueRequest, correlation.headerName, collaboratorDomain);
                
                // Add markers to the evidence
                HttpRequestResponse markedEvidence = issueRequestResponse;
                if (!requestMarkers.isEmpty()) {
                    markedEvidence = markedEvidence.withRequestMarkers(requestMarkers);
                }
                
                AuditIssue issue = AuditIssue.auditIssue(
                    "Header Injection XSS via " + correlation.headerName,
                    "Cross-Site Scripting (XSS) vulnerability detected through header injection in the " 
                    + correlation.headerName + " header. The payload was successfully executed as confirmed by "
                    + "collaborator interaction " + interaction.id() + ". This allows attackers to inject arbitrary "
                    + "JavaScript code that will be executed in the context of other users' browsers. "
                    + "Collaborator domain: " + collaboratorDomain,
                    "Fix this vulnerability by properly validating and sanitizing all user input, especially in HTTP headers. "
                    + "Implement proper output encoding when reflecting user-controlled data in responses.",
                    correlation.requestUrl,
                    AuditIssueSeverity.HIGH,
                    AuditIssueConfidence.CERTAIN,
                    "This vulnerability allows attackers to execute arbitrary JavaScript in the victim's browser, "
                    + "potentially leading to session hijacking, defacement, or other malicious activities.",
                    "The application reflects user-controlled header values without proper validation or encoding, "
                    + "allowing XSS attacks through HTTP header injection.",
                    AuditIssueSeverity.HIGH,
                    markedEvidence
                );
                
                api.siteMap().add(issue);
                api.logging().logToOutput("Audit issue created successfully (fallback): Header Injection XSS via " + correlation.headerName);
            } catch (Exception e) {
                api.logging().logToError("Failed to create fallback audit issue: " + e.getMessage());
            }
        }
    }

    private List<Marker> getResponseMarkers(HttpRequestResponse requestResponse, String payload) {
        List<Marker> markers = new ArrayList<>();
        
        if (requestResponse.response() == null) {
            return markers;
        }
        
        String responseString = requestResponse.response().toString();
        
        // Search for the payload in the response
        int start = 0;
        while (start < responseString.length()) {
            int found = responseString.indexOf(payload, start);
            if (found == -1) {
                break;
            }
            
            markers.add(Marker.marker(found, found + payload.length()));
            start = found + payload.length();
        }
        
        // If no direct payload found, look for parts of it (like the sleep function)
        if (markers.isEmpty()) {
            start = 0;
            while (start < responseString.length()) {
                int found = responseString.indexOf("sleep(", start);
                if (found == -1) {
                    break;
                }
                
                // Try to find the end of the sleep function call
                int end = found + 6; // "sleep(" length
                while (end < responseString.length() && responseString.charAt(end) != ')') {
                    end++;
                }
                if (end < responseString.length()) {
                    end++; // Include the closing parenthesis
                    markers.add(Marker.marker(found, end));
                }
                start = end;
            }
        }
        
        return markers;
    }

    private List<Marker> getRequestMarkersForHeader(HttpRequest request, String headerName, String payload) {
        List<Marker> markers = new ArrayList<>();
        
        String requestString = request.toString();
        String[] lines = requestString.split("\r\n");
        
        // Find the header line that contains the specified header name and payload
        int currentPosition = 0;
        for (String line : lines) {
            if (line.toLowerCase().startsWith(headerName.toLowerCase() + ":") && line.contains(payload)) {
                // Mark the entire header line
                int lineStart = currentPosition;
                int lineEnd = currentPosition + line.length();
                markers.add(Marker.marker(lineStart, lineEnd));
                api.logging().logToOutput("Marked header line: " + line);
                break;
            }
            currentPosition += line.length() + 2; // +2 for \r\n
        }
        
        // If no header line found, fall back to the old method
        if (markers.isEmpty()) {
            return getRequestMarkers(request, payload);
        }
        
        return markers;
    }

    private List<Marker> getRequestMarkersForSqli(HttpRequest request, String payload) {
        List<Marker> markers = new ArrayList<>();
        
        String requestString = request.toString();
        String[] lines = requestString.split("\r\n");
        
        // Find all header lines that contain the SQL payload
        int currentPosition = 0;
        for (String line : lines) {
            if (line.contains(":") && line.contains(payload) && !line.startsWith("Host:")) {
                // Mark the entire header line that contains the payload
                int lineStart = currentPosition;
                int lineEnd = currentPosition + line.length();
                markers.add(Marker.marker(lineStart, lineEnd));
                api.logging().logToOutput("Marked SQL injection header line: " + line);
            }
            currentPosition += line.length() + 2; // +2 for \r\n
        }
        
        // If no header lines found, fall back to the old method
        if (markers.isEmpty()) {
            return getRequestMarkers(request, payload);
        }
        
        return markers;
    }

    private List<Marker> getRequestMarkers(HttpRequest request, String payload) {
        List<Marker> markers = new ArrayList<>();
        
        String requestString = request.toString();
        
        // Search for the payload in the request
        int start = 0;
        while (start < requestString.length()) {
            int found = requestString.indexOf(payload, start);
            if (found == -1) {
                break;
            }
            
            markers.add(Marker.marker(found, found + payload.length()));
            start = found + payload.length();
        }
        
        return markers;
    }
} 