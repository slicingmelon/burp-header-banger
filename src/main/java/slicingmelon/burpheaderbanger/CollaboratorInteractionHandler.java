package slicingmelon.burpheaderbanger;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.InteractionHandler;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.ArrayList;
import java.util.List;

public class CollaboratorInteractionHandler implements InteractionHandler {
    private final MontoyaApi api;
    private final BurpHeaderBanger extension;

    public CollaboratorInteractionHandler(MontoyaApi api, BurpHeaderBanger extension) {
        this.api = api;
        this.extension = extension;
    }

    @Override
    public void handleInteraction(Interaction interaction) {
        api.logging().logToOutput("═══════════════════════════════════════════════════════════");
        api.logging().logToOutput("XSS INTERACTION DETECTED!");
        api.logging().logToOutput("Interaction ID: " + interaction.id().toString());
        api.logging().logToOutput("Interaction Type: " + interaction.type().name());
        api.logging().logToOutput("Detected: " + new java.util.Date());

        // Search proxy history for requests containing this interaction ID
        List<ProxyHttpRequestResponse> matchingRequests = api.proxy().history(
            requestResponse -> requestResponse.finalRequest().toString().contains(interaction.id().toString())
        );

        api.logging().logToOutput("Found " + matchingRequests.size() + " matching requests in proxy history");

        // Create audit issues for each matching request
        for (ProxyHttpRequestResponse proxyRequest : matchingRequests) {
            createXssAuditIssue(interaction, proxyRequest);
        }

        api.logging().logToOutput("═══════════════════════════════════════════════════════════");
    }

    private void createXssAuditIssue(Interaction interaction, ProxyHttpRequestResponse proxyRequest) {
        try {
            String interactionId = interaction.id().toString();
            String requestUrl = proxyRequest.finalRequest().url();
            
            // Determine which header contained the payload by searching the request
            String affectedHeader = findAffectedHeader(proxyRequest.finalRequest().toString(), interactionId);
            
            api.logging().logToOutput("Creating XSS audit issue:");
            api.logging().logToOutput("  • URL: " + requestUrl);
            api.logging().logToOutput("  • Affected Header: " + affectedHeader);
            api.logging().logToOutput("  • Interaction ID: " + interactionId);

            // Create the audit issue evidence
            HttpRequestResponse evidence = HttpRequestResponse.httpRequestResponse(
                proxyRequest.finalRequest(),
                proxyRequest.originalResponse()
            );

            // Add markers to highlight the payload in the request
            List<Marker> requestMarkers = findPayloadMarkers(proxyRequest.finalRequest().toString(), interactionId);
            if (!requestMarkers.isEmpty()) {
                evidence = evidence.withRequestMarkers(requestMarkers);
            }

            // Create the audit issue
            AuditIssue issue = AuditIssue.auditIssue(
                "Header Injection XSS via " + affectedHeader,
                "Cross-Site Scripting (XSS) vulnerability detected through header injection in the " 
                + affectedHeader + " header. The payload was successfully executed as confirmed by "
                + "collaborator interaction " + interaction.id() + ". This allows attackers to inject arbitrary "
                + "JavaScript code that will be executed in the context of other users' browsers.",
                "Fix this vulnerability by properly validating and sanitizing all user input, especially in HTTP headers. "
                + "Implement proper output encoding when reflecting user-controlled data in responses.",
                requestUrl,
                AuditIssueSeverity.HIGH,
                AuditIssueConfidence.CERTAIN,
                "This vulnerability allows attackers to execute arbitrary JavaScript in the victim's browser, "
                + "potentially leading to session hijacking, defacement, or other malicious activities.",
                "The application reflects user-controlled header values without proper validation or encoding, "
                + "allowing XSS attacks through HTTP header injection.",
                AuditIssueSeverity.HIGH,
                evidence
            );

            // Add to Burp's site map
            api.siteMap().add(issue);
            api.logging().logToOutput("✅ XSS audit issue created successfully for header: " + affectedHeader);

        } catch (Exception e) {
            api.logging().logToError("❌ Failed to create XSS audit issue: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private String findAffectedHeader(String requestString, String interactionId) {
        String[] lines = requestString.split("\r\n");
        
        for (String line : lines) {
            if (line.contains(":") && line.contains(interactionId)) {
                String headerName = line.split(":")[0].trim();
                return headerName;
            }
        }
        
        return "Unknown Header";
    }

    private List<Marker> findPayloadMarkers(String requestString, String interactionId) {
        List<Marker> markers = new ArrayList<>();
        
        // Find all occurrences of the interaction ID in the request
        int start = 0;
        while (start < requestString.length()) {
            int found = requestString.indexOf(interactionId, start);
            if (found == -1) {
                break;
            }
            
            markers.add(Marker.marker(found, found + interactionId.length()));
            start = found + interactionId.length();
        }
        
        return markers;
    }
} 