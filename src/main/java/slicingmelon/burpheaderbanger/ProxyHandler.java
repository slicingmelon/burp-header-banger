package slicingmelon.burpheaderbanger;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledExecutorService;

public class ProxyHandler implements ProxyRequestHandler, ProxyResponseHandler {
    private final BurpHeaderBanger extension;
    private final MontoyaApi api;
    private final AuditIssueBuilder auditIssueCreator;
    private final ScheduledExecutorService scheduler;
    private final CollaboratorClient collaboratorClient;
    private final Map<String, Long> requestTimestamps;
    private final String collaboratorServerLocation;
    
    // Store original clean requests for sensitive headers scan
    private final Map<String, HttpRequest> originalRequests = new ConcurrentHashMap<>();

    public ProxyHandler(BurpHeaderBanger extension, MontoyaApi api, AuditIssueBuilder auditIssueCreator, 
                       ScheduledExecutorService scheduler, CollaboratorClient collaboratorClient, 
                       Map<String, Long> requestTimestamps) {
        this.extension = extension;
        this.api = api;
        this.auditIssueCreator = auditIssueCreator;
        this.scheduler = scheduler;
        this.collaboratorClient = collaboratorClient;
        this.requestTimestamps = requestTimestamps;
        
        // Initialize collaborator server location
        if (collaboratorClient != null) {
            this.collaboratorServerLocation = collaboratorClient.generatePayload().toString();
        } else {
            this.collaboratorServerLocation = null;
        }

    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        if (!extension.isExtensionActive()) {
            return ProxyRequestReceivedAction.continueWith(interceptedRequest);
        }

        HttpRequest request = interceptedRequest;
        String host = request.httpService().host();
        String url = request.url();
        api.logging().logToOutput("[ProxyHandler] Checking exclusion for host: " + host + ", url: " + url);
        
        // Skip modification for requests going to the collaborator server
        if (collaboratorServerLocation != null && request.url().contains("oastify.com")) {
            api.logging().logToOutput("Skipping collaborator request: " + request.url());
            return ProxyRequestReceivedAction.continueWith(interceptedRequest);
        }
        
        // Check if only processing in-scope items
        if (extension.isOnlyInScopeItems() && !api.scope().isInScope(request.url())) {
            return ProxyRequestReceivedAction.continueWith(interceptedRequest);
        }

        // Check if host or URL should be excluded
        if (extension.isExcluded(url, host)) {
            api.logging().logToOutput("[ProxyHandler] Skipping request due to exclusion for host: " + host + ", url: " + url);
            return ProxyRequestReceivedAction.continueWith(interceptedRequest);
        }

        // Store original clean request for later sensitive headers scan
        String requestKey = request.url();
        originalRequests.put(requestKey, request);
        api.logging().logToOutput("Stored original clean request for sensitive headers scan: " + requestKey);

        // Modify request headers (only regular headers for proxy traffic)
        HttpRequest modifiedRequest = modifyRequestHeaders(request);
        
        // NOTE: Timestamp is now stored in handleRequestToBeSent() to exclude intercept delays
        return ProxyRequestReceivedAction.continueWith(modifiedRequest);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        if (!extension.isExtensionActive()) {
            return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
        }
        
        // Store timestamp for SQL injection timing detection (excludes intercept delays)
        if (extension.getAttackMode() == 1 && extension.isTimingBasedDetectionEnabled()) {
            String requestKey = interceptedRequest.url();
            requestTimestamps.put(requestKey, System.currentTimeMillis());
            api.logging().logToOutput("Stored timestamp for SQL injection timing: " + requestKey);
        }
        
        return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
        if (!extension.isExtensionActive()) {
            return ProxyResponseReceivedAction.continueWith(interceptedResponse);
        }

        // Skip responses from collaborator server
        if (collaboratorServerLocation != null && interceptedResponse.request().url().contains(collaboratorServerLocation)) {
            api.logging().logToOutput("Skipping collaborator response from: " + interceptedResponse.request().url());
            return ProxyResponseReceivedAction.continueWith(interceptedResponse);
        }

        // Process response for SQL injection detection
        if (extension.getAttackMode() == 1) {
            processResponseForSqli(interceptedResponse);
        }
        
        // Now trigger sensitive headers scan using stored original clean request
        String requestKey = interceptedResponse.request().url();
        HttpRequest originalCleanRequest = originalRequests.remove(requestKey);
        if (originalCleanRequest != null) {
            scheduler.execute(() -> processSensitiveHeadersScan(originalCleanRequest));
            api.logging().logToOutput("Triggered sensitive headers scan for: " + requestKey);
        } else {
            api.logging().logToOutput("No stored original request found for sensitive headers scan: " + requestKey);
        }

        return ProxyResponseReceivedAction.continueWith(interceptedResponse);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
        return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
    }

    private HttpRequest modifyRequestHeaders(HttpRequest request) {
        // Only apply regular headers for proxy traffic
        HttpRequest workingRequest;
        if (extension.getAttackMode() == 2) {
            workingRequest = applyHeadersWithPayload(request, extension.getHeaders(), extension.getBxssPayload(), false);
        } else {
            workingRequest = applyHeadersWithPayload(request, extension.getHeaders(), extension.getSqliPayload(), false);
        }
        
        // Add extra headers
        return addExtraHeaders(workingRequest);
    }

    /**
     * Reusable method to apply headers with payload logic
     * @param request Original request
     * @param headersList List of headers to inject
     * @param payload Payload to inject
     * @param isForSensitiveHeaders Whether this is for sensitive headers (affects host value logic)
     * @return Modified request with headers applied
     */
    private HttpRequest applyHeadersWithPayload(HttpRequest request, List<String> headersList, String payload, boolean isForSensitiveHeaders) {
        HttpRequest workingRequest = request;
        String hostValue = null;
        
        // Get host value if needed for sensitive headers
        if (isForSensitiveHeaders) {
            hostValue = getHeaderValue(request.headers(), "Host");
        }
        
        api.logging().logToOutput("Applying headers with payload for request: " + request.url());
        api.logging().logToOutput("Headers to process: " + headersList);
        api.logging().logToOutput("Headers count: " + headersList.size());
        
        for (String headerName : headersList) {
            api.logging().logToOutput("Processing header: " + headerName);
            
            String finalPayload;
            
            // Check if payload uses collaborator tracking (only for BXSS)
            if (extension.getAttackMode() == 2 && payload.contains("{{collaborator}}")) {
                // Generate collaborator payload
                CollaboratorPayload collabPayload = collaboratorClient.generatePayload();
                String payloadDomain = collabPayload.toString();
                String currentPayload = payload.replace("{{collaborator}}", payloadDomain);
                
                finalPayload = buildFinalPayload(request, headerName, currentPayload, hostValue, isForSensitiveHeaders);
                api.logging().logToOutput("Using collaborator payload for header: " + headerName + " with domain: " + payloadDomain);
            } else {
                // No collaborator tracking
                finalPayload = buildFinalPayload(request, headerName, payload, hostValue, isForSensitiveHeaders);
                api.logging().logToOutput("Using payload (no collaborator tracking): " + headerName);
            }

            // Remove existing header first, then add new one
            workingRequest = workingRequest.withRemovedHeader(headerName);
            workingRequest = workingRequest.withAddedHeader(headerName, finalPayload);
            
            api.logging().logToOutput("Added header: " + headerName + " = " + finalPayload);
        }
        
        return workingRequest;
    }

    /**
     * Build the final payload for a header based on the header type and context
     */
    private String buildFinalPayload(HttpRequest request, String headerName, String payload, String hostValue, boolean isForSensitiveHeaders) {
        String existingValue = request.headerValue(headerName);
        
        if ("User-Agent".equalsIgnoreCase(headerName)) {
            // User-Agent: Mozilla + payload
            return "Mozilla" + payload;
        } else if ("Origin".equalsIgnoreCase(headerName) || "Referer".equalsIgnoreCase(headerName)) {
            // Origin & Referer: If exists, append payload to original value, else use appropriate default
            if (existingValue != null) {
                return existingValue + payload;
            } else if (isForSensitiveHeaders && hostValue != null) {
                // For sensitive headers, use host value as base
                return hostValue + payload;
            } else {
                return payload;
            }
        } else {
            // All other headers: If exists, append payload to current value, else use appropriate default
            if (existingValue != null) {
                return existingValue + payload;
            } else if (isForSensitiveHeaders && hostValue != null && 
                      (headerName.toLowerCase().contains("host") || headerName.toLowerCase().contains("server"))) {
                // For sensitive headers that are host-related, use host value as base
                return hostValue + payload;
            } else {
                return payload;
            }
        }
    }

    /**
     * Add extra headers to the request
     */
    private HttpRequest addExtraHeaders(HttpRequest request) {
        HttpRequest workingRequest = request;
        
        for (String extraHeader : extension.getExtraHeaders()) {
            String[] parts = extraHeader.split(":", 2);
            if (parts.length == 2) {
                String headerName = parts[0].trim();
                String headerValue = parts[1].trim();
                
                if (!extension.isAllowDuplicateHeaders()) {
                    if (workingRequest.hasHeader(headerName)) {
                        continue; // Skip if header already exists and duplicates not allowed
                    }
                }
                
                workingRequest = workingRequest.withAddedHeader(headerName, headerValue);
                api.logging().logToOutput("Added extra header: " + headerName + " = " + headerValue);
            }
        }
        
        return workingRequest;
    }

    private void processResponseForSqli(InterceptedResponse interceptedResponse) {
        // Check if timing-based detection is disabled
        if (!extension.isTimingBasedDetectionEnabled()) {
            api.logging().logToOutput("Timing-based SQL injection detection is disabled");
            return;
        }
        
        // Check content type
        String contentType = getHeaderValue(interceptedResponse.headers(), "Content-Type");
        if (contentType != null) {
            String[] parts = contentType.split(";");
            if (parts.length > 0) {
                String mimeType = parts[0].trim().toLowerCase();
                if (BurpHeaderBanger.SKIP_CONTENT_TYPES.contains(mimeType)) {
                    return;
                }
            }
        }

        // NOTE: Timing measurement now excludes intercept delays by using handleRequestToBeSent()
        // This provides more accurate timing for blind SQL injection detection
        String requestKey = interceptedResponse.request().url();
        Long startTime = requestTimestamps.get(requestKey);
        if (startTime != null) {
            long responseTime = System.currentTimeMillis() - startTime;
            requestTimestamps.remove(requestKey);
            
            // Log timing information for debugging
            api.logging().logToOutput("SQL injection timing check - Response time: " + responseTime + " ms, threshold: " + (extension.getSqliSleepTime() * 1000) + " ms");
            
            if (responseTime >= extension.getSqliSleepTime() * 1000) {
                api.logging().logToOutput("TIMING-BASED SQL INJECTION DETECTED (Server response time: " + responseTime + " ms)");
                auditIssueCreator.createSqlInjectionIssue(interceptedResponse, responseTime);
            }
        }
    }

    private void processSensitiveHeadersScan(HttpRequest originalRequest) {
        String host = originalRequest.httpService().host();
        String url = originalRequest.url();
        
        api.logging().logToOutput("Processing sensitive headers scan for: " + url);
        
        // Check if host or URL should be excluded from sensitive headers scan
        if (extension.isExcluded(url, host)) {
            api.logging().logToOutput("[SensitiveHeaders] Skipping sensitive headers scan due to exclusion for host: " + host + ", url: " + url);
            return;
        }
        
        // Get host value
        String hostValue = getHeaderValue(originalRequest.headers(), "Host");
        if (hostValue == null) {
            api.logging().logToOutput("No Host header found, skipping sensitive headers scan");
            return;
        }

        // Start with original request and apply both regular headers + sensitive headers cleanly
        HttpRequest workingRequest = originalRequest;
        
        // Apply regular headers first
        if (extension.getAttackMode() == 2) {
            workingRequest = applyHeadersWithPayload(workingRequest, extension.getHeaders(), extension.getBxssPayload(), false);
        } else {
            workingRequest = applyHeadersWithPayload(workingRequest, extension.getHeaders(), extension.getSqliPayload(), false);
        }
        
        // Apply sensitive headers
        if (extension.getAttackMode() == 2) {
            workingRequest = applyHeadersWithPayload(workingRequest, extension.getSensitiveHeaders(), extension.getBxssPayload(), true);
        } else {
            workingRequest = applyHeadersWithPayload(workingRequest, extension.getSensitiveHeaders(), extension.getSqliPayload(), true);
        }
        
        // Add extra headers
        workingRequest = addExtraHeaders(workingRequest);
        
        api.logging().logToOutput("Sensitive headers scan: Applied " + extension.getHeaders().size() + " regular headers + " + 
                                extension.getSensitiveHeaders().size() + " sensitive headers");

        try {
            long startTime = System.currentTimeMillis();
            var response = api.http().sendRequest(workingRequest);
            long responseTime = System.currentTimeMillis() - startTime;
            
            api.logging().logToOutput("Sensitive headers scan - Response time: " + responseTime + " ms (manual timing)");
            
            // Only check timing if timing-based detection is enabled and in SQL injection mode
            if (extension.getAttackMode() == 1 && extension.isTimingBasedDetectionEnabled() && 
                responseTime >= extension.getSqliSleepTime() * 1000) {
                api.logging().logToOutput("TIMING-BASED SQL INJECTION DETECTED in sensitive headers (Server response time: " + responseTime + " ms)");
                auditIssueCreator.createSensitiveHeaderSqlIssue(response, responseTime);
            }
        } catch (Exception e) {
            api.logging().logToError("Error sending sensitive headers request: " + e.getMessage());
        }
    }

    private String getHeaderValue(List<HttpHeader> headers, String headerName) {
        for (HttpHeader header : headers) {
            if (header.name().equalsIgnoreCase(headerName)) {
                return header.value();
            }
        }
        return null;
    }

} 