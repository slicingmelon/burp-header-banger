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
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class ProxyHandler implements ProxyRequestHandler, ProxyResponseHandler {
    private final BurpHeaderBanger extension;
    private final MontoyaApi api;
    private final AuditIssueBuilder auditIssueCreator;
    private final ScheduledExecutorService scheduler;
    private final CollaboratorClient collaboratorClient;
    private final Map<String, PayloadCorrelation> payloadMap;
    private final Map<String, Long> requestTimestamps;
    private final String collaboratorServerLocation;

    public ProxyHandler(BurpHeaderBanger extension, MontoyaApi api, AuditIssueBuilder auditIssueCreator, 
                       ScheduledExecutorService scheduler, CollaboratorClient collaboratorClient, 
                       Map<String, PayloadCorrelation> payloadMap, Map<String, Long> requestTimestamps) {
        this.extension = extension;
        this.api = api;
        this.auditIssueCreator = auditIssueCreator;
        this.scheduler = scheduler;
        this.collaboratorClient = collaboratorClient;
        this.payloadMap = payloadMap;
        this.requestTimestamps = requestTimestamps;
        
        // Initialize collaborator server location
        if (collaboratorClient != null) {
            this.collaboratorServerLocation = collaboratorClient.generatePayload().toString();
        } else {
            this.collaboratorServerLocation = null;
        }
        
        // Register interaction handler for direct collaborator interaction processing
        if (extension.getCollaboratorClient() != null) {
            // TODO: Implement direct interaction handler here
            // This will search proxy history when interactions occur
        }
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        if (!extension.isExtensionActive()) {
            return ProxyRequestReceivedAction.continueWith(interceptedRequest);
        }

        HttpRequest request = interceptedRequest;
        
        // Skip modification for requests going to the collaborator server
        if (collaboratorServerLocation != null && request.url().contains("oastify.com")) {
            api.logging().logToOutput("Skipping collaborator request: " + request.url());
            return ProxyRequestReceivedAction.continueWith(interceptedRequest);
        }
        
        // Check if only processing in-scope items
        if (extension.isOnlyInScopeItems() && !api.scope().isInScope(request.url())) {
            return ProxyRequestReceivedAction.continueWith(interceptedRequest);
        }

        // Check if host should be skipped
        String host = request.httpService().host();
        if (extension.getSkipHosts().contains(host)) {
            return ProxyRequestReceivedAction.continueWith(interceptedRequest);
        }

        // Modify request headers
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
        
        // Launch separate scan for sensitive headers
        scheduler.execute(() -> processSensitiveHeadersScan(interceptedResponse));

        return ProxyResponseReceivedAction.continueWith(interceptedResponse);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
        return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
    }

    private HttpRequest modifyRequestHeaders(HttpRequest request) {
        if (extension.getAttackMode() == 2) {
            return injectUniqueXssPayloads(request);
        } else {
            return injectSqlInjectionPayloads(request);
        }
    }

    private HttpRequest injectUniqueXssPayloads(HttpRequest request) {
        HttpRequest workingRequest = request;
        
        api.logging().logToOutput("Injecting XSS payloads for request: " + request.url());
        api.logging().logToOutput("XSS - Headers to process: " + extension.getHeaders());
        api.logging().logToOutput("XSS - Headers count: " + extension.getHeaders().size());
        
        for (String headerName : extension.getHeaders()) {
            api.logging().logToOutput("XSS - Processing header: " + headerName);
            
            String finalPayload;
            String payloadDomain = null;
            
            // Check if payload uses collaborator tracking
            if (extension.getBxssPayload().contains("{{collaborator}}")) {
                // Generate collaborator payload and do tracking
                CollaboratorPayload collabPayload = collaboratorClient.generatePayload();
                payloadDomain = collabPayload.toString();
                String currentPayload = extension.getBxssPayload().replace("{{collaborator}}", payloadDomain);
                
                if ("User-Agent".equalsIgnoreCase(headerName)) {
                    // User-Agent: Mozilla + payload
                    finalPayload = "Mozilla" + currentPayload;
                } else if ("Origin".equalsIgnoreCase(headerName) || "Referer".equalsIgnoreCase(headerName)) {
                    // Origin & Referer: If exists, append payload to original value, else just payload
                    String existingValue = request.headerValue(headerName);
                    if (existingValue != null) {
                        finalPayload = existingValue + currentPayload;
                    } else {
                        finalPayload = currentPayload;
                    }
                } else {
                    // All other headers: If exists, append payload to current value, else just payload
                    String existingValue = request.headerValue(headerName);
                    if (existingValue != null) {
                        finalPayload = existingValue + currentPayload;
                    } else {
                        finalPayload = currentPayload;
                    }
                }
                
                // Create and store correlation for collaborator tracking
                PayloadCorrelation correlation = new PayloadCorrelation(request.url(), headerName, request.method());
                payloadMap.put(payloadDomain, correlation);
                
                api.logging().logToOutput("XSS - Added payload to map: " + payloadDomain + " -> " + headerName + " for " + request.url());
            } else {
                // Custom payload without collaborator - no tracking needed
                String currentPayload = extension.getBxssPayload();
                
                if ("User-Agent".equalsIgnoreCase(headerName)) {
                    // User-Agent: Mozilla + payload
                    finalPayload = "Mozilla" + currentPayload;
                } else if ("Origin".equalsIgnoreCase(headerName) || "Referer".equalsIgnoreCase(headerName)) {
                    // Origin & Referer: If exists, append payload to original value, else just payload
                    String existingValue = request.headerValue(headerName);
                    if (existingValue != null) {
                        finalPayload = existingValue + currentPayload;
                    } else {
                        finalPayload = currentPayload;
                    }
                } else {
                    // All other headers: If exists, append payload to current value, else just payload
                    String existingValue = request.headerValue(headerName);
                    if (existingValue != null) {
                        finalPayload = existingValue + currentPayload;
                    } else {
                        finalPayload = currentPayload;
                    }
                }
                
                api.logging().logToOutput("XSS - Using custom payload (no collaborator tracking): " + headerName);
            }

            // Remove existing header first, then add new one
            workingRequest = workingRequest.withRemovedHeader(headerName);
            workingRequest = workingRequest.withAddedHeader(headerName, finalPayload);
            
            api.logging().logToOutput("XSS - Added header: " + headerName + " = " + finalPayload);
        }
        
        // Add extra headers using the proper API method
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
                api.logging().logToOutput("XSS - Added extra header: " + headerName + " = " + headerValue);
            }
        }
        
        // Debug: Show final request headers after all processing
        api.logging().logToOutput("XSS - Final request headers (" + workingRequest.headers().size() + " total):");
        for (HttpHeader header : workingRequest.headers()) {
            api.logging().logToOutput("  " + header.name() + ": " + header.value());
        }
        
        return workingRequest;
    }
    
    private HttpRequest injectSqlInjectionPayloads(HttpRequest request) {
        HttpRequest workingRequest = request;
        
        api.logging().logToOutput("Injecting SQL injection payloads for request: " + request.url());
        api.logging().logToOutput("Headers to process: " + extension.getHeaders());
        api.logging().logToOutput("Headers count: " + extension.getHeaders().size());
        
        // Process ALL headers from the Headers list (both existing and non-existing)
        for (String headerName : extension.getHeaders()) {
            api.logging().logToOutput("Processing header: " + headerName);
            
            // SQL injection payloads never use collaborator tracking
            String currentPayload = extension.getSqliPayload();
            String finalPayload;
            
            if ("User-Agent".equalsIgnoreCase(headerName)) {
                // User-Agent: Mozilla + payload
                finalPayload = "Mozilla" + currentPayload;
            } else if ("Origin".equalsIgnoreCase(headerName) || "Referer".equalsIgnoreCase(headerName)) {
                // Origin & Referer: If exists, append payload to original value, else just payload
                String existingValue = request.headerValue(headerName);
                if (existingValue != null) {
                    finalPayload = existingValue + currentPayload;
                } else {
                    finalPayload = currentPayload;
                }
            } else {
                // All other headers: If exists, append payload to current value, else just payload
                String existingValue = request.headerValue(headerName);
                if (existingValue != null) {
                    finalPayload = existingValue + currentPayload;
                } else {
                    finalPayload = currentPayload;
                }
            }
            
            api.logging().logToOutput("SQLi - Using payload (no collaborator tracking): " + headerName);
            
            // Remove existing header first, then add new one
            workingRequest = workingRequest.withRemovedHeader(headerName);
            workingRequest = workingRequest.withAddedHeader(headerName, finalPayload);
            
            api.logging().logToOutput("SQLi - Added header: " + headerName + " = " + finalPayload);
        }
        
        // Add extra headers using the proper API method
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

    private void processSensitiveHeadersScan(InterceptedResponse interceptedResponse) {
        HttpRequest originalRequest = interceptedResponse.initiatingRequest();
        
        api.logging().logToOutput("Processing sensitive headers scan for: " + originalRequest.url());
        
        // Get host value
        String hostValue = getHeaderValue(originalRequest.headers(), "Host");
        if (hostValue == null) {
            api.logging().logToOutput("No Host header found, skipping sensitive headers scan");
            return;
        }

        if (extension.getAttackMode() == 2) {
            // BXSS logic for sensitive headers
            HttpRequest workingRequest = originalRequest;
            
            for (String sensitiveHeader : extension.getSensitiveHeaders()) {
                String finalPayload;
                String payloadDomain = null;
                
                // Check if payload uses collaborator tracking
                if (extension.getBxssPayload().contains("{{collaborator}}")) {
                    // Generate collaborator payload and do tracking
                    CollaboratorPayload collabPayload = collaboratorClient.generatePayload();
                    payloadDomain = collabPayload.toString();
                    String currentPayload = extension.getBxssPayload().replace("{{collaborator}}", payloadDomain);
                    
                    if ("Origin".equalsIgnoreCase(sensitiveHeader)) {
                        // Origin: If exists, append payload to its value, else Host header value + payload
                        String existingValue = originalRequest.headerValue(sensitiveHeader);
                        if (existingValue != null) {
                            finalPayload = existingValue + currentPayload;
                        } else {
                            finalPayload = hostValue + currentPayload;
                        }
                    } else {
                        // All other sensitive headers: If exists, append payload to existing value, else Host header value + payload
                        String existingValue = originalRequest.headerValue(sensitiveHeader);
                        if (existingValue != null) {
                            finalPayload = existingValue + currentPayload;
                        } else {
                            finalPayload = hostValue + currentPayload;
                        }
                    }
                    
                    // Store correlation for collaborator tracking
                    PayloadCorrelation correlation = new PayloadCorrelation(originalRequest.url(), sensitiveHeader, originalRequest.method());
                    payloadMap.put(payloadDomain, correlation);
                    
                    api.logging().logToOutput("XSS - Added sensitive header payload to map: " + payloadDomain + " -> " + sensitiveHeader);
                } else {
                    // Custom payload without collaborator - no tracking needed
                    String currentPayload = extension.getBxssPayload();
                    
                    if ("Origin".equalsIgnoreCase(sensitiveHeader)) {
                        // Origin: If exists, append payload to its value, else Host header value + payload
                        String existingValue = originalRequest.headerValue(sensitiveHeader);
                        if (existingValue != null) {
                            finalPayload = existingValue + currentPayload;
                        } else {
                            finalPayload = hostValue + currentPayload;
                        }
                    } else {
                        // All other sensitive headers: If exists, append payload to existing value, else Host header value + payload
                        String existingValue = originalRequest.headerValue(sensitiveHeader);
                        if (existingValue != null) {
                            finalPayload = existingValue + currentPayload;
                        } else {
                            finalPayload = hostValue + currentPayload;
                        }
                    }
                    
                    api.logging().logToOutput("XSS - Using custom payload for sensitive header (no collaborator tracking): " + sensitiveHeader);
                }
                
                // Remove existing header first, then add new one
                workingRequest = workingRequest.withRemovedHeader(sensitiveHeader);
                workingRequest = workingRequest.withAddedHeader(sensitiveHeader, finalPayload);
                
                api.logging().logToOutput("XSS - Added sensitive header: " + sensitiveHeader + " = " + finalPayload);
            }
            
            // Add extra headers
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
                }
            }
            
            api.http().sendRequest(workingRequest);
            return;
        }
        
        // SQL injection logic for sensitive headers
        HttpRequest workingRequest = originalRequest;
        
        for (String sensitiveHeader : extension.getSensitiveHeaders()) {
            // SQL injection payloads might use collaborator for out-of-band attacks (LOAD_FILE, xp_cmdshell, etc.)
            String currentPayload = extension.getSqliPayload();
            
            String finalPayload;
            if ("Origin".equalsIgnoreCase(sensitiveHeader)) {
                // Origin: If exists, append payload to its value, else Host header value + payload
                String existingValue = originalRequest.headerValue(sensitiveHeader);
                if (existingValue != null) {
                    finalPayload = existingValue + currentPayload;
                } else {
                    finalPayload = hostValue + currentPayload;
                }
            } else {
                // All other sensitive headers: If exists, append payload to existing value, else Host header value + payload
                String existingValue = originalRequest.headerValue(sensitiveHeader);
                if (existingValue != null) {
                    finalPayload = existingValue + currentPayload;
                } else {
                    finalPayload = hostValue + currentPayload;
                }
            }
            
            // Remove existing header first, then add new one
            workingRequest = workingRequest.withRemovedHeader(sensitiveHeader);
            workingRequest = workingRequest.withAddedHeader(sensitiveHeader, finalPayload);
            
            api.logging().logToOutput("SQLi - Added sensitive header: " + sensitiveHeader + " = " + finalPayload);
        }
        
        // Add extra headers
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
            }
        }
        
        try {
            long startTime = System.currentTimeMillis();
            var response = api.http().sendRequest(workingRequest);
            long responseTime = System.currentTimeMillis() - startTime;
            
            api.logging().logToOutput("SQLi sensitive headers - Response time: " + responseTime + " ms (manual timing)");
            
            // Only check timing if timing-based detection is enabled
            if (extension.isTimingBasedDetectionEnabled() && responseTime >= extension.getSqliSleepTime() * 1000) {
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