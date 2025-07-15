package slicingmelon.burpheaderbanger;

public class PayloadCorrelation {
    public final String requestUrl;
    public final String headerName;
    public final String requestMethod;
    public final long timestamp;

    public PayloadCorrelation(String requestUrl, String headerName, String requestMethod) {
        this.requestUrl = requestUrl;
        this.headerName = headerName;
        this.requestMethod = requestMethod;
        this.timestamp = System.currentTimeMillis();
    }
} 