package slicingmelon.burpheaderbanger;

import java.util.regex.Pattern;

public class Exclusion {
    private boolean enabled;
    private String pattern;
    private boolean isRegex;
    private transient Pattern compiledPattern;
    
    public Exclusion(boolean enabled, String pattern, boolean isRegex) {
        this.enabled = enabled;
        this.pattern = pattern;
        this.isRegex = isRegex;
        compilePattern();
    }
    
    public Exclusion() {
        this(true, "", false);
    }
    
    public boolean isEnabled() {
        return enabled;
    }
    
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    
    public String getPattern() {
        return pattern;
    }
    
    public void setPattern(String pattern) {
        this.pattern = pattern;
        compilePattern();
    }
    
    public boolean isRegex() {
        return isRegex;
    }
    
    public void setRegex(boolean isRegex) {
        this.isRegex = isRegex;
        compilePattern();
    }
    
    private void compilePattern() {
        if (isRegex && pattern != null && !pattern.isEmpty()) {
            try {
                this.compiledPattern = Pattern.compile(pattern);
            } catch (Exception e) {
                this.compiledPattern = null;
            }
        } else {
            this.compiledPattern = null;
        }
    }
    
    public boolean matches(String input) {
        if (!enabled || pattern == null || pattern.isEmpty()) {
            return false;
        }
        
        if (isRegex) {
            if (compiledPattern == null) {
                return false;
            }
            return compiledPattern.matcher(input).find();
        } else {
            return input.contains(pattern);
        }
    }
    
    @Override
    public String toString() {
        return (enabled ? "✓" : "✗") + " " + pattern + (isRegex ? " (regex)" : "");
    }
    
    // For JSON serialization
    public String toJson() {
        return String.format("{\"enabled\":%s,\"pattern\":\"%s\",\"isRegex\":%s}", 
                enabled, pattern.replace("\"", "\\\""), isRegex);
    }
    
    // For JSON deserialization
    public static Exclusion fromJson(String json) {
        try {
            json = json.trim();
            if (json.startsWith("{") && json.endsWith("}")) {
                json = json.substring(1, json.length() - 1);
            }
            
            boolean enabled = true;
            String pattern = "";
            boolean isRegex = false;
            
            String[] parts = json.split(",");
            for (String part : parts) {
                part = part.trim();
                if (part.startsWith("\"enabled\":")) {
                    enabled = Boolean.parseBoolean(part.substring(10));
                } else if (part.startsWith("\"pattern\":\"")) {
                    pattern = part.substring(11, part.length() - 1).replace("\\\"", "\"");
                } else if (part.startsWith("\"isRegex\":")) {
                    isRegex = Boolean.parseBoolean(part.substring(10));
                }
            }
            
            return new Exclusion(enabled, pattern, isRegex);
        } catch (Exception e) {
            return new Exclusion();
        }
    }
} 