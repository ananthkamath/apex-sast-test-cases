public class VulnerableClass {
    // Violates specify-sharing-level rule by not specifying sharing mode
    
    static {
        // Violates apex-csrf-static-constructor rule
        Account acc = new Account(Name = 'Test Account');
        insert acc;
    }
    
    public VulnerableClass() {
        // Violates apex-csrf-constructor rule
        Account acc = new Account(Name = 'Test Account');
        insert acc;
    }
    
    public void insecureHttpCall() {
        // Violates insecure-http-request rule
        HttpRequest req = new HttpRequest();
        req.setEndpoint('http://insecure-endpoint.com');
    }
    
    public void hardcodedCredentials() {
        // Violates named-credentials-string-match rule
        HttpRequest req = new HttpRequest();
        req.setHeader('Authorization', 'Basic dXNlcm5hbWU6cGFzc3dvcmQ=');
    }
    
    public void soqlInjection(String userInput) {
        // Violates soql-injection-unescaped-param rule
        Database.query('SELECT Id FROM Account WHERE Name = \'' + userInput + '\'');
    }
    
    public void badCrypto() {
        // Violates bad-crypto rule
        Blob hardcodedKey = Blob.valueOf('0000000000000000');
        Blob hardcodedIV = Blob.valueOf('1234567890123456');
        Blob data = Blob.valueOf('Sensitive Data');
        Blob encrypted = Crypto.encrypt('AES128', hardcodedKey, hardcodedIV, data);
    }
    
    public void debugLogging() {
        // Violates system-debug rule
        System.debug('Sensitive information being logged');
    }
    
    public void nativeDML() {
        // Violates dml-native-statements rule
        Account acc = new Account(Name = 'Test Account');
        insert acc;
    }
}