package org.cysecurity.cspf.jvl.controller;

import junit.framework.TestCase;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;

/**
 * Tests to verify that SQL injection vulnerabilities (CWE-89) in servlet
 * controllers have been remediated by replacing vulnerable plain Statement +
 * string-concatenation patterns with parameterized PreparedStatement queries.
 *
 * Affected files:
 *   - LoginValidator.java  (login authentication query)
 *   - EmailCheck.java      (email availability check query)
 *   - UsernameCheck.java   (username availability check query)
 *   - Register.java        (user registration INSERT statements)
 *
 * The fix replaces:
 *   Statement stmt = con.createStatement();
 *   stmt.executeQuery("SELECT ... WHERE field='" + userInput + "'");
 *
 * With the safe equivalent:
 *   PreparedStatement pstmt = con.prepareStatement("SELECT ... WHERE field=?");
 *   pstmt.setString(1, userInput);
 *   pstmt.executeQuery();
 */
public class SqlInjectionRemediationTest extends TestCase {

    // -------------------------------------------------------------------------
    // LoginValidator.java tests
    // -------------------------------------------------------------------------

    /**
     * Verifies that LoginValidator.java imports PreparedStatement and
     * not the vulnerable plain Statement class.
     */
    public void testLoginValidatorImportsPreparedStatement() throws Exception {
        File src = findSourceFile("LoginValidator.java");
        assertNotNull("LoginValidator.java must be locatable", src);
        String content = readFile(src);

        assertTrue(
            "LoginValidator.java must import java.sql.PreparedStatement",
            content.contains("import java.sql.PreparedStatement"));

        assertFalse(
            "LoginValidator.java must not import java.sql.Statement (replaced by PreparedStatement)",
            content.contains("import java.sql.Statement"));
    }

    /**
     * Verifies that LoginValidator.java uses a parameterized query with '?'
     * placeholders for both username and password fields.
     */
    public void testLoginValidatorUsesParameterizedQuery() throws Exception {
        File src = findSourceFile("LoginValidator.java");
        assertNotNull("LoginValidator.java must be locatable", src);
        String content = readFile(src);

        assertTrue(
            "LoginValidator.java must use PreparedStatement",
            content.contains("PreparedStatement"));

        assertTrue(
            "LoginValidator.java must use '?' placeholder for username parameter",
            content.contains("username=?"));

        assertTrue(
            "LoginValidator.java must use '?' placeholder for password parameter",
            content.contains("password=?"));

        assertTrue(
            "LoginValidator.java must call setString() to bind username",
            content.contains("setString"));
    }

    /**
     * Verifies that the classic SQL injection bypass payload cannot be
     * introduced via string concatenation in LoginValidator.java.
     * The vulnerable pattern ' OR '1'='1 works only if user input is
     * concatenated directly into the query.
     */
    public void testLoginValidatorDoesNotConcatenateUserInput() throws Exception {
        File src = findSourceFile("LoginValidator.java");
        assertNotNull("LoginValidator.java must be locatable", src);
        String content = readFile(src);

        assertFalse(
            "LoginValidator.java must not concatenate 'user' into SQL query string",
            content.contains("'\"+" + "user+\"'") ||
            content.contains("username='\"+" + "user") ||
            content.contains("\"+'\"+" + "user"));

        assertFalse(
            "LoginValidator.java must not concatenate 'pass' into SQL query string",
            content.contains("password='\"+" + "pass") ||
            content.contains("\"+'\"+" + "pass"));

        assertFalse(
            "LoginValidator.java must not use createStatement() for authentication query",
            content.contains("createStatement()"));
    }

    // -------------------------------------------------------------------------
    // EmailCheck.java tests
    // -------------------------------------------------------------------------

    /**
     * Verifies that EmailCheck.java imports PreparedStatement and
     * not the vulnerable plain Statement class.
     */
    public void testEmailCheckImportsPreparedStatement() throws Exception {
        File src = findSourceFile("EmailCheck.java");
        assertNotNull("EmailCheck.java must be locatable", src);
        String content = readFile(src);

        assertTrue(
            "EmailCheck.java must import java.sql.PreparedStatement",
            content.contains("import java.sql.PreparedStatement"));

        assertFalse(
            "EmailCheck.java must not import java.sql.Statement (replaced by PreparedStatement)",
            content.contains("import java.sql.Statement"));
    }

    /**
     * Verifies that EmailCheck.java uses a parameterized query with a '?'
     * placeholder for the email field.
     */
    public void testEmailCheckUsesParameterizedQuery() throws Exception {
        File src = findSourceFile("EmailCheck.java");
        assertNotNull("EmailCheck.java must be locatable", src);
        String content = readFile(src);

        assertTrue(
            "EmailCheck.java must use PreparedStatement",
            content.contains("PreparedStatement"));

        assertTrue(
            "EmailCheck.java SQL query must use '?' placeholder",
            content.contains("email=?"));

        assertTrue(
            "EmailCheck.java must call setString() to bind the email parameter",
            content.contains("setString"));
    }

    /**
     * Verifies that the vulnerable string-concatenation pattern has been
     * removed from EmailCheck.java.
     */
    public void testEmailCheckDoesNotConcatenateEmailInput() throws Exception {
        File src = findSourceFile("EmailCheck.java");
        assertNotNull("EmailCheck.java must be locatable", src);
        String content = readFile(src);

        assertFalse(
            "EmailCheck.java must not concatenate 'email' into SQL query string",
            content.contains("email='\"+" + "email") ||
            content.contains("where email='\""));

        assertFalse(
            "EmailCheck.java must not use createStatement() for the email check query",
            content.contains("createStatement()"));
    }

    /**
     * Verifies that a UNION-based SQL injection payload in the email parameter
     * would be treated as a literal string value when PreparedStatement is used.
     */
    public void testEmailCheckUnionInjectionPayloadNotConcatenated() throws Exception {
        File src = findSourceFile("EmailCheck.java");
        assertNotNull("EmailCheck.java must be locatable", src);
        String content = readFile(src);

        // UNION attacks require the payload to be concatenated into the query
        assertFalse(
            "Vulnerable concatenation pattern '+ email +' must not exist in EmailCheck.java",
            content.contains("+ email +") || content.contains("+ email\""));

        assertTrue(
            "Safe PreparedStatement + setString pattern must be present in EmailCheck.java",
            content.contains("prepareStatement") && content.contains("setString"));
    }

    // -------------------------------------------------------------------------
    // UsernameCheck.java tests
    // -------------------------------------------------------------------------

    /**
     * Verifies that UsernameCheck.java imports PreparedStatement and
     * not the vulnerable plain Statement class.
     */
    public void testUsernameCheckImportsPreparedStatement() throws Exception {
        File src = findSourceFile("UsernameCheck.java");
        assertNotNull("UsernameCheck.java must be locatable", src);
        String content = readFile(src);

        assertTrue(
            "UsernameCheck.java must import java.sql.PreparedStatement",
            content.contains("import java.sql.PreparedStatement"));

        assertFalse(
            "UsernameCheck.java must not import java.sql.Statement (replaced by PreparedStatement)",
            content.contains("import java.sql.Statement"));
    }

    /**
     * Verifies that UsernameCheck.java uses a parameterized query with a '?'
     * placeholder for the username field.
     */
    public void testUsernameCheckUsesParameterizedQuery() throws Exception {
        File src = findSourceFile("UsernameCheck.java");
        assertNotNull("UsernameCheck.java must be locatable", src);
        String content = readFile(src);

        assertTrue(
            "UsernameCheck.java must use PreparedStatement",
            content.contains("PreparedStatement"));

        assertTrue(
            "UsernameCheck.java SQL query must use '?' placeholder",
            content.contains("username=?"));

        assertTrue(
            "UsernameCheck.java must call setString() to bind the username parameter",
            content.contains("setString"));
    }

    /**
     * Verifies that the vulnerable string-concatenation pattern has been
     * removed from UsernameCheck.java.
     */
    public void testUsernameCheckDoesNotConcatenateUsernameInput() throws Exception {
        File src = findSourceFile("UsernameCheck.java");
        assertNotNull("UsernameCheck.java must be locatable", src);
        String content = readFile(src);

        assertFalse(
            "UsernameCheck.java must not concatenate 'user' into SQL query string",
            content.contains("username='\"+" + "user") ||
            content.contains("where username='\""));

        assertFalse(
            "UsernameCheck.java must not use createStatement() for the username check query",
            content.contains("createStatement()"));
    }

    /**
     * Verifies that a tautology injection payload (' OR '1'='1) in the username
     * parameter would be treated as a literal value and not alter query logic.
     */
    public void testUsernameCheckTautologyInjectionPayloadNotConcatenated() throws Exception {
        File src = findSourceFile("UsernameCheck.java");
        assertNotNull("UsernameCheck.java must be locatable", src);
        String content = readFile(src);

        // Tautology attacks require the payload to be concatenated into the query
        assertFalse(
            "Vulnerable concatenation pattern '+ user +' must not exist in UsernameCheck.java",
            content.contains("+ user +") || content.contains("+ user\""));

        assertTrue(
            "Safe PreparedStatement + setString pattern must be present in UsernameCheck.java",
            content.contains("prepareStatement") && content.contains("setString"));
    }

    // -------------------------------------------------------------------------
    // Register.java tests
    // -------------------------------------------------------------------------

    /**
     * Verifies that Register.java imports PreparedStatement and
     * not the vulnerable plain Statement class.
     */
    public void testRegisterImportsPreparedStatement() throws Exception {
        File src = findSourceFile("Register.java");
        assertNotNull("Register.java must be locatable", src);
        String content = readFile(src);

        assertTrue(
            "Register.java must import java.sql.PreparedStatement",
            content.contains("import java.sql.PreparedStatement"));

        assertFalse(
            "Register.java must not import java.sql.Statement (replaced by PreparedStatement)",
            content.contains("import java.sql.Statement"));
    }

    /**
     * Verifies that Register.java uses PreparedStatement with '?' placeholders
     * for the user registration INSERT queries.
     */
    public void testRegisterUsesParameterizedInsertForUsers() throws Exception {
        File src = findSourceFile("Register.java");
        assertNotNull("Register.java must be locatable", src);
        String content = readFile(src);

        assertTrue(
            "Register.java must use PreparedStatement for user INSERT",
            content.contains("PreparedStatement"));

        assertTrue(
            "Register.java must use '?' placeholders in INSERT query",
            content.contains("?"));

        assertTrue(
            "Register.java must call setString() to bind user registration parameters",
            content.contains("setString"));
    }

    /**
     * Verifies that Register.java does not concatenate any user-supplied input
     * into the INSERT SQL query strings.
     */
    public void testRegisterDoesNotConcatenateUserInputIntoInsert() throws Exception {
        File src = findSourceFile("Register.java");
        assertNotNull("Register.java must be locatable", src);
        String content = readFile(src);

        assertFalse(
            "Register.java must not concatenate 'user' directly into INSERT SQL string",
            content.contains("values ('\"+" + "user") ||
            content.contains("values ('\"+" + "pass"));

        assertFalse(
            "Register.java must not use createStatement() for user registration queries",
            content.contains("createStatement()"));
    }

    /**
     * Verifies that a second-order SQL injection payload stored via user
     * registration cannot escape the parameterized binding in Register.java.
     * Tests that the 'about', 'email', 'secret', and 'username' fields are
     * all bound via setString rather than concatenated.
     */
    public void testRegisterAllFieldsBoundViaSetString() throws Exception {
        File src = findSourceFile("Register.java");
        assertNotNull("Register.java must be locatable", src);
        String content = readFile(src);

        // Count setString occurrences — at minimum 5 for the users INSERT
        // (username, password, email, About, secret) + 1 for UserMessages INSERT
        int setStringCount = countOccurrences(content, "setString");
        assertTrue(
            "Register.java must call setString() at least 6 times to bind all user-supplied parameters",
            setStringCount >= 6);
    }

    /**
     * Verifies that the UserMessages INSERT in Register.java also uses
     * PreparedStatement (not raw concatenation) for the recipient field.
     */
    public void testRegisterUserMessagesInsertIsParameterized() throws Exception {
        File src = findSourceFile("Register.java");
        assertNotNull("Register.java must be locatable", src);
        String content = readFile(src);

        assertTrue(
            "Register.java UserMessages INSERT must use '?' placeholder for recipient",
            content.contains("UserMessages") && content.contains("prepareStatement"));

        assertFalse(
            "Register.java must not concatenate 'user' into the UserMessages INSERT query",
            content.contains("values ('\"+" + "user+\"'") ||
            content.contains("recipient, sender") && content.contains("'\"+" + "user"));
    }

    // -------------------------------------------------------------------------
    // Helper methods
    // -------------------------------------------------------------------------

    /**
     * Locates a source file by name, searching the standard Maven source
     * directory relative to the current working directory.
     */
    private File findSourceFile(String fileName) {
        String[] searchPaths = {
            "src/main/java/org/cysecurity/cspf/jvl/controller/" + fileName,
            "../src/main/java/org/cysecurity/cspf/jvl/controller/" + fileName
        };
        for (String path : searchPaths) {
            File f = new File(path);
            if (f.exists()) {
                return f;
            }
        }
        return null;
    }

    /**
     * Reads the entire content of a file into a single String.
     */
    private String readFile(File file) throws Exception {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\n");
            }
        }
        return sb.toString();
    }

    /**
     * Counts the number of non-overlapping occurrences of a substring.
     */
    private int countOccurrences(String text, String token) {
        int count = 0;
        int idx = 0;
        while ((idx = text.indexOf(token, idx)) != -1) {
            count++;
            idx += token.length();
        }
        return count;
    }
}
