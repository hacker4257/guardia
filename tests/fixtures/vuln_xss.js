// XSS vulnerabilities for testing

function displayUser(userData) {
    // VULN004: XSS via innerHTML
    document.getElementById('output').innerHTML = userData;
}

function writeContent(content) {
    // VULN004: XSS via document.write
    document.write(content);
}

function safeDisplay(userData) {
    document.getElementById('output').textContent = userData;
}

// Hardcoded IP for testing VULN006
const API_SERVER = "192.168.1.100";
const DB_HOST = "10.0.0.50";
