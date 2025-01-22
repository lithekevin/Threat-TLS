<div align="center">
  <h1>Threat-TLS</h1>
  <p>
    <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" height="22">
    <img src="https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=Flask&logoColor=white" alt="Flask" height="22">
    <img src="https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white" alt="Sqlite" height="22">
<img src="https://img.shields.io/badge/Suricata-FF5733?style=for-the-badge&logo=suricata&logoColor=white" alt="Suricata" height="22">
    <img src="https://img.shields.io/badge/Zeek-000000?style=for-the-badge&logo=zeek&logoColor=white" alt="Zeek" height="22">
  </p>
</div>

<div id="overview" align="center">
  <h2>Overview</h2>
  <p>Threat-TLS is a network-based intrusion detection tool designed to identify weak, malicious, or suspicious TLS connections in intercepted traffic. By leveraging Suricata and Zeek IDS configured with custom rules, Threat-TLS detects TLS threat patterns associated with known vulnerabilities, such as outdated protocol versions, weak cryptographic algorithms, or malicious extensions. The tool validates detected threats using tools like Metasploit, Nmap, and TLS-Attacker, generating detailed reports for mitigation.<p>
    <img src="static/serverDetails.png" alt="Server Details" height="400">
  </p>
</div>

<div id="features" align="left">
  <h2>Features</h2>
  <ul>
    <li>TLS Threat Detection: Identifies patterns in TLS connections that may indicate vulnerabilities or attacks.</li>
    <li>Custom IDS Rules: Configurable rules for Suricata and Zeek to detect specific TLS threats.</li>
    <li>Threat Validation: Verifies detected threats using tools like Metasploit and Nmap.</li>
    <li>Detailed Reporting: Provides comprehensive logs and actionable insights for mitigation.</li>
    <li>Experimental Testbed: Tested with vulnerable OpenSSL versions to validate detection and verification processes.</li>
  </ul>
</div>

<div id="installation" align="left">
  <h2>Installation</h2>
  <p>1. Clone the repository:</p>
  <p>
    <code>git clone https://github.com/lithekevin/Threat-TLS.git</code><br>
    <code>cd threat-tls</code>
  </p>
  <p>2. Set up the environment variable for the NVD API key:</p>
  <p>
    <code>export NVD_API_KEY=your_api_key</code>
  </p>
</div>

<div id="usage" align="left">
  <h2>Usage</h2>
  <h3>Monitor Network Traffic</h3>
  <p>To start monitoring network traffic with Suricata or Zeek, run the following command:</p>
  <p>
    <code>python core.py --IDS=Suricata</code><br>
or<br>
    <code>python core.py --IDS=Zeek</code>
  </p>
  <p>Visualize the results in the web interface by opening the following URL in your browser:</p>
  <p>
    <code>http://localhost:5000</code>
  </p>

<h3>Perform Specific Attack</h3>
  <p>To perform a specific attack on a host, use the following command:</p>
  <p>
    <code>python core.py --attack attack_name --host ip:port</code>
  </p>
  <p>Replace <code>attack_name</code> with the name of the attack (e.g., heartbleed) and <code>ip:port</code> with the target host.</p>

<h3>Whitelist Configuration</h3>
  <p>You can use a JSON configuration file to specify versions, ciphers, and certificate fingerprints that need to be whitelisted:</p>
  <p>
    <code>python core.py --json /path/to/config.json</code>
  </p>
</div>

<div id="vulnerabilities" align="left">
  <h2>Vulnerabilities</h2>
  <p>The tool checks for the following vulnerabilities:</p>
  <ul>
    <li>BLEICHENBACHER: CVE-2012-0884</li>
    <li>CCSINJECTION: CVE-2014-0224</li>
    <li>POODLE: CVE-2014-3566</li>
    <li>HEARTBEAT EXTENSION: CVE-2014-0160</li>
    <li>LUCKY13: CVE-2013-0169</li>
    <li>PADDING ORACLE ATTACK: CVE-2016-2107</li>
    <li>SWEET32: CVE-2016-2183</li>
    <li>DROWN: CVE-2016-0800</li>
    <li>TICKETBLEED: CVE-2016-9244</li>
    <li>CRIME: CVE-2012-4929</li>
    <li>LOGJAM: CVE-2015-4000</li>
    <li>ROCA: CVE-2017-15361</li>
    <li>BEAST: CVE-2011-3389</li>
    <li>RC4: CVE-2013-2566</li>
    <li>FREAK: CVE-2015-0204</li>
  </ul>
</div>

<div id="license" align="left">
  <h2>License</h2>
  <p>This project is licensed under the MIT License. See the LICENSE file for details.</p>
</div>