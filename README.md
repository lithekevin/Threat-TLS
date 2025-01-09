# Threat-TLS

Threat-TLS is a tool designed to monitor network traffic for TLS attacks using Suricata or Zeek IDS. It checks for various vulnerabilities and provides detailed logs and mitigation steps.

## Features

- Monitors network traffic for TLS attacks
- Supports Suricata and Zeek IDS
- Provides detailed logs and mitigation steps through the web interface
- Supports multiple vulnerabilities including Heartbleed, POODLE, and more

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/threat-tls.git
    cd threat-tls
    ```

2. Set up the environment variable for the NVD API key:
    ```sh
    export NVD_API_KEY=your_api_key
    ```

## Usage

### Monitor Network Traffic

To start monitoring network traffic with Suricata or Zeek, run the following command:

```sh
  python core.py --IDS=Suricata
```
or

```sh
  python core.py --IDS=Zeek
```

### Perform Specific Attack
To perform a specific attack on a host, use the following command:
```sh
  python core.py --attack attack_name --host ip:port
```
Replace attack_name with the name of the attack (e.g., heartbleed) and ip:port with the target host.

### Whitelist Configuration
You can use a JSON configuration file to specify versions, ciphers, and certificate fingerprints that need to be whitelisted:

```sh
  python core.py --json /path/to/config.json
```

## Vulnerabilities
The tool checks for the following vulnerabilities:

```
    BLEICHENBACHER: CVE-2012-0884
    CCSINJECTION: CVE-2014-0224
    POODLE: CVE-2014-3566
    HEARTBEAT EXTENSION: CVE-2014-0160
    LUCKY13: CVE-2013-0169
    PADDING ORACLE ATTACK: CVE-2016-2107
    SWEET32: CVE-2016-2183
    DROWN: CVE-2016-0800
    TICKETBLEED: CVE-2016-9244
    CRIME: CVE-2012-4929
    LOGJAM: CVE-2015-4000
    ROCA: CVE-2017-15361
    BEAST: CVE-2011-3389
    RC4: CVE-2013-2566
    FREAK: CVE-2015-0204
```

## License
This project is licensed under the MIT License. See the LICENSE file for details.

## Contributing
Contributions are welcome! Please open an issue or submit a pull request for any changes.