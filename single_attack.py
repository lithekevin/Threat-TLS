import subprocess

def single_attack(attack, host):
    ip = host.split(':')[0]
    port = host.split(':')[1]
    path_to_tls_attacker = "/home/kali/Desktop/TLS-Attacker/apps/Attacks.jar"


    # Helper function to run subprocess commands
    def run_command(command_list, description):
        try:
            print(f'Starting {description}...\n')
            process = subprocess.Popen(command_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            output = stdout.decode()
            error = stderr.decode()
            if output:
                print(output)
            if error:
                print(f"Error: {error}")
        except Exception as e:
            print(f"An error occurred while running {description}: {e}")

    # Define attack functions
    def heartbleed_attack():
        # Nmap Heartbleed
        run_command(
            ['nmap', '-A', '-p', port, '--script=ssl-heartbleed.nse', ip],
            'Heartbleed Attack with Nmap'
        )

        # Metasploit Heartbleed
        metasploit_command = (
            f"use auxiliary/scanner/ssl/openssl_heartbleed;"
            f"set RHOSTS {ip};"
            f"set RPORT {port};"
            "run;exit"
        )
        run_command(
            ['msfconsole', '-q', '-x', metasploit_command],
            'Heartbleed Attack with Metasploit'
        )

        # testssl Heartbleed
        run_command(
            ['testssl', '--heartbleed', '--fast', host],
            'Heartbleed Attack with testssl'
        )

        # TLS-Attacker Heartbleed
        run_command(
            ['java', '-jar', path_to_tls_attacker, 'heartbleed', '-connect', host],
            'Heartbleed Attack with TLS-Attacker'
        )

    def crime_attack():
        run_command(
            ['testssl', '--crime', '--fast', host],
            'CRIME Attack Test with testssl'
        )

    def drown_attack():
        # TLS-Attacker DROWN
        run_command(
            ['java', '-jar', path_to_tls_attacker, 'generalDrown', '-connect', host],
            'DROWN Attack with TLS-Attacker'
        )

        # testssl DROWN
        run_command(
            ['testssl', '--drown', '--fast', host],
            'DROWN Attack Test with testssl'
        )

    def bleichenbacher_attack():
        run_command(
            ['java', '-jar', path_to_tls_attacker, 'bleichenbacher', '-connect', host],
            'Bleichenbacher Attack with TLS-Attacker'
        )

    def robot_attack():
        # testssl ROBOT
        run_command(
            ['testssl', '--robot', '--fast', host],
            'ROBOT Attack Test with testssl'
        )

        # Metasploit ROBOT
        metasploit_command = (
            f"use auxiliary/scanner/ssl/bleichenbacher_oracle;"
            f"set RHOSTS {ip};"
            f"set RPORT {port};"
            "run;exit"
        )
        run_command(
            ['msfconsole', '-q', '-x', metasploit_command],
            'ROBOT Attack with Metasploit'
        )

    def padding_oracle_attack():
        run_command(
            ['java', '-jar', path_to_tls_attacker, 'padding_oracle', '-connect', host],
            'Padding Oracle Attack with TLS-Attacker'
        )

    def sweet32_attack():
        run_command(
            ['testssl', '--sweet32', '--fast', host],
            'Sweet32 Attack Test with testssl'
        )

    def logjam_attack():
        # testssl Logjam
        run_command(
            ['testssl', '--logjam', '--fast', host],
            'Logjam Attack Test with testssl'
        )

        # Nmap Logjam
        run_command(
            ['nmap', '-A', '-p', port, '--script=ssl-dh-params', ip],
            'Logjam Attack Test with Nmap'
        )

    def lucky13_attack():
        run_command(
            ['testssl', '--lucky13', '--fast', host],
            'Lucky13 Attack Test with testssl'
        )

    def poodle_attack():
        # Nmap POODLE
        run_command(
            ['nmap', '-A', '-p', port, '--script=ssl-poodle', ip],
            'POODLE Attack Test with Nmap'
        )

        # testssl POODLE
        run_command(
            ['testssl', '--poodle', '--fast', host],
            'POODLE Attack Test with testssl'
        )

        # TLS-Attacker POODLE
        run_command(
            ['java', '-jar', path_to_tls_attacker, 'poodle', '-connect', host],
            'POODLE Attack with TLS-Attacker'
        )

    def ticketbleed_attack():
        run_command(
            ['nmap', '-A', '-p', port, '--script=tls-ticketbleed', ip],
            'Ticketbleed Attack Test with Nmap'
        )

    def ccs_injection_attack():
        # Nmap CCS Injection
        run_command(
            ['nmap', '-A', '-p', port, '--script=ssl-ccs-injection', ip],
            'CCS Injection Attack Test with Nmap'
        )

        # Metasploit CCS Injection
        metasploit_command = (
            f"use auxiliary/scanner/ssl/openssl_ccs;"
            f"set RHOSTS {ip};"
            f"set RPORT {port};"
            "run;exit"
        )
        run_command(
            ['msfconsole', '-q', '-x', metasploit_command],
            'CCS Injection Attack with Metasploit'
        )

    def roca_attack():
        run_command(
            ['nmap', '-A', '-p', port, '--script=rsa-vuln-roca', ip],
            'ROCA Vulnerability Test with Nmap'
        )

    # Mapping attack names to functions
    attack_functions = {
        'heartbleed': heartbleed_attack,
        'crime': crime_attack,
        'drown': drown_attack,
        'bleichenbacher': bleichenbacher_attack,
        'robot': robot_attack,
        'padding_oracle_attack': padding_oracle_attack,
        'sweet32': sweet32_attack,
        'logjam': logjam_attack,
        'lucky13': lucky13_attack,
        'poodle': poodle_attack,
        'ticketbleed': ticketbleed_attack,
        'ccs_injection': ccs_injection_attack,
        'roca': roca_attack,
    }

    # Execute the corresponding attack function
    try:
        attack_func = attack_functions.get(attack.lower())
        if attack_func:
            attack_func()
        else:
            print(f"Attack '{attack}' is not recognized.")
    except Exception as e:
        print(f"An error occurred while executing the attack '{attack}': {e}")
