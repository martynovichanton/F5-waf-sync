import pexpect
import paramiko
from scp import SCPClient, SCPException
import sys
import getpass
import re
import os
from datetime import datetime

class Ssh():
    def __init__(self, ip, port, user, password):
        self.ip = ip
        self.port = port
        self.user = user
        self.password = password
        self.client = None
        self.shell = None
        self.scp = None
        self.session = None

    def connect(self):
        try:
            ssh_cmd = f"ssh {self.user}@{self.ip}"
            self.session = pexpect.spawn(ssh_cmd, encoding='utf-8')
            self.session.expect("assword")
            self.session.sendline(self.password)
            self.session.expect(f"{self.user}@")

            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(self.ip, self.port, self.user, self.password)
            self.shell = self.client.invoke_shell(height=100, width=100)

            self.scp = SCPClient(self.client.get_transport())
        
        except Exception as e:
            print(f"[-] Exception: {e}")

    def disconnect(self):
        try:
            self.session.sendline("exit")
            self.session.close()

            self.client.close()
            self.shell.close()

            self.scp.close()
        except Exception as e:
            print(f"[-] Exception: {e}")

    def download_file(self, file, path):
        try:
            self.scp.get(file, path)
        except Exception as e:
            print(f"[-] Exception: {e}")

    def ssh_command(self, command):
        try:
            self.session.sendline(command)
            self.session.expect(f"{self.user}@")
            output = self.session.before
        except Exception as e:
            print(f"[-] Exception: {e}")
            return
        return output
    
    def scp_transfer(self, dst_host, file_path):
        try:
            self.session.sendline(f"scp {file_path} {self.user}@{dst_host}:/var/tmp/")
            self.session.expect("assword")
            self.session.sendline(self.password)
            self.session.expect(f"{self.user}@")
            output = self.session.before
            # print(output)
        except Exception as e:
            print(f"[-] Exception: {e}")

    def get_asm_policies(self):
        print(f"[+] Fetching ASM policies from {self.ip}...")
        output = self.ssh_command("bash")
        output = self.ssh_command("tmsh list asm policy one-line")

        policies = []
        for line in output.splitlines():
            match = re.search(r'policy\s+(\S+)\s+', line)
            if match:
                policies.append(match.group(1))
        return policies
    
    def save_policies(self, policies):
        print(f"[+] Saving ASM policies on {self.ip}...")
        for policy in policies:
            print(f"[+] Exporting policy on source: {policy}")
            self.ssh_command(f"tmsh save asm policy {policy} xml-file {policy}.xml overwrite")

    def backup_policies(self, policies, output_dir):
        print(f"[+] Backing up ASM policies from {self.ip}...")
        for policy in policies:
            print(f"[+] Backing up policy from source: {policy}")
            policy_filename = f"/var/tmp/{policy}.xml"
            self.download_file(policy_filename, output_dir)

    def transfer_policies(self, policies, dst_f5):
        print(f"[+] Transferring ASM policies from {self.ip} to {dst_f5}...")
        for policy in policies:
            policy_filename = f"/var/tmp/{policy}.xml"
            print(f"[+] Transferring {policy_filename} to {dst_f5} via SCP")
            self.scp_transfer(dst_f5, policy_filename)
    
    def apply_policies(self, policies):
        print(f"[+] Applying ASM policies on {self.ip}...")
        for policy in policies:
            print(f"[+] Applying {policy} on {self.ip}")
            self.ssh_command(f"tmsh load asm policy {policy} overwrite file /var/tmp/{policy}.xml")
            self.ssh_command(f"tmsh modify asm policy {policy} active")
            self.ssh_command(f"tmsh publish asm policy {policy}")

def main():
    # connect with paramiko, scp and pexpect
    # get all asm policies from src and dst devices
    # save all asm policies locally on src and dst devices
    # backup all asm policies to the local server from src and dst devices
    # scp transfer policies to dst f5
    # apply policies on dst f5
    # disconnect

    if len(sys.argv) != 3:
        print("Usage: waf_sync.py <source_f5_ip> <destination_f5_ip>")
        sys.exit(1)

    port = 22
    src_f5 = sys.argv[1]
    dst_f5 = sys.argv[2]
    username = getpass.getpass("Enter username: ")
    password = getpass.getpass("Enter password: ")

    ssh_src = Ssh(src_f5, port, username, password)
    ssh_dst = Ssh(dst_f5, port, username, password)
    ssh_src.connect()
    ssh_dst.connect()

    now = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    output_dir_src = f"output/output-{src_f5}-{now}"
    output_dir_dst = f"output/output-{dst_f5}-{now}"
    os.mkdir(output_dir_src)
    os.mkdir(output_dir_dst)

    policies_src = ssh_src.get_asm_policies()
    policies_dst = ssh_dst.get_asm_policies()

    if not policies_src or not policies_dst:
        print("[-] No ASM policies found!")
        sys.exit(1)

    print(f"[+] Found {len(policies_src)} policies on source. Processing each...")
    print(f"[+] Found {len(policies_dst)} policies on destination. Processing each...")

    ssh_src.save_policies(policies_src)
    ssh_dst.save_policies(policies_dst)
    ssh_src.backup_policies(policies_src, output_dir_src)
    ssh_dst.backup_policies(policies_dst, output_dir_dst)
    ssh_src.transfer_policies(policies_src, dst_f5)
    # ssh_dst.apply_policies(policies_src)

    ssh_src.disconnect()
    ssh_dst.disconnect()
    print("[+] Migration completed successfully.")

if __name__ == "__main__":
    main()