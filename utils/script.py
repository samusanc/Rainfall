import paramiko
import os


def configure_vm(ip, port, user, pwd, pub_key):
    try:
        with open("server.txt", "r") as f:
            file_content = f.read()
    except Exception as e:
        print(f"Error reading local server.txt: {e}")
        return

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        print("Connecting to VM...")
        ssh.connect(ip, port=port, username=user, password=pwd, timeout=10)

        print("1. Setting directory permissions (chmod 777 .)...")
        stdin, stdout, stderr = ssh.exec_command("chmod 777 .")
        stdout.channel.recv_exit_status()

        print("2. Creating remote .ssh directory and adding the SSH key...")
        ssh_commands = f"""
        mkdir -p ~/.ssh
        chmod 700 ~/.ssh
        echo "{pub_key}" >> ~/.ssh/authorized_keys
        echo "{pub_key}" >> ~/.ssh/known_hosts
        chmod 600 ~/.ssh/authorized_keys ~/.ssh/known_hosts
        """
        stdin, stdout, stderr = ssh.exec_command(ssh_commands)
        stdout.channel.recv_exit_status()

        print("3. Copying content from local server.txt to remote server.py...")
        sftp = ssh.open_sftp()
        with sftp.open("server.py", "w") as remote_file:
            remote_file.write(file_content)

        sftp.chmod("server.py", 0o755)
        sftp.close()

        print("Successfully copied server.txt to server.py!")
        print("Process completed successfully!")

    except Exception as e:
        print(f"Error: {e}")

    finally:
        ssh.close()


if __name__ == "__main__":
    d_ip = "127.0.0.1"
    d_port = 8002
    d_user = "level0"
    d_pwd = "level0"
    d_pub_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEusIyd+2uOHNyOBSWi/tq2j3d7dx0oTUhqVJN09kM/A samu2004ssmm@gmail.com"

    ip = input(f"IP [{d_ip}]: ").strip() or d_ip
    port_input = input(f"Port [{d_port}]: ").strip()
    port = int(port_input) if port_input else d_port
    user = input(f"User [{d_user}]: ").strip() or d_user
    pwd = input(f"Password [{d_pwd}]: ").strip() or d_pwd

    configure_vm(ip, port, user, pwd, d_pub_key)
