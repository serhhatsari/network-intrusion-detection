from scapy.all import *

# Function to craft and send a packet with a specific payload
def send_packet(payload):
    intruded_packet = IP(dst="10.0.0.1") / TCP(dport=80) / Raw(load=payload)
    send(intruded_packet)

# Test functions for each signature rule
def test_directory_traversal_attack():
    send_packet("/etc/passwd")

def test_sql_injection_attack():
    send_packet("SELECT * FROM users;")

def test_command_injection_attack():
    send_packet("; exec(")

def test_password_leak():
    send_packet("passwd:")

def test_ssh_key_exchange():
    send_packet("ssh-rsa")

def test_sql_union_select_injection():
    send_packet("UNION ALL SELECT")

def test_cross_site_scripting_attack():
    send_packet("<script>alert(")

def test_delete_from_sql_injection():
    send_packet("DELETE FROM")

def test_bash_command_injection():
    send_packet("/bin/bash")

def test_oracle_error():
    send_packet("ORA-")

def test_update_users_password_sql_injection():
    send_packet("UPDATE users SET password")

def test_drop_database_sql_injection():
    send_packet("DROP DATABASE")

def test_pop_up_window_attack():
    send_packet("<script>window.open(")

def test_hex_encoding_sql_injection():
    send_packet("\\x")

def test_delete_from_users_sql_injection():
    send_packet("DELETE FROM users")

def test_xp_cmdshell_sql_injection():
    send_packet("xp_cmdshell")


# Example usage
if __name__ == "__main__":
    test_directory_traversal_attack()
    #test_sql_injection_attack()
    #test_command_injection_attack()
    #test_password_leak()
    #test_ssh_key_exchange()
    #test_sql_union_select_injection()
    #test_cross_site_scripting_attack()
    #test_delete_from_sql_injection()
    #test_bash_command_injection()
    #test_oracle_error()
    #test_update_users_password_sql_injection()
    #test_drop_database_sql_injection()
    #test_pop_up_window_attack()
    #test_delete_from_users_sql_injection()
    #test_xp_cmdshell_sql_injection()
