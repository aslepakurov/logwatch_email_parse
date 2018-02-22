import imaplib
import email
import re

from bean import Report
from io import StringIO


def extract_body(email_payload):
    if isinstance(email_payload, str):
        return email_payload
    else:
        return '\n'.join([extract_body(part.get_payload()) for part in email_payload])


conn = imaplib.IMAP4_SSL("imap.gmail.com", 993)
conn.login("login", "pass")
conn.select()
typ, data = conn.search(None, '(FROM "logwatch")')
try:
    for num in data[0].split():
        typ, msg_data = conn.fetch(num, '(RFC822)')
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                payload = msg.get_payload()
                body = extract_body(payload)
                stri = StringIO(body)
                report = Report()
                flag = True
                while flag:
                    line = stri.readline()
                    if line != '':
                        if "Date Range Processed" in line:
                            line = stri.readline()
                            line = line.replace("(", "").replace(")", "").strip()
                            report.set_date(line)
                            continue
                        if "fail2ban-messages Begin" in line:
                            line = stri.readline()
                            while "fail2ban-messages End" not in line:
                                line = stri.readline()
                                if "Fail2Ban hosts found" in line:
                                    line = stri.readline()
                                    if "sshd" in line:
                                        line = stri.readline()
                                        while line.replace("\r\n", "").strip() != '':
                                            ip_times = line.replace(" ", "")\
                                                .replace(")", "")\
                                                .replace("Times", "")\
                                                .replace("\r\n", "").split("(")
                                            report.add_fail2ban(ip_times[0], ip_times[1])
                                            line = stri.readline()
                            continue
                        if "SSHD Begin" in line:
                            line = stri.readline()
                            while "SSHD End" not in line:
                                line = stri.readline()
                                if "Didn't receive an ident from these IPs" in line:
                                    line = stri.readline()
                                    while line.replace("\r\n", "").strip() != '':
                                        ip_times = line.replace(" ", "") \
                                            .replace("Time(s)", "") \
                                            .replace(")", "") \
                                            .replace("\r\n", "")\
                                            .split(":")
                                        ip_host = ip_times[0].split("(")
                                        report.add_no_ident(ip_host[0], ip_host[1] if len(ip_host) == 2 else "", ip_times[1])
                                        line = stri.readline()
                                if "Refused ROOT login attempt from" in line:
                                    line = stri.readline()
                                    while line.replace("\r\n", "").strip() != '':
                                        ip_times = line.replace(" ", "") \
                                            .replace("Time(s)", "") \
                                            .replace(")", "") \
                                            .replace("\r\n", "")\
                                            .split(":")
                                        ip_host = ip_times[0].split("(")
                                        report.add_root_ident(ip_host[0], ip_host[1] if len(ip_host) == 2 else "", ip_times[1])
                                        line = stri.readline()
                                if "Users logging in through sshd" in line:
                                    line = stri.readline()
                                    while line.replace("\r\n", "").strip() != '':
                                        user = line.strip().split(":")[0]
                                        hosts = []
                                        line = stri.readline()
                                        while len(list(filter(None, line.replace("\r\n", "").strip().split(":")))) != 1:
                                            ip_times = line.replace(" ", "")\
                                                .replace(")", "")\
                                                .replace("times", "")\
                                                .replace("time", "")\
                                                .replace("\r\n", "").split(":")
                                            ip_host = ip_times[0].split("(")
                                            hosts.append((ip_host[0], ip_host[1] if len(ip_host) == 2 else "", ip_times[1]))
                                            line = stri.readline()
                                            if line.replace("\r\n", "").strip() == '': break
                                        report.add_login(user, hosts)
                                if "Illegal users from" in line:
                                    line = stri.readline()
                                    while line.replace("\r\n", "").strip() != '':
                                        host = line.strip().split(":")[0] if line.strip().startswith("undef") else re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line).group()
                                        add_host_split = line.split(":")[0]
                                        add_host = "" if len(add_host_split.split("(")) != 2 else add_host_split.split("(")[1].replace(")", "")
                                        users = []
                                        line = stri.readline()
                                        while line != 'undef' and re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line) is None:
                                            user_times = line.replace(" ", "") \
                                                .replace("[preauth]", "") \
                                                .replace("times", "") \
                                                .replace("time", "") \
                                                .replace("\r\n", "").split(":")
                                            users.append((user_times[0], user_times[1]))
                                            line = stri.readline()
                                            if line.replace("\r\n", "").strip() == '': break
                                        report.add_user_ident(host, add_host, users)
                            continue
                    else:
                        flag = False
                print(report.date)
                print(report.fail2ban)
                print(report.sshd_root_ident)
                print(report.sshd_no_ident)
                print(report.sshd_login)
                print(report.sshd_user_iden)

finally:
    try:
        conn.close()
    except:
        pass
    conn.logout()
