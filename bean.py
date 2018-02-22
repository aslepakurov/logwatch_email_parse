class Report(object):
    fail2ban = []
    sshd_no_ident=[]
    sshd_root_ident=[]
    sshd_user_iden=[]
    sshd_login=[]
    date = ""

    def __init__(self):
        self.fail2ban = []
        self.sshd_no_ident = []
        self.sshd_root_ident = []
        self.sshd_user_iden = []
        self.sshd_login = []
        self.date = ""
        pass

    def set_date(self, date):
        self.date = date

    def add_fail2ban(self, ip, times):
        self.fail2ban.append((ip, times))

    def add_no_ident(self, ip, times, host=""):
        self.sshd_no_ident.append((ip, times, host))

    def add_root_ident(self, ip, times, host=""):
        self.sshd_root_ident.append((ip, times, host))

    def add_user_ident(self, host, add_host, users):
        self.sshd_user_iden.append((host, add_host, users))

    def add_login(self, user, hosts):
        self.sshd_login.append((user, hosts))
