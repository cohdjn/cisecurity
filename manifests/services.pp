# services
#
# Implements Center of Internet Security service controls.
#
# @param auditd_action_mail_acct [String] Email address of user who should receive notifications from auditd. Default value: 'root'.
# @param auditd_admin_space_left_action [Enum['ignore','syslog','rotate','email','exec','suspend','single','halt']] Action system should take when it's low on disk space. Default value: 'halt'.
# @param auditd_configure_rules [Enum['enabled','disabled']] Whether CIS rules should be applied to the system. Default value: 'enabled'.
# @param auditd_max_log_file [Integer] The maximum log file size of a single log file. Default value: 8.
# @param auditd_max_log_file_action [Enum['ignore','syslog','suspend','rotate','keep_logs']] The action to be taken when the maximum log file size. Default value: 'keep_logs'
# @param auditd_space_left_action [Enum['ignore','syslog','rotate','email','exec','suspend','single','halt']] Action system should take when it's low on disk space. Default value: 'email'.
# @param auditd_configure_boot_auditing [Enum['enabled','disabled']] Direct the kernel to start auditing before the auditd service starts. Default value: 'enabled'.
# @param autofs [Enum['enabled','disabled'] Whether to ensure the autofs service is running and boot-time enabled. Default value: 'disabled'.
# @param avahi_daemon [Enum['enabled','disabled'] Whether to ensure the avahi-daemon service is running and boot-time enabled. Default value: 'disabled'.
# @param chargen_dgram [Enum['enabled','disabled'] Whether to ensure the chargen-dgram inetd service is running and enabled. Default value: 'disabled'.
# @param chargen_stream [Enum['enabled','disabled'] Whether to ensure the chargen-stream inetd service is running and enabled. Default value: 'disabled'.
# @param configure_auditd [Enum['enabled','disabled']] Configure audit subsystem with values specified in variables in this class. Default value: 'enabled'.
# @param configure_cron [Enum['enabled','disabled']] Whether to ensure the cron daemon is running and boot-time enabled. Default value: 'enabled'.
# @param configure_postfix [Enum['enabled','disabled']] Whether to configure Postfix to listen only on localhost. Default value: 'enabled'.
# @param configure_rsyslog [Enum['enabled','disabled']] Configure rsyslog subsystem with values specified in variables in the class. Default value: 'enabled'.
# @param configure_sshd [Enum['enabled','disabled']] Configure SSH daemon with values specified in variables in the class. Default value: 'enabled'.
# @param configure_time [Enum['enabled','disabled']] Whether to configure time services (ntp or chrony). Default value: 'enabled'.
# @param cups [Enum['enabled','disabled'] Whether to ensure the cups service is running and boot-time enabled. Default value: 'disabled'.
# @param daytime_dgram [Enum['enabled','disabled'] Whether to ensure the daytime-dgram inetd service is running and enabled. Default value: 'disabled'.
# @param daytime_stream [Enum['enabled','disabled'] Whether to ensure the daytime-stream inetd service is running and enabled. Default value: 'disabled'.
# @param dhcpd [Enum['enabled','disabled'] Whether to ensure the dhcpd service is running and boot-time enabled. Default value: 'disabled'.
# @param dovecot [Enum['enabled','disabled'] Whether to ensure the dovecot service is running and boot-time enabled. Default value: 'disabled'.
# @param discard_dgram [Enum['enabled','disabled'] Whether to ensure the discard-dgram inetd service is running and enabled. Default value: 'disabled'.
# @param discard_stream [Enum['enabled','disabled'] Whether to ensure the discard-stream inetd service is running and enabled. Default value: 'disabled'.
# @param echo_dgram [Enum['enabled','disabled'] Whether to ensure the echo-dgram inetd service is running and enabled. Default value: 'disabled'.
# @param echo_stream [Enum['enabled','disabled'] Whether to ensure the echo-stream inetd service is running and enabled. Default value: 'disabled'.
# @param httpd [Enum['enabled','disabled'] Whether to ensure the httpd service is running and boot-time enabled. Default value: 'disabled'.
# @param inetd [Enum['enabled','disabled'] Whether to ensure the inetd service is running and boot-time enabled. Default value: 'disabled'.
# @param named [Enum['enabled','disabled'] Whether to ensure the named service is running and boot-time enabled. Default value: 'disabled'.
# @param nfs [Enum['enabled','disabled'] Whether to ensure the nfs service is running and boot-time enabled. Default value: 'disabled'.
# @param ntalk [Enum['enabled','disabled'] Whether to ensure the ntalk service is running and boot-time enabled. Default value: 'disabled'.
# @param ntp_service_restrictions [Array[String]] Configures ntp daemon restrictions. Default value: ['-4 default kod nomodify notrap nopeer noquery', '-6 default kod nomodify notrap nopeer noquery', '127.0.0.1', '-6 ::1'].
# @param rexec [Enum['enabled','disabled'] Whether to ensure the rexec service is running and boot-time enabled. Default value: 'disabled'.
# @param rhnsd [Enum['enabled','disabled'] Whether to ensure the rhnsd service is running and boot-time enabled. Default value: 'disabled'.
# @param rlogin [Enum['enabled','disabled'] Whether to ensure the rlogin service is running and boot-time enabled. Default value: 'disabled'.
# @param rpcbind [Enum['enabled','disabled'] Whether to ensure the rpcbind service is running and boot-time enabled. Default value: 'disabled'.
# @param rsh [Enum['enabled','disabled'] Whether to ensure the rsh service is running and boot-time enabled. Default value: 'disabled'.
# @param rsyncd [Enum['enabled','disabled'] Whether to ensure the rsync service is running and boot-time enabled. Default value: 'disabled'.
# @param rsyslog_remote_servers [Hash[String,Integer]] Configures rsyslog loghosts. Default value: {'log.domain.com' => 514}.
# @param slapd [Enum['enabled','disabled'] Whether to ensure the slapd service is running and boot-time enabled. Default value: 'disabled'.
# @param smb [Enum['enabled','disabled'] Whether to ensure the smb service is running and boot-time enabled. Default value: 'disabled'.
# @param sshd_banner_file [String] File to use to send banner to remote user before authentication. Default value: '/etc/issue.net'.
# @param sshd_client_alive_count_max [Integer] Maximum number of client alive messages before closing session. Default value: 4.
# @param sshd_client_alive_interval [Integer] Interval in seconds before sending a message to the client. Default value: 300.
# @param sshd_hostbased_authentication [Enum['yes','no']] Whether rhosts and public key authentication is allowed. Default value: 'no'.
# @param sshd_ignore_rhosts [Enum['yes','no']] Specifies whether .rhosts and .shosts files will be used. Default value: 'no'.
# @param sshd_login_grace_time [Integer] Amount of time until the server disconnects without successful login. Default value: 60.
# @param sshd_log_level [Enum['QUIET','FATAL','ERROR','INFO','VERBOSE','DEBUG','DEBUG1','DEBUG2','DEBUG3'] Verbosity level used when logging messages. Default value: 'INFO'.
# @param sshd_max_auth_tries [Integer] Maximum number of authentication attempts per connection. Default value: 4.
# @param sshd_permit_empty_password [Enum['yes','no']] Specifies whether sshd allows login to account with empty passwords. Default value: 'no'.
# @param sshd_permit_root_login [Enum['yes','no']] Specifies whether sshd allows root to log in directly. Default value: 'no'.
# @param sshd_permitted_ciphers [Array[String]] Specifies the ciphers allowed to secure connection. Default value: ['aes256-ctr', 'aes192-ctr', 'aes128-ctr', 'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'chacha20-poly1305@openssh.com'].
# @param sshd_permitted_macs [Array[String]] Specified the message authentication protocols allowed to secure the connection. Default value: ['hmac-sha2-512-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com', 'umac-128-etm@openssh.com', 'hmac-sha2-512', 'hmac-sha2-256', 'umac-128@openssh.com', 'curve25519-sha256@libssh.org', 'diffie-hellman-group-exchange-sha256'].
# @param sshd_permit_user_environment [Enum['yes','no]] Specifies whether ~/.ssh.environment and environment= options in ~/.ssh/authorized_keys are permitted. Default value: 'no'.
# @param sshd_protocol [Integer[1,2]] Specifies the ssh protocol version to be used. Default value: 2.
# @param squid [Enum['enabled','disabled'] Whether to ensure the squid service is running and boot-time enabled. Default value: 'disabled'.
# @param telnet [Enum['enabled','disabled'] Whether to ensure the telnet service is running and boot-time enabled. Default value: 'disabled'.
# @param tftp [Enum['enabled','disabled'] Whether to ensure the tftp service is running and boot-time enabled. Default value: 'disabled'.
# @param tftp_server [Enum['enabled','disabled'] Whether to ensure the tftp-server service is running and boot-time enabled. Default value: 'disabled'.
# @param time_dgram [Enum['enabled','disabled'] Whether to ensure the time-dgram inetd service is running and enabled. Default value: 'disabled'.
# @param time_service_provider [Enum['chrony','ntp']] Specifies which time server service to use. Default value: 'ntp'.
# @param time_service_servers [Array[String]] Specifies authoritative time servers to synchronize with. Default value:  '0.rhel.pool.ntp.org', '1.rhel.pool.ntp.org', '2.rhel.pool.ntp.org', '3.rhel.pool.ntp.org'].
# @param time_stream [Enum['enabled','disabled'] Whether to ensure the time-stream inetd service is running and enabled. Default value: 'disabled'.
# @param vsftpd [Enum['enabled','disabled'] Whether to ensure the vsftpd service is running and boot-time enabled. Default value: 'disabled'.
# @param ypserv [Enum['enabled','disabled'] Whether to ensure the ypserv service is running and boot-time enabled. Default value: 'disabled'.

class cisecurity::services (
  String $auditd_action_mail_acct                            = 'root',
  Enum[
    'email',
    'exec',
    'halt',
    'ignore',
    'rotate',
    'single',
    'suspend',
    'syslog'] $auditd_admin_space_left_action                = 'halt',
  Enum['enabled','disabled'] $auditd_configure_rules         = 'enabled',
  Integer $auditd_max_log_file                               = 8,
  Enum[
    'keep_logs',
    'ignore',
    'rotate',
    'suspend',
    'syslog'] $auditd_max_log_file_action                    = 'keep_logs',
  Enum[
    'email',
    'exec',
    'halt',
    'ignore',
    'rotate',
    'single',
    'suspend',
    'syslog'] $auditd_space_left_action                      = 'email',
  Enum['enabled','disabled'] $auditd_configure_boot_auditing = 'enabled',
  Enum['enabled','disabled'] $autofs                         = 'disabled',
  Enum['enabled','disabled'] $avahi_daemon                   = 'disabled',
  Enum['enabled','disabled'] $chargen_dgram                  = 'disabled',
  Enum['enabled','disabled'] $chargen_stream                 = 'disabled',
  Enum['enabled','disabled'] $configure_auditd               = 'enabled',
  Enum['enabled','disabled'] $configure_cron                 = 'enabled',
  Enum['enabled','disabled'] $configure_postfix              = 'enabled',
  Enum['enabled','disabled'] $configure_rsyslog              = 'enabled',
  Enum['enabled','disabled'] $configure_sshd                 = 'enabled',
  Enum['enabled','disabled'] $configure_time                 = 'enabled',
  Enum['enabled','disabled'] $cups                           = 'disabled',
  Enum['enabled','disabled'] $daytime_dgram                  = 'disabled',
  Enum['enabled','disabled'] $daytime_stream                 = 'disabled',
  Enum['enabled','disabled'] $dhcpd                          = 'disabled',
  Enum['enabled','disabled'] $discard_dgram                  = 'disabled',
  Enum['enabled','disabled'] $discard_stream                 = 'disabled',
  Enum['enabled','disabled'] $dovecot                        = 'disabled',
  Enum['enabled','disabled'] $echo_dgram                     = 'disabled',
  Enum['enabled','disabled'] $echo_stream                    = 'disabled',
  Enum['enabled','disabled'] $httpd                          = 'disabled',
  Enum['enabled','disabled'] $inetd                          = 'disabled',
  Enum['enabled','disabled'] $named                          = 'disabled',
  Enum['enabled','disabled'] $nfs                            = 'disabled',
  Enum['enabled','disabled'] $ntalk                          = 'disabled',
  Array[String] $ntp_service_restrictions                    = [
    '-4 default kod nomodify notrap nopeer noquery',
    '-6 default kod nomodify notrap nopeer noquery',
    '127.0.0.1',
    '-6 ::1',
                                                               ],
  Enum['enabled','disabled'] $rexec                          = 'disabled',
  Enum['enabled','disabled'] $rhnsd                          = 'disabled',
  Enum['enabled','disabled'] $rlogin                         = 'disabled',
  Enum['enabled','disabled'] $rpcbind                        = 'disabled',
  Enum['enabled','disabled'] $rsh                            = 'disabled',
  Enum['enabled','disabled'] $rsyncd                         = 'disabled',
  Hash[String,Integer] $rsyslog_remote_servers               = { 'log.domain.com' => 514 },
  Enum['enabled','disabled'] $slapd                          = 'disabled',
  Enum['enabled','disabled'] $smb                            = 'disabled',
  Enum['enabled','disabled'] $snmpd                          = 'disabled',
  String $sshd_banner_file                                   = '/etc/issue.net',
  Integer $sshd_client_alive_count_max                       = 4,
  Integer $sshd_client_alive_interval                        = 300,
  Enum['yes','no'] $sshd_hostbased_authentication            = 'no',
  Enum['yes','no'] $sshd_ignore_rhosts                       = 'yes',
  Integer $sshd_login_grace_time                             = 60,
  Enum[
    'DEBUG',
    'DEBUG1',
    'DEBUG2',
    'DEBUG3',
    'ERROR',
    'FATAL',
    'INFO',
    'QUIET',
    'VERBOSE'] $sshd_log_level                               = 'INFO',
  Integer $sshd_max_auth_tries                               = 4,
  Enum['yes','no'] $sshd_permit_empty_passwords              = 'no',
  Enum['yes','no'] $sshd_permit_root_login                   = 'no',
  Array[String] $sshd_permitted_ciphers                      = [
    'aes256-ctr',
    'aes192-ctr',
    'aes128-ctr',
    'aes256-gcm@openssh.com',
    'aes128-gcm@openssh.com',
    'chacha20-poly1305@openssh.com',
                                                               ],
  Array[String] $sshd_permitted_macs                         = [
    'hmac-sha2-512-etm@openssh.com',
    'hmac-sha2-256-etm@openssh.com',
    'umac-128-etm@openssh.com',
    'hmac-sha2-512',
    'hmac-sha2-256',
    'umac-128@openssh.com',
    'curve25519-sha256@libssh.org',
    'diffie-hellman-group-exchange-sha256',
                                                               ],
  Enum['yes','no'] $sshd_permit_user_environment             = 'no',
  Integer $sshd_protocol                                     = 2,
  Enum['yes','no'] $sshd_x11_forwarding                      = 'no',
  Enum['enabled','disabled'] $squid                          = 'disabled',
  Enum['enabled','disabled'] $telnet                         = 'disabled',
  Enum['enabled','disabled'] $tftp                           = 'disabled',
  Enum['enabled','disabled'] $tftp_server                    = 'disabled',
  Enum['enabled','disabled'] $time_dgram                     = 'disabled',
  Enum['chrony','ntp'] $time_service_provider                = 'ntp',
  Array[String] $time_service_servers                        = [
    '0.rhel.pool.ntp.org',
    '1.rhel.pool.ntp.org',
    '2.rhel.pool.ntp.org',
    '3.rhel.pool.ntp.org',
  Enum['enabled','disabled'] $time_stream                    = 'disabled',
  Enum['enabled','disabled'] $vsftpd                         = 'disabled',
  Enum['enabled','disabled'] $ypserv                         = 'disabled',
                                                               ],
) {

  # Private variables.
  $service_list = [
    'avahi-daemon.service',
    'cups.service',
    'dhcpd.service',
    'dovecot.service',
    'httpd.service',
    'named.service',
    'nfs.service',
    'ntalk.service',
    'rexec.socket',
    'rhnsd.service',
    'rlogin.socket',
    'rpcbind.service',
    'rsh.socket',
    'rsyncd.service',
    'slapd.service',
    'smb.service',
    'snmpd.service',
    'squid.service',
    'telnet.socket',
    'tftp.socket',
    'vsftpd.service',
    'ypserv.service',
  ]

  if $configure_auditd == 'enabled' {
    class { '::auditd':
      service_ensure          => running,
      service_enable          => true,
      action_mail_acct        => $auditd_action_mail_acct,
      admin_space_left_action => $auditd_admin_space_left_action,
      max_log_file            => $auditd_max_log_file,
      max_log_file_action     => $auditd_max_log_file_action,
      space_left_action       => $auditd_space_left_action,
    }
  }

  if $auditd_configure_boot_auditing == 'enabled' {
    kernel_parameter { 'audit':
      ensure => present,
      value  => '1',
    }
  } else {
    kernel_parameter { 'audit':
      ensure => absent,
      value  => '1',
    }
  }

  if $auditd_configure_rules == 'enabled' {
    auditd::rule { '-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change': }
    auditd::rule { '-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change': }
    auditd::rule { '-a always,exit -F arch=b64 -S clock_settime -k time-change': }
    auditd::rule { '-a always,exit -F arch=b32 -S clock_settime -k time-change': }
    auditd::rule { '-w /etc/localtime -p wa -k time-change': }
    auditd::rule { '-w /etc/group -p wa -k identity': }
    auditd::rule { '-w /etc/passwd -p wa -k identity': }
    auditd::rule { '-w /etc/gshadow -p wa -k identity': }
    auditd::rule { '-w /etc/shadow -p wa -k identity': }
    auditd::rule { '-w /etc/security/opasswd -p wa -k identity': }
    auditd::rule { '-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale': }
    auditd::rule { '-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale': }
    auditd::rule { '-w /etc/issue -p wa -k system-locale': }
    auditd::rule { '-w /etc/issue.net -p wa -k system-locale': }
    auditd::rule { '-w /etc/hosts -p wa -k system-locale': }
    auditd::rule { '-w /etc/sysconfig/network -p wa -k system-locale': }
    auditd::rule { '-w /etc/selinux/ -p wa -k MAC-policy': }
    auditd::rule { '-w /var/log/lastlog -p wa -k logins': }
    auditd::rule { '-w /var/run/faillock/ -p wa -k logins': }
    auditd::rule {'-w /var/run/utmp -p wa -k session': }
    auditd::rule {'-w /var/run/wtmp -p wa -k session': }
    auditd::rule {'-w /var/run/btmp -p wa -k session': }
    auditd::rule {'-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod': }
    auditd::rule {'-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod': }
    auditd::rule {'-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod': }
    auditd::rule {'-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod': }
    auditd::rule {'-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod': }
    auditd::rule {'-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod': }
    auditd::rule { '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access': }
    auditd::rule { '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access': }
    auditd::rule { '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access': }
    auditd::rule { '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access': }
    auditd::rule { '-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts': }
    auditd::rule { '-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts': }
    auditd::rule { '-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete': }
    auditd::rule { '-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete': }
    auditd::rule{'-w /etc/sudoers -p wa -k scope': }
    auditd::rule{'-w /etc/sudoers.d -p wa -k scope': }
    auditd::rule{ '-w /var/log/sudo.log -p wa -k actions': }
    auditd::rule{ '-w /sbin/insmod -p x -k modules': }
    auditd::rule{ '-w /sbin/rmmod -p x -k modules': }
    auditd::rule{ '-w /sbin/modprobe -p x -k modules': }
    auditd::rule{ '-a always,exit arch=b64 -S init_module -S delete_module -k modules': }

    if $facts['cisecurity']['suid_sgid_files'] == undef {
      warning ('Cannot configure auditing suid/sgid files because required system facts are undefined.')
    } else {
      $facts['cisecurity']['suid_sgid_files'].each | String $file | {
        auditd::rule { "-a always,exit -F path='${file}' -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged": }
      }
    }

    auditd::rule{ '-e 2':
      order => 999,
    }
  }

  if $configure_postfix == 'enabled' {
    class { 'postfix':
      inet_interfaces => 'localhost',
    }
  }

  if $configure_cron == 'enabled' {
    service { 'crond':
      ensure => running,
      enable => true,
    }
  }

  if $configure_rsyslog == 'enabled' {
    class { '::rsyslog':
      perm_file => '0640',
    }

    class { 'rsyslog::client':
      remote_servers => $rsyslog_remote_servers,
    }

    file { '/etc/rsyslog.d/CIS.conf':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
      source => 'puppet:///modules/cisecurity/rsyslog/rsyslog.conf'
    }
  }

  if $configure_sshd == 'enabled' {
    service { 'sshd':
      ensure => running,
      enable => true,
    }

    sshd_config { 'Protocol':
      ensure => present,
      value  => $sshd_protocol,
    }

    sshd_config { 'LogLevel':
      ensure => present,
      value  => $sshd_log_level,
    }

    sshd_config { 'X11Forwarding':
      ensure => present,
      value  => $sshd_x11_forwarding,
    }

    sshd_config { 'MaxAuthTries':
      ensure => present,
      value  => $sshd_max_auth_tries,
    }

    sshd_config { 'IgnoreRhosts':
      ensure => present,
      value  => $sshd_ignore_rhosts,
    }

    sshd_config { 'HostbasedAuthentication':
      ensure => present,
      value  => $sshd_hostbased_authentication,
    }

    sshd_config { 'PermitRootLogin':
      ensure => present,
      value  => $sshd_permit_root_login,
    }

    sshd_config { 'PermitEmptyPasswords':
      ensure => present,
      value  => $sshd_permit_empty_passwords,
    }

    sshd_config { 'PermitUserEnvironment':
      ensure => present,
      value  => $sshd_permit_user_environment,
    }

    $ciphers = join($sshd_permitted_ciphers, ',')
    sshd_config { 'Ciphers':
      ensure => present,
      value  => $ciphers,
    }

    sshd_config { 'MACs':
      ensure => present,
      value  => $sshd_permitted_macs,
    }

    sshd_config { 'ClientAliveInterval':
      ensure => present,
      value  => $sshd_client_alive_interval,
    }

    sshd_config { 'ClientAliveCountMax':
      ensure => present,
      value  => $sshd_client_alive_count_max,
    }

    sshd_config { 'LoginGraceTime':
      ensure => present,
      value  => $sshd_login_grace_time,
    }

    sshd_config { 'BannerFile':
      ensure => present,
      value  => $sshd_banner_file,
    }
  }

  if $configure_time == 'enabled' {
    case $time_service_provider {
      'ntp': {
        class { '::ntp':
          service_ensure => running,
          service_enable => true,
          servers        => $time_service_servers,
          restrict       => $ntp_service_restrictions,
        }

        file { '/etc/sysconfig/ntpd':
          ensure  => file,
          owner   => 'root',
          group   => 'root',
          mode    => '0644',
          content => 'OPTIONS="-g -u ntp:ntp"',
        }

        class { '::chrony':
          service_ensure => stopped,
          service_enable => false,
        }
      }

      'chrony': {
        class { '::chrony':
          service_ensure => running,
          service_enable => true,
          servers        => $time_service_servers,
        }

        file { '/etc/sysconfig/chronyd':
          ensure  => file,
          owner   => 'root',
          group   => 'root',
          mode    => '0644',
          content => 'OPTIONS="-u chrony"',
        }

        class { '::ntpd':
          service_ensure => stopped,
          service_enable => false,
        }
      }
    }
  }

  $service_list.each | String $service | {
    $uscore_service = regsubst($service, '-', '_')
    $uscore_service = regsubst($uscore_service, '.service', '')
    $uscore_service = regsubst($uscore_service, '.socket', '')
    if getvar("service_${uscore_service}") == 'enabled' {
      service { $service:
        ensure => started,
        enable => true,
      }
    } else {
      service { $service:
        ensure => stopped,
        enable => false,
      }
    }
  }
  
}
