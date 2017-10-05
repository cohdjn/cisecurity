# redhat7/pam
#
# Implements Center of Internet Security PAM controls.

class cisecurity::redhat7::pam (

  Enum['enabled','disabled'] $account_lockout_enforcement,
  Integer $account_lockout_attempts,
  Integer $account_lockout_time,
  Enum['enabled','disabled'] $inactive_account_lockout,
  Integer $inactive_account_lockout_days,
  Enum['enabled','disabled'] $password_aging,
  Integer $password_aging_max_days,
  Integer $password_aging_min_days,
  Integer $password_aging_warn_days,
  Enum['enabled','disabled'] $password_enforcement,
  Integer $password_min_length,
  Integer $password_num_digits,
  Integer $password_num_lowercase,
  Integer $password_num_uppercase,
  Integer $password_num_other_chars,
  Integer $password_max_attempts,
  Integer $password_num_remembered,
  String $root_primary_group,
  Enum['enabled','disabled'] $wheel,
) {

  user { 'root':
    ensure => present,
    gid    => $root_primary_group,
  }

  if $inactive_account_lockout == 'enabled' {
    exec { "useradd -D -f ${inactive_account_lockout_days}":
      path   => [ '/sbin', '/bin' ],
      unless => "useradd -D | grep INACTIVE | grep ${inactive_account_lockout_days}",
    }
  }

  if $wheel == 'enabled' {
    pam { 'su pam_wheel.so':
      ensure    => present,
      service   => 'su',
      type      => 'auth',
      control   => 'required',
      module    => 'pam_wheel.so',
      arguments => [ 'use_uid' ],
      position  => 'after module pam_rootok.so',
    }
  }

  if $password_aging == 'enabled' {
    file { '/etc/login.defs':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }
    file_line { 'PASS_MAX_DAYS':
      ensure             => present,
      path               => '/etc/login.defs',
      line               => "PASS_MAX_DAYS ${password_aging_max_days}",
      match              => '^PASS_MAX_DAYS.*',
      append_on_no_match => false,
    }
    file_line { 'PASS_MIN_DAYS':
      ensure             => present,
      path               => '/etc/login.defs',
      line               => "PASS_MIN_DAYS ${password_aging_min_days}",
      match              => '^PASS_MIN_DAYS.*',
      append_on_no_match => false,
    }
    file_line { 'PASS_WARN_AGE':
      ensure             => present,
      path               => '/etc/login.defs',
      line               => "PASS_WARN_AGE ${password_aging_warn_days}",
      match              => '^PASS_WARN_AGE.*',
      append_on_no_match => false,
    }
  }

  if $password_enforcement == 'enabled' {
    pam { 'password-auth pam_pwquality.so':
      ensure    => present,
      service   => 'password-auth',
      type      => 'password',
      control   => 'sufficient',
      module    => 'pam_pwquality.so',
      arguments => [ 'try_first_pass', "retry=${password_max_attempts}" ],
      position  => 'before module pam_unix.so',
    }
    pam { 'system-auth pam_pwquality.so':
      ensure    => present,
      service   => 'system-auth',
      type      => 'password',
      control   => 'sufficient',
      module    => 'pam_pwquality.so',
      arguments => [ 'try_first_pass', "retry=${password_max_attempts}" ],
      position  => 'before module pam_unix.so',
    }
    pam { 'password-auth pam_faillock.so 99':
      ensure    => present,
      service   => 'password-auth',
      type      => 'password',
      control   => 'sufficient',
      module    => 'pam_unix.so',
      arguments => [ 'sha512', 'shadow', 'nullok', 'try_first_pass', 'use_authtok', "remember=${password_num_remembered}" ],
      position  => 'after module pam_pwquality.so',
    }
    pam { 'system-auth pam_faillock.so 99':
      ensure    => present,
      service   => 'system-auth',
      type      => 'password',
      control   => 'sufficient',
      module    => 'pam_unix.so',
      arguments => [ 'sha512', 'shadow', 'nullok', 'try_first_pass', 'use_authtok', "remember=${password_num_remembered}" ],
      position  => 'after module pam_pwquality.so',
    }
    $pwquality_hash = {
      'dcredit' => $password_num_digits,
      'lcredit' => $password_num_lowercase,
      'minlen'  => $password_min_length,
      'ocredit' => $password_num_other_chars,
      'ucredit' => $password_num_uppercase,
    }
    $pwquality_hash.each | String $setting, Integer $value | {
      file_line { $setting:
        ensure => present,
        path   => '/etc/security/pwquality.conf',
        line   => "${setting}=${value}",
      }
    }
  }

  if $account_lockout_enforcement == 'enabled' {
    pam { 'password-auth pam_faillock.so 1':
      ensure    => present,
      service   => 'password-auth',
      type      => 'auth',
      control   => 'required',
      module    => 'pam_faillock.so',
      arguments => [ 'preauth', 'audit', 'silent', "deny=${account_lockout_attempts}", "unlock_time=${account_lockout_time}" ],
      position  => 'before module pam_unix.so',
    }
    pam { 'system-auth pam_faillock.so 1':
      ensure    => present,
      service   => 'system-auth',
      type      => 'auth',
      control   => 'required',
      module    => 'pam_faillock.so',
      arguments => [ 'preauth', 'audit', 'silent', "deny=${account_lockout_attempts}", "unlock_time=${account_lockout_time}" ],
      position  => 'before module pam_unix.so',
    }
    pam { 'password-auth pam_faillock.so 2':
      ensure           => present,
      service          => 'password-auth',
      type             => 'auth',
      control          => '[success=1 default=bad]',
      control_is_param => true,
      module           => 'pam_unix.so',
    }
    pam { 'system-auth pam_faillock.so 2':
      ensure           => present,
      service          => 'system-auth',
      type             => 'auth',
      control          => '[success=1 default=bad]',
      control_is_param => true,
      module           => 'pam_unix.so',
    }
    pam { 'password-auth pam_faillock.so 3':
      ensure           => present,
      service          => 'password-auth',
      type             => 'auth',
      control          => '[default=die]',
      control_is_param => true,
      module           => 'pam_faillock.so',
      arguments        => ['authfail',"deny=${account_lockout_attempts}","unlock_time=${account_lockout_time}"],
      position         => 'after module pam_unix.so',
    }
    pam { 'system-auth pam_faillock.so 3':
      ensure           => present,
      service          => 'system-auth',
      type             => 'auth',
      control          => '[default=die]',
      control_is_param => true,
      module           => 'pam_faillock.so',
      arguments        => ['authfail',"deny=${account_lockout_attempts}","unlock_time=${account_lockout_time}"],
      position         => 'after module pam_unix.so',
    }
    pam { 'password-auth pam_faillock.so 4':
      ensure    => present,
      service   => 'password-auth',
      type      => 'auth',
      control   => 'sufficient',
      module    => 'pam_faillock.so',
      arguments => ['authsucc',"deny=${account_lockout_attempts}","unlock_time=${account_lockout_time}"],
      position  => 'after module pam_faillock.so',
    }
    pam { 'system-auth pam_faillock.so 4':
      ensure    => present,
      service   => 'system-auth',
      type      => 'auth',
      control   => 'sufficient',
      module    => 'pam_faillock.so',
      arguments => ['authsucc',"deny=${account_lockout_attempts}","unlock_time=${account_lockout_time}"],
      position  => 'after module pam_faillock.so',
    }
  }

}
