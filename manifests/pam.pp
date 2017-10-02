# pam
#
# Implements Center of Internet Security PAM controls.
#
# @param account_lockout_enforcement [Enum['enabled','disabled']] Whether account lockouts should be configured and enabled. Default value: 'enabled'.
# @param account_lockout_attempts [Integer] Number of bad login attempts before the account is locked out. Default value: 5.
# @param account_lockout_time [Integer] Amount of time in seconds to leave an account locked before unlocking. Default value: 900.
# @param inactive_account_lockout [Enum['enabled','disabled']] Whether inactive accounts will be automatically locked out. Default value: 'enabled'.
# @param inactive_account_lockout_days [Integer] Number of days an account must be inactive before locking the account. Default value: 30.
# @param password_aging [Enum['enabled','disabled']] Whether account passwords must meet complex requirements. Default value: 'enabled'.
# @param password_aging_max_days [Integer] Maximum number of days before a password must be changed. Default value: 90.
# @param password_aging_min_days [Integer] Minimum number of days before a password must be changed. Default value: 7.
# @param password_aging_warn_days [Integer] Number of days before user receives warning their password needs to be changed. Default value: 7.
# @param password_enforcement [Enum['enabled','disabled']] Whether password complexity requirements are enabled. Default value: 'enabled',
# @param password_min_length [Integer] Minimum password length. Default value: 14.
# @param password_num_digits [Integer] Number of digits required. Default value: -1.
# @param password_num_lowercase [Integer] Number of lowercase characters required. Default value: -1.
# @param password_num_uppercase [Integer] Number of uppercase characters required. Default value: -1.
# @param password_num_other_chars [Integer] Number of special characters required. Default value: -1.
# @param password_max_attempts [Integer] Number of times a user can attempt to change password to meet complexity requirements before aborting. Default value: 3
# @param password_num_remembered [Integer] Number of passwords that the system will remember. Default value: 5.
# @param root_primary_group [String] The GID or name of root's primary group. Default value: 'root'.
# @param wheel [Enum['enabled','disabled']] Whether to require membership in wheel to su to root. Default value: 'enabled'.

class cisecurity::pam (

  Enum['enabled','disabled'] $account_lockout_enforcement = 'enabled',
  Integer $account_lockout_attempts                       = 5,
  Integer $account_lockout_time                           = 900,
  Enum['enabled','disabled'] $inactive_account_lockout    = 'enabled',
  Integer $inactive_account_lockout_days                  = 30,
  Enum['enabled','disabled'] $password_aging              = 'enabled',
  Integer $password_aging_max_days                        = 90,
  Integer $password_aging_min_days                        = 7,
  Integer $password_aging_warn_days                       = 7,
  Enum['enabled','disabled'] $password_enforcement        = 'enabled',
  Integer $password_min_length                            = 14,
  Integer $password_num_digits                            = -1,
  Integer $password_num_lowercase                         = -1,
  Integer $password_num_uppercase                         = -1,
  Integer $password_num_other_chars                       = -1,
  Integer $password_max_attempts                          = 3,
  Integer $password_num_remembered                        = 5,
  String $root_primary_group                              = 'root',
  Enum['enabled','disabled'] $wheel                       = 'enabled',
) {

  user { 'root':
    ensure => present,
    gid    => $root_primary_group,
  }

  if $inactive_account_lockout == 'enabled' {
    exec { "useradd -D -f ${inactive_account_lockout_days}":
      path    => [ '/sbin', '/bin' ],
      unless  => "test $(useradd -D | grep INACTIVE)=='INACTIVE=${inactive_lockout_days}'!eq'INACTIVE=${inactive_lockout_days}' ",
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
      ensure  => present,
      path    => '/etc/login.defs',
      line    => "PASS_MAX_DAYS ${cisecurity::password_aging_max_days}",
      require => File['/etc/login.defs'],
    }

    file_line { 'PASS_MIN_DAYS':
      ensure  => present,
      path    => '/etc/login.defs',
      line    => "PASS_MIN_DAYS ${cisecurity::password_aging_min_days}",
      require => File['/etc/login.defs'],
    }

    file_line { 'PASS_WARN_AGE':
      ensure  => present,
      path    => '/etc/login.defs',
      line    => "PASS_WARN_AGE ${cisecurity::password_aging_warn_days}",
      require => File['/etc/login.defs'],
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
