# redhat6/pam
#
# Implements Center of Internet Security PAM controls.

class cisecurity::redhat6::pam (

  Enum['enabled','disabled'] $account_lockout_enforcement,
  Integer $account_lockout_attempts,
  Integer $account_lockout_time,
  Enum['enabled','disabled'] $inactive_account_lockout,
  Integer $inactive_account_lockout_days,
  Hash $root_user_settings,
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
  Enum['enabled','disabled'] $wheel,
) {

  user { 'root':
    ensure => present,
    *      => $root_user_settings,
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
      ensure => present,
      path   => '/etc/login.defs',
      line   => "PASS_MAX_DAYS ${password_aging_max_days}",
      match  => '^PASS_MAX_DAYS',
    }
    file_line { 'PASS_MIN_DAYS':
      ensure => present,
      path   => '/etc/login.defs',
      line   => "PASS_MIN_DAYS ${password_aging_min_days}",
      match  => '^PASS_MIN_DAYS',
    }
    file_line { 'PASS_WARN_AGE':
      ensure => present,
      path   => '/etc/login.defs',
      line   => "PASS_WARN_AGE ${password_aging_warn_days}",
      match  => '^PASS_WARN_AGE',
    }
  }

  $osrelease = downcase("${facts['os']['family']}${facts['os']['release']['major']}")
  file { '/etc/pam.d/system-auth-ac':
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    content => epp("cisecurity/${osrelease}__system_auth"),
  }
  file { '/etc/pam.d/password-auth-ac':
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    content => epp("cisecurity/${osrelease}__password_auth"),
  }

}
