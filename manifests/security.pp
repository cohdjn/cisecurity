# security
#
# Implements Center of Internet Security security controls.
#
# @param aslr [Enum['enabled','disabled']] Whether address space layout randomization is enabled on the system. Default value: 'enabled'.
# @param banner_message_text [String] Banner text displayed to use on Gnome desktop. Default value: 'Authorized uses only. All activity may be monitored and reported.'.
# @param bootloader_password [String] Encrypted password for grub to use. Default value: 'abcd1234'.
# @param configure_system_acct_nologin [Enum['enabled','disabled']] Change all system account shells to /sbin/nologin. Default value: 'enabled'.
# @param issue [String] Source file for the contents of /etc/issue. Default value: 'puppet:///modules/cisecurity/banners/issue'.
# @param issue_net [String] Source file for the contents of /etc/issue.net. Default value: 'puppet:///modules/cisecurity/banners/issue.net'.
# @param restricted_core_dumps [Enum['enabled','disabled']] Whether core dumps should be restricted on the system. Default value: 'enabled'.
# @param single_user_authentication [Enum['enabled','disabled']] Whether authentication is required for single-user mode. Default value: 'enabled'.
# @param motd [String] Source file for the contents of /etc/motd. Default value: 'puppet:///modules/cisecurity/banners/motd'.
# @param selinux [Enum['enforcing','permissive','disabled']] Desired state of selinux. Default value: 'enforcing'.
# @param selinux_type [Enum['targeted','minimum','mls']] Desired state of selinux type. Default value: 'targeted'.
# @param secure_terminals [Array[String]] List of terminals considered safe for root to log into directly. Default value: ['console','tty1','tty2','tty3','tty4','tty5','tty6','tty7','tty8','tty9','tty10','tty11','ttyS0']

class cisecurity::packages (

  Enum['enabled','disabled'] $aslr                          = 'enabled',
  String $banner_message_text                               = 'Authorized uses only. All activity may be monitored and reported.',
  String $bootloader_password                               = 'grub.pbkdf2.sha512.10000.9218D397421145AC7721CB920B48CF0B1F435052D4CAA3AD838DB8C6E89ADAB8E5A4CA493608A6307D69877163668690158CAF8421F6411E0F720DC711C111C9.605342B230DA20A2761831CA8C2EA2E645F183CF4EA8A7E65FFCA686E53955380F26E948DA66F063FB00051B8ACDECB1D38F00E4595CB915FF12049F78FB1E3A',
  Enum['enabled','disabled'] $configure_system_acct_nologin = 'enabled',
  String $issue                                             = 'puppet:///modules/cisecurity/banners/issue',
  String $issue_net                                         = 'puppet:///modules/cisecurity/banners/issue.net',
  Enum['enabled','disabled'] $restricted_core_dumps         = 'enabled',
  Enum['enabled','disabled'] $single_user_authentication    = 'enabled',
  String $motd                                              = 'puppet:///modules/cisecurity/banners/motd',
  Enum['enforcing','permissive','disabled'] $selinux        = 'enforcing',
  Enum['targeted','minimum','mls'] $selinux_type            = 'targeted',
  Array[String] $secure_terminals                          = [
    'console',
    'tty1',
    'tty2',
    'tty3',
    'tty4',
    'tty5',
    'tty6',
    'tty7',
    'tty8',
    'tty9',
    'tty10',
    'tty11',
    'ttyS0',
                                                              ]
) {

  if $bootloader_password != '' {
    grub_user { 'root':
      ensure    => present,
      password  => $bootloader_password,
      superuser => true,
    }

    exec { "grub2-mkconfig -o ${grubcfg}":
      path        => [ '/usr/sbin', '/sbin', '/usr/bin', '/bin' ],
      refreshonly => true,
      subscribe   => Grub_user['root'],
    }
  } else {
    grub_user { 'root':
      ensure    => absent,
      password  => $bootloader_password,
      superuser => true,
    }

    exec { "grub2-mkconfig -o ${grubcfg}":
      path        => [ '/usr/sbin', '/sbin', '/usr/bin', '/bin' ],
      refreshonly => true,
      subscribe   => Grub_user['root'],
    }
  }

  if $aslr == 'enabled' {
    sysctl { 'kernel.randomize_va_space':
      ensure  => present,
      value   => '2',
      comment => 'Setting managed by Puppet cisecurity module.',
    }
  }

  if $motd != '' {
    file { '/etc/motd':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
      source => $motd,
    }
  }

  if $issue != '' {
    file { '/etc/issue':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
      source => $issue,
    }
  }

  if $issue_net != '' {
    file { '/etc/issue.net':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
      source => $issue_net,
    }
  }

  if $facts['cisecurity']['installed_packages']['gdm'] != undef {
    $gdm_file = '/etc/dconf/profile/gdm'
    file { $gdm_file:
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }

    $gdmconfig = [
      'user-db:user',
      'system-db:gdm',
      'file-db:/usr/share/gdm/greeter-dconf-defaults',
    ]
    $gdmconfig.each | String $line | {
      file_line { "${gdm_file} add ${line}":
        ensure  => present,
        path    => $gdm_file,
        line    => $line,
        require => File[$gdm_file],
        notify  => Exec['dconf update'],
      }
    }

    $gdm_banner_file = '/etc/dconf/db/gdm.d/01-banner-message'
    file { $gdm_banner_file:
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }

    $bannerconfig = {
      'banner-message-enable' => 'true',
      'banner_message_text'   => $gdm_banner_text
    }
    $bannerconfig.each | String $setting, String $value | {
      ini_setting { "${gdm_banner_file} add ${setting}":
        ensure  => present,
        path    => $gdm_banner_file,
        section => 'org/gnome/login-screen',
        setting => $setting,
        value   => $value,
        require => File[$gdm_banner_file],
        notify  => Exec['dconf update'],
      }
    }

    exec { 'dconf update':
      path        => [ '/sbin', '/bin' ],
      refreshonly => true,
    }
  }

  if $selinux == 'enforcing' {
    kernel_parameter { 'selinux':
      ensure => present,
      value  => '1',
    }
    kernel_parameter { 'enforcing':
      ensure => present,
      value  => '1',
    }
  } else {
    kernel_parameter { 'selinux':
      ensure => absent,
      value  => '1',
    }
    kernel_parameter { 'enforcing':
      ensure => absent,
      value  => '1',
    }
  }

  class { '::selinux':
    mode => $selinux,
    type => $selinux_type,
  }

  if $restricted_core_dumps == 'enabled' {
    file { '/etc/security/limits.d/CIS.conf':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }

    file_line { '/etc/security/limits.d/CIS.conf':
      ensure  => present,
      path    => '/etc/security/limits.d/CIS.conf',
      line    => '* hard core 0',
      require => File['/etc/security/limits.d/CIS.conf'],
    }

    sysctl { 'fs.suid_dumpable':
      ensure  => present,
      value   => '0',
      comment => 'Setting managed by Puppet cisecurity module.',
    }
  }

  if $single_user_authentication == 'enabled' {
    ini_setting { 'emergency.service ExecStart':
      ensure  => present,
      path    => '/usr/lib/systemd/system/emergency.service',
      section => 'Service',
      setting => 'ExecStart',
      value   => '-/bin/sh -c "/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"'
    }

    ini_setting { 'rescue.service ExecStart':
      ensure  => present,
      path    => '/usr/lib/systemd/system/rescue.service',
      section => 'Service',
      setting => 'ExecStart',
      value   => '-/bin/sh -c "/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"'
    }
  }

  if $facts['cisecurity']['unconfined_daemons'] != undef and !empty($facts['cisecurity']['unconfined_daemons']) {
    warning ('One or more unconfined daemons found running on this system.')
  }

  if $facts['architecture'] != 'x86_64' {
    warning ('The system appears to be running on an x86 system.  Make sure PAE extensions are installed and NX/XD support properly configured.')
  }

  if !empty($secure_terminals) {
    $ttys = join($cisecurity::secure_terminals, "\n")
    file { '/etc/securetty':
      ensure  => file,
      owner   => 'root',
      group   => 'root',
      mode    => '0600',
      content => $ttys,
    }
  }

  if $configure_system_acct_nologin {
    $facts['cisecurity']['system_accounts_with_valid_shell'].each | $username | {
      exec { "usermod -s /sbin/nologin ${username}":
        path => [ '/sbin', '/usr/sbin' ],
      }
    }
  }

}
