# redhat7/filesystem
#
# Implements Center of Internet Security filesystem controls.

class cisecurity::redhat7::filesystem (
  Enum['enabled','disabled'] $configure_umask_default,
  Enum['enabled','disabled'] $cramfs,
  Array[String] $dev_shm_mount_options,
  Enum['enabled','disabled'] $freevxfs,
  Enum['enabled','disabled'] $harden_system_file_perms,
  Enum['enabled','disabled'] $hfs,
  Enum['enabled','disabled'] $hfsplus,
  Array[String] $home_mount_options,
  Enum['enabled','disabled'] $jffs2,
  String $log_file_perms_cron_start_hour,
  String $log_file_perms_cron_start_minute,
  Enum['enabled','disabled'] $remediate_log_file_perms,
  Enum['enabled','disabled'] $remediate_ungrouped_files,
  Enum['enabled','disabled'] $remediate_unowned_files,
  Enum['enabled','disabled'] $remediate_world_writable_dirs,
  Enum['enabled','disabled'] $remediate_world_writable_files,
  Array[String] $removable_media_mount_options,
  Array[String] $removable_media_partitions,
  Enum['enabled','disabled'] $squashfs,
  Array[String] $tmp_mount_options,
  Enum['enabled','disabled'] $udf,
  String[3] $umask_default,
  String $ungrouped_files_replacement_group,
  String $unowned_files_replacement_owner,
  Array[String] $var_mount_options,
  Array[String] $var_log_audit_mount_options,
  Array[String] $var_log_mount_options,
  Array[String] $var_tmp_mount_options,
  Array[String] $world_writable_dirs_ignored,
  Array[String] $world_writable_files_ignored,
  Enum['enabled','disabled'] $vfat,
) {

  file { '/etc/modprobe.d':
    ensure => directory,
    mode   => '0755',
    owner  => 'root',
    group  => 'root',
  }

  file { '/etc/modprobe.d/CIS.conf':
    ensure => file,
    mode   => '0644',
    owner  => 'root',
    group  => 'root',
  }

  file { '/etc/puppetlabs/facter/facts.d/cisecurity.yaml':
    ensure => absent,
  }

  $filesystem_list = [
    'cramfs',
    'freevxfs',
    'jffs2',
    'hfs',
    'hfsplus',
    'squashfs',
    'udf',
    'vfat',
  ]
  if $facts['cisecurity']['efi'] == undef {
    notice ('Cannot configure filesystems because required external facts are unavailable. This may be transient.')
  } else {
    $filesystem_list.each | String $filesystem | {
      if getvar($filesystem) == 'disabled' {
        if $facts['cisecurity']['efi'] == true and $filesystem == 'vfat' {
          # Do nothing... EFI systems must have vfat enabled!
        } else {
          file_line { $filesystem:
            ensure => present,
            path   => '/etc/modprobe.d/CIS.conf',
            line   => "install ${filesystem} /bin/true",
          }
        }
      }
    }
  }

  if $facts['mountpoints']['/tmp'] == undef {
    notice ('Cannot configure mount options for /tmp because it\'s not a valid partition.')
  } elsif !empty($tmp_mount_options ) {
    if $facts['mountpoints']['/tmp']['filesystem'] == 'tmpfs' {
      exec { 'systemctl unmask tmp.mount':
        path      => [ 'bin', '/usr/bin' ],
        logoutput => on_failure,
        unless    => 'ls /etc/systemd/system/local-fs.target.wants/tmp.mount',
      }
      ini_setting { 'tmp mount options':
        ensure  => present,
        path    => '/etc/systemd/system/local-fs.target.wants/tmp.mount',
        section => 'Mount',
        setting => 'Options',
        value   => $tmp_mount_options,
        require => Exec['systemctl unmask tmp.mount'],
      }
      service { 'tmp.mount':
        ensure   => running,
        enable   => true,
        remounts => false,
        require  => Ini_setting['tmp mount options'],
      }
    } else {
      $flattened_tmp_options = join($tmp_mount_options, ',')
      mount { '/tmp':
        ensure   => present,
        options  => $flattened_tmp_options,
        remounts => false,
      }
    }
  }

  if $facts['mountpoints']['/var'] == undef {
    notice ('Cannot configure mount options for /var because it\'s not a valid partition.')
  } elsif !empty($var_mount_options) {
    $flattened_var_options = join($var_mount_options, ',')
    mount { '/var':
      ensure   => present,
      options  => $flattened_var_options,
      remounts => false,
    }
  }

  if !empty($var_tmp_mount_options) {
    $flattened_var_tmp_options = join($var_tmp_mount_options, ',')
    mount { '/var/tmp':
      ensure  => mounted,
      device  => '/tmp',
      fstype  => 'none',
      options => $flattened_var_tmp_options,
    }
  }

  if $facts['mountpoints']['/var/log'] == undef {
    notice ('Cannot configure mount options for /var/log because it\'s not a valid partition.')
  } elsif !empty($var_log_mount_options) {
    $flattened_var_log_options = join($var_log_mount_options, ',')
    mount { '/var/log':
      ensure   => present,
      options  => $flattened_var_log_options,
      remounts => false,
    }
  }

  if $facts['mountpoints']['/var/log/audit'] == undef {
    notice ('Cannot configure mount options for /var/log/audit because it\'s not a valid partition.')
  } elsif !empty($var_log_audit_mount_options) {
    $flattened_var_log_audit_options = join($var_log_audit_mount_options, ',')
    mount { '/var/log/audit':
      ensure   => present,
      options  => $flattened_var_log_audit_options,
      remounts => false,
    }
  }

  if $facts['mountpoints']['/home'] == undef {
    notice ('Cannot configure mount options for /home because it\'s not a valid partition.')
  } elsif !empty($home_mount_options) {
    $flattened_home_options = join($home_mount_options, ',')
    mount { '/home':
      ensure   => present,
      options  => $flattened_home_options,
      remounts => false,
    }
  }

  if $facts['mountpoints']['/dev/shm'] == undef {
    notice ('Cannot configure mount options for /dev/shm because it\'s not a valid partition.')
  } elsif !empty($dev_shm_mount_options) {
    $flattened_shm_options = join($dev_shm_mount_options, ',')
    mount { '/dev/shm':
      ensure   =>  'mounted',
      name     => '/dev/shm',
      device   => 'shmfs',
      fstype   => 'tmpfs',
      options  => $flattened_shm_options,
      remounts => false,
    }
  }

  $flattened_media_options = join($removable_media_mount_options, ',')
  $removable_media_partitions.each | String $partition | {
    mount { $partition:
      ensure   => present,
      options  => $flattened_media_options,
      remounts => false,
      atboot   => false,
    }
  }

  if $remediate_world_writable_dirs == 'enabled' {
    if $facts['cisecurity']['world_writable_dirs'] != undef {
      $facts['cisecurity']['world_writable_dirs'].each | String $directory | {
        if !$directory in $world_writable_dirs_ignored {
          file { $directory:
            ensure => directory,
            mode   => 'o+t',
          }
        }
      }
    } else {
      notice ('Cannot remediate world writable dirs because required external facts are unavailable. This may be transient.')
    }
  }

  if $remediate_world_writable_files == 'enabled' {
    if $facts['cisecurity']['world_writable_files'] != undef {
      $facts['cisecurity']['world_writable_files'].each | String $file | {
        if !$file in $world_writable_files_ignored {
          file { $file:
            ensure => file,
            mode   => 'o-w',
          }
        }
      }
    } else {
      notice ('Cannot remediate world writable files because required external facts are unavailable. This may be transient.')
    }
  }

  if $remediate_unowned_files == 'enabled' {
    if $facts['cisecurity']['unowned_files'] != undef {
      $facts['cisecurity']['unowned_files'].each | String $file | {
        unless File[$file] {
          file { $file:
            ensure => file,
            owner  => $unowned_files_replacement_owner,
          }
        }
      }
    } else {
      notice ('Cannot remediate unowned files because required exteranl facts are unavailable. This may be transient.')
    }
  }

  if $remediate_ungrouped_files == 'enabled' {
    if $facts['cisecurity']['ungrouped_files'] != undef {
      $facts['cisecurity']['ungrouped_files'].each | String $file | {
        unless File[$file] {
          file { $file:
            ensure => file,
            gid    => $ungrouped_files_replacement_group,
          }
        }
      }
    } else {
      notice ('Cannot remediate ungrouped files because required external facts are unavailable. This may be transient.')
    }
  }

  if $configure_umask_default == 'enabled' {
    file { '/etc/bashrc':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }
    file { '/etc/profile':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }
    file_line { '/etc/bashrc':
      ensure             => present,
      path               => '/etc/bashrc',
      line               => "umask ${umask_default}",
      match              => '^\s*umask 022$',
      append_on_no_match => false,
    }
    file_line { '/etc/profile':
      ensure             => present,
      path               => '/etc/profile',
      line               => "umask ${umask_default}",
      match              => '^\s*umask 022$',
      append_on_no_match => false,
    }
  }

  if $harden_system_file_perms == 'enabled' {
    file { '/boot/grub2/grub.cfg':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0600',
    }
    file { '/boot/grub2/user.cfg':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0600',
    }
    file { '/etc/passwd':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }
    file { '/etc/shadow':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0000',
    }
    file { '/etc/group':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }
    file { '/etc/gshadow':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0000',
    }
    file { '/etc/passwd-':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }
    file { '/etc/shadow-':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0000',
    }
    file { '/etc/group-':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }
    file { '/etc/gshadow-':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0000',
    }
    file { '/etc/crontab':
      ensure => file,
      group  => 'root',
      owner  => 'root',
      mode   => '0600',
    }
    if $cisecurity::redhat7::services::configure_at_allow == 'disabled' {
      file { '/etc/at.allow':
        ensure => file,
        group  => 'root',
        owner  => 'root',
        mode   => '0600',
      }
    }
    if $cisecurity::redhat7::services::configure_cron_allow  == 'disabled' {
      file { '/etc/cron.allow':
        ensure => file,
        group  => 'root',
        owner  => 'root',
        mode   => '0600',
      }
    }
    $crondirs = [ '/etc/cron.hourly', '/etc/cron.daily', '/etc/cron.weekly', '/etc/cron.monthly', '/etc/cron.d' ]
    $crondirs.each | String $directory | {
      file { $directory:
        ensure => directory,
        group  => 'root',
        owner  => 'root',
        mode   => '0700',
      }
    }
    file { '/etc/ssh/sshd_config':
      ensure => file,
      mode   => '0600',
      owner  => 'root',
      group  => 'root',
    }
  }

  if $remediate_log_file_perms == 'enabled' {
    cron { 'remediate_log_file_perms':
      ensure  => present,
      command => 'find /var/log -type f ! -path \'/var/log/puppetlabs/mcollective*.log\' -exec chmod g-wx,o-rwx {} \;',
      user    => 'root',
      hour    => $log_file_perms_cron_start_hour,
      minute  => $log_file_perms_cron_start_minute,
    }
  }

}
