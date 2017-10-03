# redhat7/network
#
# Implements Center of Internet Security network controls.
#
# @param dccp [Enum['enabled','disabled']] Whether DCCP protocol is enabled on the system. Default value: 'disabled'.
# @param hosts_allow [String] Source file for the contents of /etc/hosts.allow. Default value: 'puppet:///modules/cisecurity/tcp_wrappers/hosts.allow'.
# @param hosts_deny [String] Source file for the contents of /etc/hosts.deny. Default value: 'puppet:///modules/cisecurity/tcp_wrappers/hosts.deny'.
# @param ipv4_forwarding [Enum['enabled','disabled']] Whether the system will route packets. Default value: 'disabled'.
# @param ipv4_icmp_redirects [Enum['enabled','disabled']] Whether the system will accept ICMP redirects. Default value: 'disabled'.
# @param ipv4_ignore_icmp_bogus_responses [Enum['enabled','disabled']] Whether the system will ignore bogus ICMP responses. Default value: 'enabled'.
# @param ipv4_ignore_icmp_broadcasts [Enum['enabled','disabled']] Whether the system will ignore ICMP broadcast messages. Default value: 'enabled'.
# @param ipv4_log_suspicious_packets [Enum['enabled','disabled']] Whether the system will log suspicious packets (martians). Default value: 'enabled'.
# @param ipv4_reverse_path_filtering [Enum['enabled','disabled']] Whether the system will utilize reverse path filtering on a received packet to determine validity. Default value: 'enabled'.
# @param ipv4_secure_redirects [Enum['enabled','disabled']] Whether the system will accept secure ICMP redirects. Default value: 'disabled'.
# @param ipv4_send_redirects [Enum['enabled','disabled']] Whether the system will send ICMP redirects. Default value: 'disabled'.
# @param ipv4_source_routing [Enum['enabled','disabled']] Whether the system will accept source-routed packets. Default value: 'disabled'.
# @param ipv4_tcp_syncookies [Enum['enabled','disabled']] Whether the system utilizes TCP SYN cookie handling. Default value: 'enabled'.
# @param ipv6 [Enum['enabled','disabled']] Whether the system utilizes IPv6. Default value: 'disabled'.
# @param ipv6_accept_router_advertisements [Enum['enabled','disabled']] Whether the system will accept IPv6 router advertisements. Default value: 'disabled'.
# @param ipv6_packet_redirects [Enum['enabled','disabled']] Whether the system will accept IPv6 redirects. Default value: 'disabled'.
# @param rds [Enum['enabled','disabled']] Whether RDS protocol is enabled on the system. Default value: 'disabled'.
# @param sctp [Enum['enabled','disabled']] Whether SCTP protocol is enabled on the system. Default value: 'disabled'.
# @param tipc [Enum['enabled','disabled']] Whether TIPC protocol is enabled on the system. Default value: 'disabled'.
# @param wireless_interfaces [Enum['enabled','disabled']] Whether the system utilizes wireless interfaces. Default value: 'disabled'.

class cisecurity::redhat7::network (
  Enum['enabled','disabled'] $dccp,
  String $hosts_allow,
  String $hosts_deny,
  Enum['enabled','disabled'] $ipv4_forwarding,
  Enum['enabled','disabled'] $ipv4_icmp_redirects,
  Enum['enabled','disabled'] $ipv4_ignore_icmp_bogus_responses,
  Enum['enabled','disabled'] $ipv4_ignore_icmp_broadcasts,
  Enum['enabled','disabled'] $ipv4_log_suspicious_packets,
  Enum['enabled','disabled'] $ipv4_reverse_path_filtering,
  Enum['enabled','disabled'] $ipv4_secure_redirects,
  Enum['enabled','disabled'] $ipv4_send_redirects,
  Enum['enabled','disabled'] $ipv4_source_routing,
  Enum['enabled','disabled'] $ipv4_tcp_syncookies,
  Enum['enabled','disabled'] $ipv6,
  Enum['enabled','disabled'] $ipv6_accept_router_advertisements,
  Enum['enabled','disabled'] $ipv6_packet_redirects,
  Enum['enabled','disabled'] $rds,
  Enum['enabled','disabled'] $sctp,
  Enum['enabled','disabled'] $tipc,
  Enum['enabled','disabled'] $wireless_interfaces,
) {

  # Private variables.
  $protocol_list = [
    'dccp',
    'sctp',
    'rds',
    'tipc',
  ]

  $protocol_list.each | String $protocol | {
    if getvar($protocol) == 'enabled' {
      file_line { $protocol:
        ensure  => absent,
        path    => '/etc/modprobe.d/CIS.conf',
        line    => "install ${protocol} /bin/true",
        require => [ File['/etc/modprobe.d' ], File['/etc/modprobe.d/CIS.conf'] ]
      }
    } else {
      file_line { $protocol:
        ensure  => present,
        path    => '/etc/modprobe.d/CIS.conf',
        line    => "install ${protocol} /bin/true",
        require => [ File['/etc/modprobe.d' ], File['/etc/modprobe.d/CIS.conf'] ]
      }
    }
  }

  if $ipv4_forwarding == 'enabled' {
    sysctl { 'net.ipv4.ip_forward':
      ensure  => present,
      value   => '1',
      comment => 'Setting managed by Puppet.'
    }
  } else {
    sysctl { 'net.ipv4.ip_forward':
      ensure  => present,
      value   => '0',
      comment => 'Setting managed by Puppet.'
    }
  }

  if $ipv4_ignore_icmp_bogus_responses == 'enabled' {
    sysctl { 'net.ipv4.icmp_ignore_bogus_error_responses':
      ensure  => present,
      value   => '1',
      comment => 'Setting managed by Puppet.'
    }
  } else {
    sysctl { 'net.ipv4.icmp_ignore_bogus_error_responses':
      ensure  => present,
      value   => '0',
      comment => 'Setting managed by Puppet.'
    }
  }


  if $ipv4_ignore_icmp_broadcasts == 'enabled' {
    sysctl { 'net.ipv4.icmp_echo_ignore_broadcasts':
      ensure  => present,
      value   => '1',
      comment => 'Setting managed by Puppet.'
    }
  } else {
    sysctl { 'net.ipv4.icmp_echo_ignore_broadcasts':
      ensure  => present,
      value   => '0',
      comment => 'Setting managed by Puppet.'
    }
  }

  if $ipv4_icmp_redirects == 'enabled' {
    sysctl { 'net.ipv4.conf.all.accept_redirects':
      ensure  => present,
      value   => '1',
      comment => 'Setting managed by Puppet.'
    }
    sysctl { 'net.ipv4.conf.default.accept_redirects':
      ensure  => present,
      value   => '1',
      comment => 'Setting managed by Puppet.'
    }
  } else {
    sysctl { 'net.ipv4.conf.all.accept_redirects':
      ensure  => present,
      value   => '0',
      comment => 'Setting managed by Puppet.'
    }
    sysctl { 'net.ipv4.conf.default.accept_redirects':
      ensure  => present,
      value   => '0',
      comment => 'Setting managed by Puppet.'
    }
  }

  if $ipv4_log_suspicious_packets == 'enabled' {
    sysctl { 'net.ipv4.conf.all.log_martians':
      ensure  => present,
      value   => '1',
      comment => 'Setting managed by Puppet.'
    }
    sysctl { 'net.ipv4.conf.default.log_martians':
      ensure  => present,
      value   => '1',
      comment => 'Setting managed by Puppet.'
    }
  } else {
    sysctl { 'net.ipv4.conf.all.log_martians':
      ensure  => present,
      value   => '0',
      comment => 'Setting managed by Puppet.'
    }
    sysctl { 'net.ipv4.conf.default.log_martians':
      ensure  => present,
      value   => '0',
      comment => 'Setting managed by Puppet.'
    }
  }

  if $ipv4_send_redirects == 'enabled' {
    sysctl { 'net.ipv4.conf.all.send_redirects':
      ensure  => present,
      value   => '1',
      comment => 'Setting managed by Puppet.'
    }
    sysctl { 'net.ipv4.conf.default.send_redirects':
      ensure  => present,
      value   => '1',
      comment => 'Setting managed by Puppet.'
    }
  } else {
    sysctl { 'net.ipv4.conf.all.send_redirects':
      ensure  => present,
      value   => '0',
      comment => 'Setting managed by Puppet.'
    }
    sysctl { 'net.ipv4.conf.default.send_redirects':
      ensure  => present,
      value   => '0',
      comment => 'Setting managed by Puppet.'
    }
  }

  if $ipv4_reverse_path_filtering == 'enabled' {
    sysctl { 'net.ipv4.conf.all.rp_filter':
      ensure  => present,
      value   => '1',
      comment => 'Setting managed by Puppet.'
    }
    sysctl { 'net.ipv4.conf.default.rp_filter':
      ensure  => present,
      value   => '1',
      comment => 'Setting managed by Puppet.'
    }
  } else {
    sysctl { 'net.ipv4.conf.all.rp_filter':
      ensure  => present,
      value   => '0',
      comment => 'Setting managed by Puppet.'
    }
    sysctl { 'net.ipv4.conf.default.rp_filter':
      ensure  => present,
      value   => '0',
      comment => 'Setting managed by Puppet.'
    }
  }

  if $ipv4_secure_redirects == 'enabled' {
    sysctl { 'net.ipv4.conf.all.secure_redirects':
      ensure  => present,
      value   => '1',
      comment => 'Setting managed by Puppet.'
    }
    sysctl { 'net.ipv4.conf.default.secure_redirects':
      ensure  => present,
      value   => '1',
      comment => 'Setting managed by Puppet.'
    }
  } else {
    sysctl { 'net.ipv4.conf.all.secure_redirects':
      ensure  => present,
      value   => '0',
      comment => 'Setting managed by Puppet.'
    }
    sysctl { 'net.ipv4.conf.default.secure_redirects':
      ensure  => present,
      value   => '0',
      comment => 'Setting managed by Puppet.'
    }
  }

  if $ipv4_source_routing == 'enabled' {
    sysctl { 'net.ipv4.conf.all.accept_source_route':
      ensure  => present,
      value   => '1',
      comment => 'Setting managed by Puppet.'
    }
    sysctl { 'net.ipv4.conf.default.accept_source_route':
      ensure  => present,
      value   => '1',
      comment => 'Setting managed by Puppet.'
    }
  } else {
    sysctl { 'net.ipv4.conf.all.accept_source_route':
      ensure  => present,
      value   => '0',
      comment => 'Setting managed by Puppet.'
    }
    sysctl { 'net.ipv4.conf.default.accept_source_route':
      ensure  => present,
      value   => '0',
      comment => 'Setting managed by Puppet.'
    }
  }

  if $ipv4_tcp_syncookies == 'enabled' {
    sysctl { 'net.ipv4.tcp_syncookies':
      ensure  => present,
      value   => '1',
      comment => 'Setting managed by Puppet.'
    }
  } else {
    sysctl { 'net.ipv4.tcp_syncookies':
      ensure  => present,
      value   => '0',
      comment => 'Setting managed by Puppet.'
    }
  }

  if $ipv6_accept_router_advertisements == 'enabled' {
    sysctl { 'net.ipv6.conf.all.accept_ra':
      ensure  => present,
      value   => '1',
      comment => 'Setting managed by Puppet.'
    }
    sysctl { 'net.ipv6.conf.default.accept_ra':
      ensure  => present,
      value   => '1',
      comment => 'Setting managed by Puppet.'
    }
  } else {
    sysctl { 'net.ipv6.conf.all.accept_ra':
      ensure  => present,
      value   => '0',
      comment => 'Setting managed by Puppet.'
    }
    sysctl { 'net.ipv6.conf.default.accept_ra':
      ensure  => present,
      value   => '0',
      comment => 'Setting managed by Puppet.'
    }
  }

  if $ipv6_packet_redirects == 'enabled' {
    sysctl { 'net.ipv6.conf.all.accept_redirects':
      ensure  => present,
      value   => '1',
      comment => 'Setting managed by Puppet.'
    }
    sysctl { 'net.ipv6.conf.default.accept_redirects':
      ensure  => present,
      value   => '1',
      comment => 'Setting managed by Puppet.'
    }
  } else {
    sysctl { 'net.ipv6.conf.all.accept_redirects':
      ensure  => present,
      value   => '0',
      comment => 'Setting managed by Puppet.'
    }
    sysctl { 'net.ipv6.conf.default.accept_redirects':
      ensure  => present,
      value   => '0',
      comment => 'Setting managed by Puppet.'
    }
  }

  if $ipv6 == 'enabled' {
    file_line { 'ipv6':
      ensure  => present,
      path    => '/etc/modprobe.d/CIS.conf',
      line    => 'options ipv6 disable=0',
      require => File[ ['/etc/modprobe.d'], File['/etc/modprobe.d/CIS.conf'] ]
    }
  } else {
    file_line { 'ipv6':
      ensure  => present,
      path    => '/etc/modprobe.d/CIS.conf',
      line    => 'options ipv6 disable=1',
      require => [ File['/etc/modprobe.d'], File['/etc/modprobe.d/CIS.conf'] ]
    }
  }

  if $wireless_interfaces == 'disabled' {
    $facts['networking']['interfaces'].each | String $interface, Hash $info | {
      if $interface =~ 'wlan' {
        exec { "ip link set ${interface} down":
          path => [ '/sbin', '/bin' ]
        }
      }
    }
  }

  if $hosts_allow != '' {
    file { '/etc/hosts.allow':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
      source => $hosts_allow,
    }
  }

  if $hosts_deny != '' {
    file { '/etc/hosts.deny':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
      source => $hosts_deny,
    }
  }

}
