# lib/facter/cisecurity.rb
#
# Custom facts needed for cisecurity.
# Original script courtesy jorhett
#

Facter.add("cisecurity") do
  require 'etc'

  # Figure out os-specific stuff up top
  if Facter.value(:puppetversion).to_i >= 4
    os_name = Facter.value(:os)[:name]
  else
    os_name = Facter.value(:operatingsystem)
  end

  cisecurity = {}
  cisecurity['efi'] = File.directory?('/sys/firmware/efi') ? true : false

  # accounts_with_blank_passwords
  cisecurity['accounts_with_blank_passwords'] = []
  File.readlines('/etc/shadow').collect do |line|
    if( line =~ /^(\w+)::/ )
      cisecurity['accounts_with_blank_passwords'].push($1)
    end
  end

  # accounts_with_uid_zero and system_accounts_with_valid_shell
  cisecurity['system_accounts_with_valid_shell'] = []
  cisecurity['accounts_with_uid_zero'] = []
  Etc.passwd do |entry|
    cisecurity['accounts_with_uid_zero'].push(entry.name) if entry.uid == 0
    unless entry.uid >= 1000 || ['root','sync','shutdown','halt'].include?(entry.name) || ['/sbin/nologin','/bin/false'].include?(entry.shell)
      cisecurity['system_accounts_with_valid_shell'].push(entry.name)
    end
  end

  # installed_packages
  cisecurity['installed_packages'] = {}
  packages = %x{rpm -qa --queryformat '[%{NAME}===%{VERSION}-%{RELEASE}\n]'}.split(/$/)
  unless packages.nil? || packages == []
    packages.each do |pkg|
      name, version = pkg.lstrip.split('===')
      unless name == '' || version == ''
        cisecurity['installed_packages'][name] = version
      end
    end
  end

  # package_system_file_variances
  cisecurity['package_system_file_variances'] = {}
  variances = %x{rpm -Va --nomtime --nosize --nomd5 --nolinkto}.split(/$/)
  unless variances.nil? || variances == []
    variances.each do |line|
      if( line =~ /^(\S+)\s+(c?)\s*(\/[\w\/\-\.]+)$/ )
        cisecurity['package_system_file_variances'][$3] = $1 if $2 != 'c'
      end
    end
  end

  # redhat_gpg_key_present
  gpg_keys = %x{rpm -q gpg-pubkey --qf '%{SUMMARY}\n' | grep 'release key'}
  gpgkey_mail = case os_name
    when 'CentOS'
      'security@centos.org'
    else
      'security@redhat.com'
    end
  cisecurity['redhat_gpg_key_present'] = gpg_keys.match(gpgkey_mail) ? true : false

  # root_path
  cisecurity['root_path'] = []
  ENV['PATH'].split(/:/).each do |path|
    cisecurity['root_path'].push(path)
  end

  # subscriptions
  cisecurity['subscriptions'] = {}
  if File.exists?('/usr/bin/subscription-manager')
    subs = %x{subscription-manager status | grep 'Overall Status'}
    unless subs.nil? || subs == ''
      name, value = subs.split(/:/)
      cisecurity['subscriptions'] = value.downcase.gsub(/\s+/, '').chomp
    end
  end

  # suid_sgid_files and ungrouped_files
  cisecurity['suid_sgid_files'] = []
  cisecurity['unowned_files'] = []
  cisecurity['ungrouped_files'] = []
  cisecurity['world_writable_files'] = []
  cisecurity['world_writable_dirs'] = []
  %x{df -l --exclude-type=tmpfs -P}.split(/$/).each do |fs|
    next if fs =~ /^Filesystem/ # header line
    root_path = fs.split[5]

    unowned_files = %x{find #{root_path} -xdev -nouser}.split(/\n/)
    unless unowned_files.nil? || unowned_files == ""
      unowned_files.each do |line|
        cisecurity['unowned_files'].push(line)
      end
    end

    ungrouped_files = %x{find #{root_path} -xdev -nogroup}.split(/\n/)
    unless ungrouped_files.nil? || ungrouped_files == ""
      ungrouped_files.each do |line|
        cisecurity['ungrouped_files'].push(line)
      end
    end

    suid_sgid_files = %x{find #{root_path} -xdev -type f \\( -perm -4000 -o -perm -2000 \\)}.split(/\n/)
    unless suid_sgid_files.nil? || suid_sgid_files == ""
      suid_sgid_files.each do |line|
        cisecurity['suid_sgid_files'].push(line)
      end
    end

    world_writable_files = %x{find #{root_path} -xdev -type f -perm -0002}.split(/\n/)
    unless world_writable_files.nil? || world_writable_files == ""
      world_writable_files.each do |line|
        cisecurity['world_writable_files'].push(line)
      end
    end

    world_writable_dirs = %x{find #{root_path} -xdev -type d \\( -perm -0002 -a ! -perm -1000 \\)}.split(/\n/)
    unless world_writable_dirs.nil? || world_writable_dirs == ""
      world_writable_dirs.each do |line|
        cisecurity['world_writable_dirs'].push(line)
      end
    end
  end

  # unconfined_daemons
  cisecurity['unconfined_daemons'] = []
  %x{ps -eZ}.split(/$/).each do |line|
    next unless line =~ /initlc/
    cisecurity['unconfined_daemons'].push(line.split[-1])
  end

  # yum_enabled_repos
  cisecurity['yum_enabled_repos'] = []
  yum_repos = %x{yum repolist enabled}.split(/$/)
  unless yum_repos.nil? || yum_repos == []
    yum_repos.each do |line|
      next if line =~ /^Loaded / || line =~ /^Loading / # headers
      next if line =~ /^repo id *repo name / # column header
      next if line =~ /^ \* / # mirror list
      next if line =~ /^repolist: / # footer
      unless line.split[0] == '' || line.split[0] == ':'
        cisecurity['yum_enabled_repos'].push(line.split[0])
      end
    end
  end

  # yum_repos_gpg_check_consistent
  disabled_gpg = system('grep gpgcheck /etc/yum.repos.d/*.repo | grep 0 > /dev/null')
  cisecurity['yum_repos_gpgcheck_consistent'] = disabled_gpg ? false : true

  setcode do
    cisecurity
  end
end
