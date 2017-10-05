#!/bin/bash
# This file is managed by Puppet.

<% if $remediate_home_directories_exist == 'enabled' {-%>
# Control 6.2.7 - Ensure all users' home directories exist
cat /etc/passwd | awk -F: '{print $1 " " $3 " " $6}' | while read USER UID DIR; do
    if [ $UID -ge 1000 -a ! -d "$DIR" -a $USER != "nfsnobody" ]; then
        mkdir $DIR
        chmod <%= $home_directories_perm %> $DIR
        cp /etc/skel/.* $DIR
        cp /etc/skel/* $DIR
        chown -R $UID $DIR
        chgrp -R $UID $DIR
    fi
done
<% }-%>

<% if $remediate_home_directories_perms == 'enabled' {-%>
# Control 6.2.8 - Ensure users' home directories permissions are 750 or more restrictive
cat /etc/passwd | awk -F: '{print $1 " " $3 " " $6}' | while read USER UID DIR; do
    if [ $UID -ge 1000 -a ! -d "$DIR" -a $USER != "nfsnobody" ]; then
        chmod <%= $home_directories_perm %> $DIR
    fi
done
<% }-%>

<% if $remediate_home_directories_owner == 'enabled' {-%>
# Control 6.2.9 - Ensure users own their home directories
cat /etc/passwd | awk -F: '{print $1 " " $3 " " $6}' | while read USER UID DIR; do
    if [ $UID -ge 1000 -a -d "$DIR" -a $USER != "nfsnobody" ]; then
        OWNER=$(stat -L -c "%U" "$DIR")
        if [ "$OWNER" != "$USER" ]; then
            chown $USER $DIR
        fi
    fi
done
<% }-%>

<% if $remediate_home_directories_dot_files == 'enabled' {-%>
# Control 6.2.10 - Ensure users' dot files are not group or world writable
for DIR in `cat /etc/passwd | egrep -v '(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
    for FILE in $DIR/.[A-Za-z0-9]*; do
        if [ ! -h "$FILE" -a -f "$FILE" ]; then
            chmod 'g-w,o-w' $FILE
        fi
    done
done
<% }-%>

<% if $remediate_home_directories_forward_files == 'enabled' {-%>
# Control 6.2.11 - Ensure no users have .forward files
for DIR in `cat /etc/passwd | awk -F: '{ print $6 }'`; do
    if [ ! -h "$DIR/.forward" -a -f "$DIR/.forward" ]; then
        rm -f "$DIR/.forward"
    fi
done
<% }-%>

<% if $remediate_home_directories_netrc_files == 'enabled' {-%>
# Control 6.2.12 - Ensure no users have .netrc files
for DIR in `cat /etc/passwd | awk -F: '{ print $6 }'`; do
    if [ ! -h "$DIR/.netrc" -a -f "$DIR/.netrc" ]; then
        rm -f "$DIR/.netrc"
    fi
done
<% }-%>

<% if $remediate_home_directories_netrc_files_perms == 'enabled' {-%>
# Control 6.2.13 - Ensure users' .netrc files are not group or world accessible
for DIR in `cat /etc/passwd | awk -F: '{ print $6 }'`; do
    if [ ! -h "$DIR/.netrc" -a -f "$DIR/.netrc" ]; then
        chmod 'g-w,o-w' "$DIR/.netrc"
    fi
done
<% }-%>

<% if $remediate_home_directories_rhosts_files == 'enabled' {-%>
# Control 6.2.14 - Ensure no users have .rhosts files
for DIR in `cat /etc/passwd | egrep -v '(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
    if [ ! -h "$DIR/.rhosts" -a -f "$DIR/.rhosts" ]; then
        rm -f "$DIR/.rhosts"
    fi
done
<% }-%>

<% if $verify_user_groups_exist == 'enabled' {-%>
# Control 6.2.15 - Ensure all groups in /etc/passwd exist in /etc/group
for GROUP in $(cut -s -d: -f4 /etc/passwd | sort -u); do
    getent group $GROUP >/dev/null 2>&1
    if [ $? -ne 0 ]; then
      logger -p <%= $syslog_facility %>.<%= $syslog_severity %> -t cisecurity Group $GROUP is referenced in /etc/passwd but does not exist.
    fi
done
<% }-%>

<% if $verify_duplicate_uids_notexist == 'enabled' {-%>
# Control 6.2.16 - Ensure no duplicate UIDs exist
cat /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | while read UID; do
    [ -z "$UID" ] && break
    set - $UID
    if [ $1 -gt 1 ]; then
        USERS=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs`
        logger -p <%= $syslog_facility %>.<%= $syslog_severity %> -t cisecurity Duplicate UID ($2): $USERS
    fi
done
<% }-%>

<% if $verify_duplicate_gids_notexist == 'enabled' {-%>
# Control 6.2.17 - Ensure no duplicate GIDs exist
cat /etc/group | cut -f3 -d":" | sort -n | uniq -c | while read GID; do
    [ -z "$GID" ] && break
    set - $GID
    if [ $1 -gt 1 ]; then
        GROUPS=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/group | xargs`
        logger -p <%= $syslog_facility %>.<%= $syslog_severity %> -t cisecurity Duplicate GID ($2): $GROUPS
    fi
done
<% }-%>

<% if $verify_duplicate_usernames_notexist == 'enabled' {-%>
# Control 6.2.18 - Ensure no duplicate user names exist
cat /etc/passwd | cut -f1 -d":" | sort -n | uniq -c | while read UID; do
    [ -z "$UID" ] && break
    set - $UID
    if [ $1 -gt 1 ]; then
        UIDS=`awk -F: '($1 == n) { print $3 }' n=$2 /etc/passwd | xargs`
        logger -p <%= $syslog_facility %>.<%= $syslog_severity %> -t cisecurity Duplicate Username ($2): $UIDS
    fi
done
<% }-%>

<% if $verify_duplicate_groupnames_notexist == 'enabled' {-%>
# Control 6.2.19 - Ensure no duplicate group names exist
cat /etc/group | cut -f1 -d":" | sort -n | uniq -c | while read GID; do
    [ -z "$GID" ] && break
    set - $GID
    if [ $1 -gt 1 ]; then
        GIDS=`awk -F: '($1 == n) { print $3 }' n=$2 /etc/group | xargs`
        logger -p <%= $syslog_facility %>.<%= $syslog_severity %> -t cisecurity Duplicate Group Name ($2): $GIDS
    fi
done
<% }-%>
