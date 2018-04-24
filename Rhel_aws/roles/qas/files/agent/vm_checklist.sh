#!/bin/bash
if [ $USER != "root" ]
then
    echo " Run with super USER "
    exit 1
fi
>success.log
>error.log
#partition check for tmp
grep "[[:space:]]/tmp[[:space:]]" /etc/fstab >> /dev/null

if [ $? == 0 ]
then
        echo "/tmp partition is present" >> success.log
else
        echo "/tmp partition is present" >> error.log
fi

# To check nosuid
grep "[[:space:]]/tmp[[:space:]]" /etc/fstab |grep nosuid >> /dev/null
if [ $? == 0 ]
then
        echo "nosuid is present" >> success.log
else
        echo " nosuid is not present " >>  error.log
fi

# To check noexec
grep "[[:space:]]/tmp[[:space:]]" /etc/fstab |grep noexec >> /dev/null
if [ $? == 0 ]
then
        echo "noexec is present"  >> success.log
else
        echo " noexec is not present " >> error.log
fi

# to check /var partition
grep /var /etc/fstab >> /dev/null

if [ $? == 0 ]
then
        echo "/var partition is present"  >> success.log
else
        echo " /var partition is not present "  >> error.log
fi

#Bind Mount /var/tmp to /var
grep -e "^/tmp" /etc/fstab | grep /var/tmp >> /dev/null
if [ $? == 0 ]
then
        echo "Bind Mount /var/tmp to /var is present"  >> success.log
else
        echo " Bind Mount /var/tmp to /var not present "  >> error.log
fi

#create separate partion for /var/log
grep /var/log /etc/fstab >> /dev/null
if [ $? == 0 ]
then
        echo "create separate partion for /var/log is present"  >> success.log
else
        echo "create separate partion for /var/log not present " >> error.log
fi
#create separate partition for /var/log/audit
grep /var/log/audit /etc/fstab >> /dev/null
if [ $? == 0 ]
then
        echo "create separate partition for /var/log/audit is present"  >> success.log
else
        echo "create separate partition for /var/log/audit not present " >> error.log
fi

#Create Separate Partition for /home
grep /home /etc/fstab >> /dev/null
if [ $? == 0 ]
then
        echo "Create Separate Partition for /home is present"  >> success.log
else
        echo "Create Separate Partition for /home not present " >> error.log
fi
#Add nodev Option to /home--- mount | grep /home | grep noexec
mount | grep /home | grep noexec >> /dev/null

if [ $? == 0 ]
then
        echo "Add nodev Option to /home is present"  >> success.log
else
        echo "Add nodev Option to /home not present " >> error.log
fi

#Add nodev option to /dev/shm
mount | grep /dev/shm | grep nodev >> /dev/null
if [ $? == 0 ]
then
echo "Add nodev option to /dev/shm is present"  >> success.log
else
echo "Add nodev option to /dev/shm not present " >> error.log
fi

# Add nosuid Option to /dev/shm Partition
mount | grep /dev/shm | grep nosuid >> /dev/null
if [ $? == 0 ]
then
echo "Add nosuid Option to /dev/shm Partition present"  >> success.log
else
echo "Add nosuid Option to /dev/shm Partition not present " >> error.log
fi
# Disable Mounting of cramfs Filesystems
/sbin/modprobe -n -v cramfs >> /dev/null
if [ $? == 0 ]
then
echo "Disable Mounting of cramfs Filesystems present"  >> success.log
else
echo "Disable Mounting of cramfs Filesystems not present " >> error.log
fi

#======================================================================
# Disable Mounting of hfs Filesystems
/sbin/lsmod | grep hfs > /dev/null
if [ $? == 0 ]
then
echo "Disable Mounting of hfs Filesystems is present" >>  success.log
else
echo "Disable Mounting of hfs Filesystems is not present " >>  error.log
fi
# Disable Mounting of hfsplus Filesystems
/sbin/modprobe -n -v hfsplus 2&> /dev/null
if [ $? == 0 ]
then
echo "Disable Mounting of hfsplus Filesystems is present" >> success.log
else
echo "Disable Mounting of hfsplus Filesystems is not present " >>  error.log
fi


#Disable Mounting of udf Filesystems

/sbin/modprobe -n -v udf > /dev/null

if [ $? == 0 ]
then
echo "Disable Mounting of hfsplus Filesystems is present" >> success.log
else
echo "Disable Mounting of hfsplus Filesystems is not present " >>  error.log
fi

# Configure Connection to the RHN RPM Repositories
yum repolist 2&> /dev/null
if [ $? == 0 ]
then
echo "Configure Connection to the RHN RPM Repositories is present" >> success.log
else
echo "Configure Connection to the RHN RPM Repositories is not present " >>  error.log
fi

#Verify Red Hat GPG Key is Installed
rpm -q --queryformat "%{SUMMARY}n" gpg-pubkey > /dev/null
if [ $? == 0 ]
then
echo " Red Hat GPG Key is Installed is present" >> success.log
else
echo " Red Hat GPG Key is Installed is not present " >>  error.log
fi
#Verify that gpgcheck is Globally Activated
grep gpgcheck /etc/yum.conf > /dev/null

if [ $? == 0 ]
then
echo " that gpgcheck is Globally Activated is present" >> success.log
else
echo "that gpgcheck is Globally Activated is not present " >>  error.log
fi


#Disable the rhnsd Daemon
chkconfig --list rhnsd 2&> /dev/null
if [ $? != 0 ]
then
echo "Disable the rhnsd Daemon is not present" >> success.log
else
echo "Disable the rhnsd Daemon is  present " >>  error.log
fi

#Obtain Software Package Updates with yum
yum check-update 2&> /dev/null
if [ $? == 0 ]
then
echo "Obtain Software Package Updates with yum is present" >> success.log
else
echo "Obtain Software Package Updates with yum is not present" >>  error.log
fi

####################################################################################################

# Remove MCS Translation Service
rpm -q mcstrans > /dev/null
if [ $? != 0 ]
then
echo " Remove MCS Translation Service pacakge is not present" >> success.log
else
echo "Remove MCS Translation Service pacakge is  present" >>  error.log
fi


#Check for Unconfined Daemons
ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{ print $NF }' > /dev/null
if [ $? == 0 ]
then
echo "NO unconfined daemons found during the audit action" >> success.log
else
echo "unconfined daemons found during the audit action " >>  error.log
fi
# Set User/Group Owner on /boot/grub2/grub.cfg
stat -L -c "%a" /etc/grub2.cfg | egrep ".00 " > /dev/null

if [ $? == 0 ]
then
echo "NO unconfined daemons found during the audit action" >> success.log
else
echo "unconfined daemons found during the audit action " >>  error.log
fi

#Set User/Group Owner on /boot/grub2/grub.cfg
stat -L -c "%a" /etc/grub2.cfg | egrep ".00"  > /dev/null
if [ $? == 0 ]
then
echo "Set User/Group Owner on /boot/grub2/grub.cfg is done" >> success.log
else
echo "Set User/Group Owner on /boot/grub2/grub.cfg is not done " >>  error.log
fi



#Set Permissions on /boot/grub2/grub.cfg

if [ $? == 0 ]
then
echo "Set Permissions on /boot/grub2/grub.cf is present " >> success.log
else
echo "Set Permissions on /boot/grub2/grub.cf is not present " >>  error.log
fi


# Set Boot Loader Password
grep "^password" /etc/grub2.cfg > /dev/null
if [ $? == 0 ]
then
echo "Set Boot Loader Password is present " >> success.log
else
echo "Set Boot Loader Password is not present " >>  error.log
fi

#Restrict Core Dumps 1 validation
sysctl fs.suid_dumpable > /dev/null

if [ $? == 0 ]
then
echo "Restrict Core Dumps 1 validation is stasified " >> success.log
else
echo "Restrict Core Dumps 1 validation is unstasified " >>  error.log
fi
#Restrict Core Dumps 2 validation
grep "hard core" /etc/security/limits.conf > /dev/null
if [ $? == 0 ]
then
echo "Restrict Core Dumps 2 validation is stasified " >> success.log
else
echo "Restrict Core Dumps 1 validation is unstasified " >>  error.log

fi


#Enable Randomized Virtual Memory Region Placement
sysctl kernel.randomize_va_space > /dev/null


if [ $? == 0 ]
then
echo "Enable Randomized Virtual Memory Region Placement is stasified " >> success.log
else
echo "Enable Randomized Virtual Memory Region Placement is unstasified " >>  error.log

fi

# Remove telnet-client

rpm -q telnet telnet-server ypserv tftp rsh-server xinetd ypbind tftp-server talk talk-server rsh > /dev/null

if [ $? != 0 ]
then
echo "Remove telnet-server ypserv tftp rsh-server xinetd ypbind tftp-server talk talk-server rsh is done " >> success.log
else
echo "Remove telnet telnet-server ypserv tftp rsh-server xinetd ypbind tftp-server talk talk-server rsh is not done " >>  error.log

fi


#Disable Send Packet Redirects

/sbin/sysctl net.ipv4.conf.default.send_redirects > /dev/null ;/sbin/sysctl net.ipv4.conf.all.send_redirects > /dev/null
if [ $? == 0 ]
then
echo "Disable Send Packet Redirects is stasified " >> success.log
else
echo "Disable Send Packet Redirects is unstasified " >>  error.log

fi


#Disable Source Routed Packet Acceptance ---
/sbin/sysctl net.ipv4.conf.default.accept_source_route > /dev/null ; /sbin/sysctl net.ipv4.conf.all.accept_source_route > /dev/null

if [ $? == 0 ]
then
echo "Disable Source Routed Packet Acceptanc is stasified " >> success.log
else
echo "Disable Source Routed Packet Acceptanc is unstasified " >>  error.log

fi

# Disable ICMP Redirect Acceptance ---
/sbin/sysctl net.ipv4.conf.default.accept_redirects > /dev/null ; /sbin/sysctl net.ipv4.conf.all.accept_redirects > /dev/null

if [ $? == 0 ]
then
echo "Disable Source Routed Packet Acceptance is stasified " >> success.log
else
echo "Disable Source Routed Packet Acceptance is unstasified " >>  error.log

fi
#Disable Secure ICMP Redirect Acceptance
/sbin/sysctl net.ipv4.conf.default.secure_redirects > /dev/null ; /sbin/sysctl net.ipv4.conf.all.secure_redirects > /dev/null
if [ $? == 0 ]
then
echo "Disable Secure ICMP Redirect Acceptance is stasified " >> success.log
else
echo "Disable Secure ICMP Redirect Acceptance is unstasified " >>  error.log

fi

#Log Suspicious Packets
/sbin/sysctl net.ipv4.conf.default.log_martians > /dev/null ;/sbin/sysctl net.ipv4.conf.all.log_martians > /dev/null

if [ $? == 0 ]
then
echo "Log Suspicious Packets is stasified " >> success.log
else
echo "Log Suspicious Packets is unstasified " >>  error.log

fi


# Enable Ignore Broadcast Requests ---
/sbin/sysctl net.ipv4.icmp_echo_ignore_broadcasts > /dev/null

if [ $? == 0 ]
then
echo "Enable Ignore Broadcast Requests is stasified " >> success.log
else
echo "Enable Ignore Broadcast Requests is unstasified " >>  error.log

fi

# Enable Bad Error Message Protection ---
/sbin/sysctl net.ipv4.icmp_ignore_bogus_error_responses > /dev/null

if [ $? == 0 ]
then
echo "Enable Bad Error Message Protection is stasified " >> success.log
else
echo "Enable Bad Error Message Protection is unstasified " >>  error.log

fi

#Enable RFC-recommended Source Route Validation
/sbin/sysctl net.ipv4.conf.default.rp_filter > /dev/null ; /sbin/sysctl net.ipv4.conf.all.rp_filter > /dev/null

if [ $? == 0 ]
then
echo "Enable RFC-recommended Source Route Validation is stasified " >> success.log
else
echo "Enable RFC-recommended Source Route Validation is unstasified " >>  error.log

fi

#Enable TCP SYN Cookies
/sbin/sysctl net.ipv4.tcp_syncookies > /dev/null

if [ $? == 0 ]
then
echo "Enable TCP SYN Cookies is stasified " >> success.log
else
echo "Enable TCP SYN Cookies is unstasified " >>  error.log

fi


#Deactivate Wireless Interfaces

#Disable IPv6 Router Advertisements
/sbin/sysctl net.ipv6.conf.all.accept_ra > /dev/null ; /sbin/sysctl net.ipv6.conf.default.accept_ra > /dev/null

if [ $? == 0 ]
then
echo "Deactivate Wireless Interfaces is stasified " >> success.log
else
echo "Deactivate Wireless Interfaces is unstasified " >>  error.log

fi

#Install TCP Wrappers
rpm -qa tcp_wrappers > /dev/null

if [ $? == 0 ]
then
echo "Install TCP Wrappers is stasified " >> success.log
else
echo "Install TCP Wrappers is unstasified " >>  error.log

fi


# Uncommon Network Protocols
/sbin/sysctl net.ipv4.conf.all.send_redirects > /dev/null

if [ $? == 0 ]
then
echo "Uncommon Network Protocols is stasified " >> success.log
else
echo "Uncommon Network Protocols is unstasified " >>  error.log

fi

# Logging and Auditing

rpm -q rsyslog > /dev/null
if [ $? == 0 ]
then
echo "rsyslog package is installed " >> success.log
else
echo "rsyslog package is not installed " >>  error.log

fi
#Configure logrotate
grep '{' /etc/logrotate.d/syslog > /dev/null
if [ $? == 0 ]
then
echo "Configure logrotate in /etc/logrotate.d/syslog " >> success.log
else
echo "not Configure logrotate in /etc/logrotate.d/syslog " >>  error.log

fi


# System Access, Authentication and Authorization

rpm -q cronie-anacron > /dev/null
if [ $? == 0 ]
then
echo " System Access, Authentication and Authorization package cronie-anacron installed " >> success.log
else
echo "System Access, Authentication and Authorization package cronie-anacron is not installed " >>  error.log

fi

#Configure SSH
grep "^Protocol" /etc/ssh/sshd_config > /dev/null


if [ $? == 0 ]
then
echo " Configure SSH is done " >> success.log
else
echo "Configure SSH is not done " >>  error.log

fi

# Restrict Access to the su Command
grep wheel /etc/group > /dev/null ; grep pam_wheel.so /etc/pam.d/su >/dev/null
if [ $? == 0 ]
then
echo " Restrict Access to the su Command is done " >> success.log
else
echo "Restrict Access to the su Command is not done " >>  error.log

fi


#User Accounts and Environment
#grep PASS_MAX_DAYS /etc/login.defs
#chage --list USER

#Disable System Accounts

egrep -v "^+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<500 && $7!="/sbin/nologin") {print}' > /dev/null
if [ $? == 0 ]
then
echo " Disable System Accounts is done " >> success.log
else
echo "Disable System Accounts is not done " >>  error.log

fi


#Set Default Group for root Account
grep "^root:" /etc/passwd | cut -f4 -d: > /dev/null
if [ $? == 0 ]
then
echo "Set Default Group for root Account is done " >> success.log
else
echo "Set Default Group for root Account is not done " >>  error.log

fi

#Set Default umask for Users
grep "^umask 077" /etc/bashrc > /dev/null
if [ $? == 0 ]
then
echo "Set Default umask for Users is done " >> success.log
else
echo "SSet Default umask for Users is not done " >>  error.log

fi


#Warning Banners
#ls -l /etc/issue.net
#ls /etc/issue
#/bin/ls -l /etc/motd

#System Maintenance

rpm -qf /etc/passwd > /dev/null
if [ $? == 0 ]
then
echo "System Maintenance setup package is installed " >> success.log
else
echo "System Maintenance setup package is not installed " >>  error.log

fi

# Verify System File Permissions
sys_permissions=`find /etc/passwd -perm 644`
if [ /etc/passwd == $sys_permissions ]
then
echo "System File Permissions 644 " >> success.log
else
echo "system file permissions are not with 644 " >>  error.log

fi

#Review User and Group Settings
/bin/cat /etc/shadow | /bin/awk -F: '($2 == "" ) { print $1 " does not have a password "}' > /dev/null
if [ /etc/passwd == $sys_permissions ]
then
echo " All accounts in /etc/shadow has passwords " >> success.log
else
echo " All accounts in /etc/shadow has no passwords " >>  error.log

fi

