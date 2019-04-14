# encoding: utf-8
# copyright: 2019, Sjors

title 'vSphere 6.7u1 security configuration guide'

hosts = stub
vms = stub
dvsportgroups = stub
vssportgroups = stub
dvs = stub
vss = stub

# you can also use plain tests


# you add controls here


control 'ESXi.apply-patches' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Keep ESXi system properly patched'             # A human-readable title
  desc 'By staying up to date on ESXi patches, vulnerabilities in the hypervisor can be mitigated. An educated attacker can exploit known vulnerabilities when attempting to attain access or elevate privileges on an ESXi host.'
  tag disa: 'ESXI-06-000072'
  ref "reference", url: "https://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.update_manager.doc/GUID-D53B8D36-A8D7-4B3B-895C-929267508026.html"
  ref "reference", url: "https://www.vmware.com/support/policies/security_response"

  

  hosts.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'ESXi.config-persistent-logs' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Configure persistent logging for all ESXi host'             # A human-readable title
  desc 'ESXi can be configured to store log files on an in-memory file system.  This occurs when the host\'s "/scratch" directory is linked to "/tmp/scratch". When this is done only a single day\'s worth of logs are stored at any time. In addition log files will be reinitialized upon each reboot.  This presents a security risk as user activity logged on the host is only stored temporarily and will not persistent across reboots.  This can also complicate auditing and make it harder to monitor events and diagnose issues.  ESXi host logging should always be configured to a persistent datastore.'
  tag disa: 'ESXI-06-000045'
  ref "reference", url: "http://kb.vmware.com/kb/1033696"
  ref "reference", url: "https://docs.vmware.com/en/VMware-vSphere/6.7/com.vmware.vsphere.security.doc/GUID-9F67DB52-F469-451F-B6C8-DAE8D95976E7.html"

  

  hosts.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'ESXi.config-snmp' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Ensure proper SNMP configuration'             # A human-readable title
  desc 'If SNMP is not being used, it should remain disabled. If it is being used, the proper trap destination should be configured. If SNMP is not properly configured, monitoring information can be sent to a malicious host that can then use this information to plan an attack.  Note:  ESXi 5.1 and later supports SNMPv3 which provides stronger security than SNMPv1 or SNMPv2, including key authentication and encryption. Deciding what version of SNMP to use (v1, v2 or v3) is a site specific setting.'
  tag disa: 'ESXI-06-000053'
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.monitoring.doc/GUID-8EF36D7D-59B6-4C74-B1AA-4A9D18AB6250.html"
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.security.doc/GUID-4309DE28-AFB6-4B2D-A8EA-A38D36A8C6E6.html"
  ref "reference", url: "SNMP V3 configuration - http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.monitoring.doc/GUID-2E4B0F2A-11D8-4649-AC6C-99F89CE93026.html"

  

  hosts.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'ESXi.disable-mob' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Disable Managed Object Browser (MOB)'             # A human-readable title
  desc 'The managed object browser (MOB) provides a way to explore the object model used by the VMkernel to manage the host; it enables configurations to be changed as well. This interface is meant to be used primarily for debugging the vSphere SDK. In Sphere 6.x this is disabled by default. This guideline is here to remind you to audit your ESXi servers to ensure someone hasn\'t turned on the MOB.'
  tag disa: 'ESXI-06-000034'
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.security.doc/GUID-0EF83EA7-277C-400B-B697-04BDC9173EA3.html"

  

  hosts.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'ESXi.enable-ad-auth' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Use Active Directory for local user authentication'             # A human-readable title
  desc 'Join ESXi hosts to an Active Directory (AD) domain to eliminate the need to create and maintain multiple local user accounts. Using AD for user authentication simplifies the ESXi host configuration, ensures password complexity and reuse policies are enforced and reduces the risk of security breaches and unauthorized access.  Note: if the AD group "ESX Admins" (default) exists then all users and groups that are assigned as members to this group will have full administrative access to all ESXi hosts the domain.'
  tag disa: 'ESXI-06-000037,ESXI-06-100037,ESXI-06-200037,ESXI-06-300037'
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.security.doc/GUID-4FD32125-4955-439D-B39F-C654CCB207DC.html"

  

  hosts.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'ESXi.enable-auth-proxy' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'When adding ESXi hosts to Active Directory use the vSphere Authentication Proxy to protect passwords'             # A human-readable title
  desc 'If you configure your host to join an Active Directory domain using Host Profiles the Active Directory credentials are saved in the host profile and are transmitted over the network.  To avoid having to save Active Directory credentials in the Host Profile and to avoid transmitting Active Directory credentials over the network  use the vSphere Authentication Proxy.'
  tag disa: 'ESXI-06-000038,ESXI-06-100038,ESXI-06-200038,ESXI-06-300038'
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/index.jsp?topic=%2Fcom.vmware.vsphere.security.doc%2FGUID-084B74BD-40A5-4A4B-A82C-0C9912D580DC.html"

  

  hosts.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'ESXi.enable-chap-auth' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Enable bidirectional CHAP, also known as Mutual CHAP, authentication for iSCSI traffic'             # A human-readable title
  desc 'vSphere allows for the use of bidirectional authentication of both the iSCSI target and host. Choosing not to enforce more stringent authentication can make sense if you create a dedicated network or VLAN to service all your iSCSI devices. By not authenticating both the iSCSI target and host, there is a potential for a MiTM attack in which an attacker might impersonate either side of the connection to steal data. Bidirectional authentication can mitigate this risk. If the iSCSI facility is isolated from general network traffic, it is less vulnerable to exploitation.'
  tag disa: 'ESXI-06-000054'
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.storage.doc/GUID-AC65D747-728F-4109-96DD-49B433E2F266.html"
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.security.doc/GUID-DFC745FB-CDD6-4828-8948-4D0E0561EEF8.html"

  

  hosts.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'ESXi.enable-normal-lockdown-mode' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Enable Normal Lockdown Mode to restrict access'             # A human-readable title
  desc 'Enabling lockdown mode disables direct access to an ESXi host requiring the host be managed remotely from vCenter Server.  This is done to ensure the roles and access controls implemented in vCenter are always enforced and users cannot bypass them by logging into a host directly.   By forcing all interaction to occur through vCenter Server, the risk of someone inadvertently attaining elevated privileges or performing tasks that are not properly audited is greatly reduced.  Note:  Lockdown mode does not apply to  users who log in using authorized keys. When you use an authorized key file for root user authentication, root users are not prevented from accessing a host with SSH even when the host is in lockdown mode. Note that users listed in the DCUI.Access list for each host are allowed to override lockdown mode and login to the DCUI.  By default the "root" user is the only user listed in the DCUI.Access list.'
  tag disa: 'ESXI-06-000001,ESXI-06-100001'
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.security.doc/GUID-88B24613-E8F9-40D2-B838-225F5FF480FF.htmlhttp://kb.vmware.com/kb/1008077"

  

  hosts.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'ESXi.enable-remote-syslog' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Configure remote logging for ESXi hosts '             # A human-readable title
  desc 'Remote logging to a central log host provides a secure, centralized store for ESXi logs. By gathering host log files onto a central host you can more easily monitor all hosts with a single tool. You can also do aggregate analysis and searching to look for such things as coordinated attacks on multiple hosts. Logging to a secure, centralized log server helps prevent log tampering and also provides a long-term audit record. To facilitate remote logging VMware provides the vSphere Syslog Collector.'
  tag disa: 'ESXI-06-000004,ESXI-06-100004,ESXI-06-200004,ESXI-06-300004,ESXI-06-400004,ESXI-06-500004'
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vcli.examples.doc/GUID-7391AF2D-BD74-4ED8-B649-DBB31EB3CB21.html"

  

  hosts.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'ESXi.enable-strict-lockdown-mode' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Enable Strict lockdown mode to restrict access'             # A human-readable title
  desc 'Enabling lockdown mode disables direct access to an ESXi host requiring the host be managed remotely from vCenter Server.  This is done to ensure the roles and access controls implemented in vCenter are always enforced and users cannot bypass them by logging into a host directly.   By forcing all interaction to occur through vCenter Server, the risk of someone inadvertently attaining elevated privileges or performing tasks that are not properly audited is greatly reduced.  Strict lockdown mode stops the DCUI service. However, the ESXi Shell and SSH services are independent of lockdown mode. For lockdown mode to be an effective security measure, ensure that the ESXi Shell and SSH services are also disabled. Those services are disabled by default.When a host is in lockdown mode, users on the Exception Users list can access the host from the ESXi Shell and through SSH if they have the Administrator role on the host and if these services are enabled. This access is possible even in strict lockdown mode. Leaving the ESXi Shell service and the SSH service disabled is the most secure option. '
  tag disa: 'ESXI-06-000001,ESXI-06-100001'
  ref "reference", url: "​http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.security.doc/GUID-88B24613-E8F9-40D2-B838-225F5FF480FF.html"

  

  hosts.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'ESXi.firewall-restrict-access' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Configure the ESXi host firewall to restrict access to services running on the host '             # A human-readable title
  desc 'Unrestricted access to services running on an ESXi host can expose a host to outside attacks and unauthorized access. Reduce the risk by configuring the ESXi firewall to only allow access from authorized networks. This guideline is focused specifically on two types of access. SSH (which is disabled by default) and vSphere Web Access running on Port 80. Modification of firewall rules for any other service may have a negative impact on the overall operation. Best practices state that ESXi and vCenter should be running in a separate network.This guideline will show how to limit access to the SSH and Web server to IP address ranges to further limit the scope of vulnerability.'
  tag disa: ''
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.security.doc/GUID-8912DD42-C6EA-4299-9B10-5F3AEA52C605.html"

  

  hosts.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'ESXi.set-account-auto-unlock-time' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Set the time after which a locked account is automatically unlocked'             # A human-readable title
  desc 'Multiple account login failures for the same account could possibly be a threat vector trying to brute force the system or cause denial of service. Such attempts to brute force the system should be limited by locking out the account after reaching a threshold. In case, you would want to auto unlock the account, i.e. unlock the account without administrative action, set the time for which the account remains locked. Setting a high duration for which account remains locked would deter and serverly slow down the brute force method of logging in. '
  tag disa: 'ESXI-06-000006'
  ref "reference", url: "​http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.security.doc/GUID-DC96FFDB-F5F2-43EC-8C73-05ACDAE6BE43.html"

  

  hosts.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'ESXi.set-account-lockout' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Set the count of maximum failed login attempts before the account is locked out'             # A human-readable title
  desc 'Multiple account login failures for the same account could possibly be a threat vector trying to brute force the system or cause denial of service. Such attempts to brute force the system should be limited by locking out the account after reaching a threshold.'
  tag disa: 'ESXI-06-000005'
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.security.doc/GUID-DC96FFDB-F5F2-43EC-8C73-05ACDAE6BE43.html"

  

  hosts.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'ESXi.set-dcui-access' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Set DCUI.Access to allow trusted users to override lockdown mode'             # A human-readable title
  desc 'Lockdown mode disables direct host access requiring that admins manage hosts from vCenter Server.  However, if a host becomes isolated from vCenter Server, the admin is locked out and can no longer manage the host. If you are using normal lockdown mode, you can avoid becoming locked out of an ESXi host that is running in lockdown mode, by setting DCUI.Access to a list of highly trusted users who can override lockdown mode and access the DCUI. The DCUI is not running in strict lockdown mode. '
  tag disa: 'ESXI-06-000002'
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.security.doc/GUID-6779F098-48FE-4E22-B116-A8353D19FF56.html"
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.security.doc/GUID-88B24613-E8F9-40D2-B838-225F5FF480FF.html"
  ref "reference", url: " "

  

  hosts.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'ESXi.set-dcui-timeout' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Audit DCUI timeout value'             # A human-readable title
  desc 'DCUI is used for directly logging into ESXi host and carrying out host management tasks. The idle connections to DCUI must be terminated to avoid any unintended usage of the DCUI originating from a left over login session.'
  tag disa: 'ESXI-06-000043'
  ref "reference", url: "​​​"

  

  hosts.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'ESXi.set-password-policies' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Establish a password policy for password complexity'             # A human-readable title
  desc 'ESXi uses the pam_passwdqc.so plug-in to set password strength and complexity.  It is important to use passwords that are not easily guessed and that are difficult for password generators to determine.   Password strength and complexity rules apply to all ESXi users, including root. They do not apply to Active Directory users when the ESX host is joined to a domain. Those password policies are enforced by AD. '
  tag disa: 'ESXI-06-000031,ESXI-06-100031,ESXI-06-200031,ESXI-06-300031,ESXI-06-400031,ESXI-06-500031,ESXI-06-600031'
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.security.doc/GUID-DC96FFDB-F5F2-43EC-8C73-05ACDAE6BE43.html"

  

  hosts.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'ESXi.set-shell-interactive-timeout' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Set a timeout to automatically terminate idle ESXi Shell and SSH sessions'             # A human-readable title
  desc 'If a user forgets to log out of their SSH session, the idle connection will remains open indefinitely, increasing the potential for someone to gain privileged access to the host.  The ESXiShellInteractiveTimeOut allows you to automatically terminate idle shell sessions.'
  tag disa: 'ESXI-06-000041,ESXI-06-100041'
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.security.doc/GUID-94F0C54F-05E3-4E16-8027-0280B9ED1009.html"
  ref "reference", url: "http://kb.vmware.com/kb/2004746"

  

  hosts.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'ESXi.set-shell-timeout' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Set a timeout to limit how long the ESXi Shell and SSH services are allowed to run'             # A human-readable title
  desc 'When the ESXi Shell or SSH services are enabled on a host they will run indefinitely.  To avoid having these services left running set the ESXiShellTimeOut.  The ESXiShellTimeOut defines a window of time after which the ESXi Shell and SSH services will automatically be terminated.'
  tag disa: 'ESXI-06-000042,ESXI-06-100042'
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.security.doc/GUID-B314F79B-2BDD-4D68-8096-F009B87ACB33.html"
  ref "reference", url: "http://kb.vmware.com/kb/2004746"

  

  hosts.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'ESXi.TransparentPageSharing-intra-enabled' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Ensure default setting for intra-VM TPS is correct'             # A human-readable title
  desc 'Acknowledgement of the recent academic research that leverages Transparent Page Sharing (TPS) to gain unauthorized access to data under certain highly controlled conditions and documents VMware’s precautionary measure of restricting TPS to individual virtual machines by default in upcoming ESXi releases. At this time, VMware believes that the published information disclosure due to TPS between virtual machines is impractical in a real world deployment.VMs that do not have the sched.mem.pshare.salt option set cannot share memory with any other VMs.'
  tag disa: 'ESXI-06-000055'
  ref "reference", url: "​https://kb.vmware.com/kb/2080735"
  ref "reference", url: "​https://kb.vmware.com/kb/2097593"
  ref "reference", url: "​https://kb.vmware.com/kb/2091682"
  ref "reference", url: " "

  

  hosts.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'ESXi.verify-acceptance-level-supported' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Verify Image Profile and VIB Acceptance Levels'             # A human-readable title
  desc 'Verify the ESXi Image Profile to only allow signed VIBs.  An unsigned VIB represents untested code installed on an ESXi host.  The ESXi Image profile supports four acceptance levels: (1) VMwareCertified - VIBs created, tested and signed by VMware(2) VMwareAccepted - VIBs created by a VMware partner but tested and signed by VMware, (3) PartnerSupported - VIBs created, tested and signed by a certified VMware partner (4) CommunitySupported - VIBs that have not been tested by VMware or a VMware partner.  Community Supported VIBs are not supported and do not have a digital signature.  To protect the security and integrity of your ESXi hosts do not allow unsigned (CommunitySupported) VIBs to be installed on your hosts.'
  tag disa: 'ESXI-06-000047,ESXI-06-100047'
  ref "reference", url: "http//pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.install.doc/GUID-56600593-EC2E-4125-B1A0-065BDD16CF2D.html"
  ref "reference", url: "http//pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.security.doc/GUID-751034F3-5337-4DB2-8272-8DAC0980EACA.html"

  

  hosts.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'VM.disable-console-copy' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Explicitly disable copy/paste operations'             # A human-readable title
  desc 'Copy and paste operations are disabled by default. However, if you explicitly disable this feature audit controls can check that this setting is correct.'
  tag disa: 'VMCH-06-000001'
  ref "reference", url: "​http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.security.doc/GUID-367D02C1-B71F-4AC3-AA05-85033136A667.html"

  

  hosts.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'VM.disable-console-paste' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Explicitly disable copy/paste operations'             # A human-readable title
  desc 'Copy and paste operations are disabled by default, however, if you explicitly disable this feature, audit controls can check that this setting is correct.'
  tag disa: 'VMCH-06-000004'
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.security.doc/GUID-367D02C1-B71F-4AC3-AA05-85033136A667.html"

  

  vms.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'VM.disable-disk-shrinking-shrink' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Disable virtual disk shrinking'             # A human-readable title
  desc 'Shrinking a virtual disk reclaims unused space in it. The shrinking process itself, which takes place on the host, reduces the size of the disk\'s files by the amount of disk space reclaimed in the wipe process. If there is empty space in the disk, this process reduces the amount of space the virtual disk occupies on the host drive. Normal users and processes—that is, users and processes without root or administrator privileges—within virtual machines have the capability to invoke this procedure. A non-root user cannot wipe the parts of the virtual disk that require root-level permissions. However, if this is done repeatedly, the virtual disk can become unavailable while this shrinking is being performed, effectively causing a denial of service. In most datacenter environments, disk shrinking is not done, so you should disable this feature. Repeated disk shrinking can make a virtual disk unavailable. Limited capability is available to non-administrative users in the guest.'
  tag disa: 'VMCH-06-000005'
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.security.doc/GUID-9610FE65-3A78-4982-8C28-5B34FEB264B6.html"

  

  vms.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'VM.disable-disk-shrinking-wiper' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Disable virtual disk shrinking'             # A human-readable title
  desc 'Shrinking a virtual disk reclaims unused space in it. VMware Tools reclaims all unused portions of disk partitions (such as deleted files) and prepares them for shrinking. Wiping takes place in the guest operating system.  If there is empty space in the disk, this process reduces the amount of space the virtual disk occupies on the host drive. Normal users and processes—that is, users and processes without root or administrator privileges—within virtual machines have the capability to invoke this procedure. A non-root user  cannot wipe the parts of the virtual disk that require root-level permissions.  However, if this is done repeatedly, the virtual disk can become unavailable while this shrinking is being performed, effectively causing a denial of service. In most datacenter environments, disk shrinking is not done, so you should disable this feature. Repeated disk shrinking can make a virtual disk unavailable. Limited capability is available to non-administrative users in the guest.'
  tag disa: 'VMCH-06-000006'
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.security.doc/GUID-9610FE65-3A78-4982-8C28-5B34FEB264B6.html"

  

  vms.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'VM.disable-independent-nonpersistent' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Avoid using independent nonpersistent disks'             # A human-readable title
  desc 'The security issue with nonpersistent disk mode is that successful attackers, with a simple shutdown or reboot, might undo or remove any traces that they were ever on the machine. To safeguard against this risk, production virtual machines should be set to use persistent disk mode; additionally, make sure that activity within the VM is logged remotely on a separate server, such as a syslog server or equivalent Windows-based event collector. Without a persistent record of activity on a VM, administrators might never know whether they have been attacked or hacked.'
  tag disa: 'VMCH-06-000007'
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.security.doc/GUID-1E583D6D-77C7-402E-9907-80B7F478D3FC.html"

  

  vms.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'VM.disable-non-essential-3D-features' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Disable 3D features on Server and desktop virtual machines'             # A human-readable title
  desc 'It is suggested that 3D be disabled on virtual machines that do not require 3D functionality, (e.g. server or desktops not using 3D applications).'
  tag disa: ''

  

  vms.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'VM.disconnect-devices-floppy' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Disconnect unauthorized devices'             # A human-readable title
  desc 'Ensure that no device is connected to a virtual machine if it is not required. For example, serial and parallel ports are rarely used for virtual machines in a datacenter environment, and CD/DVD drives are usually connected only temporarily during software installation. For less commonly used devices that are not required, either the parameter should not be present or its value must be FALSE.  NOTE: The parameters listed are not sufficient to ensure that a device is usable; other required parameters specify how each device is instantiated.  Any enabled or connected device represents a potential attack channel.When setting is set to FALSE, functionality is disabled, however the device may still show up withing the guest operation system.'
  tag disa: 'VMCH-06-000028'
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.security.doc/GUID-600D24C8-0F77-4D96-B273-A30F256B29D4.html"

  

  vms.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'VM.disconnect-devices-parallel' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Disconnect unauthorized devices'             # A human-readable title
  desc 'Ensure that no device is connected to a virtual machine if it is not required. For example, serial and parallel ports are rarely used for virtual machines in a datacenter environment, and CD/DVD drives are usually connected only temporarily during software installation. For less commonly used devices that are not required, either the parameter should not be present or its value must be FALSE.  NOTE: The parameters listed are not sufficient to ensure that a device is usable; other required parameters specify how each device is instantiated.  Any enabled or connected device represents a potential attack channel.When setting is set to FALSE, functionality is disabled, however the device may still show up withing the guest operation system.'
  tag disa: 'VMCH-06-000030'
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.security.doc/GUID-600D24C8-0F77-4D96-B273-A30F256B29D4.html"

  

  vms.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'VM.disconnect-devices-serial' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Disconnect unauthorized devices'             # A human-readable title
  desc 'Ensure that no device is connected to a virtual machine if it is not required. For example, serial and parallel ports are rarely used for virtual machines in a datacenter environment, and CD/DVD drives are usually connected only temporarily during software installation. For less commonly used devices that are not required, either the parameter should not be present or its value must be FALSE.  NOTE: The parameters listed are not sufficient to ensure that a device is usable; other required parameters specify how each device is instantiated.  Any enabled or connected device represents a potential attack channel.When setting is set to FALSE, functionality is disabled, however the device may still show up withing the guest operation system.'
  tag disa: 'VMCH-06-000031'
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.security.doc/GUID-600D24C8-0F77-4D96-B273-A30F256B29D4.html"

  

  vms.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'VM.Enable-VGA-Only-Mode' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Disable all but VGA mode on specific virtual machines'             # A human-readable title
  desc 'Many Server-class virtual machines need only a standard VGA console (typically a Unix/Linux server system). Enabling this setting removes additional unnecessary (for a server workload)  functionality beyond disabling 3D. '
  tag disa: ''

  

  vms.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'VM.limit-setinfo-size' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Limit informational messages from the VM to the VMX file'             # A human-readable title
  desc 'The configuration file containing these name-value pairs is limited to a size of 1MB. This 1MB capacity should be sufficient for most cases, but you can change this value if necessary. You might increase this value if large amounts of custom information are being stored in the configuration file. The default limit is 1MB;this limit is applied even when the sizeLimit parameter is not listed in the .vmx file.  Uncontrolled size for the VMX file can lead to denial of service if the datastore is filled.'
  tag disa: 'VMCH-06-000036'
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.security.doc/GUID-91BF834E-CB92-4014-8CF7-29CE40F3E8A3.html"

  

  vms.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'VM.minimize-console-VNC-use' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Control access to VM console via VNC protocol'             # A human-readable title
  desc 'The VM console enables you to connect to the console of a virtual machine, in effect seeing what a monitor on a physical server would show. This console is also availabe via the VNC protocol. Setting up this access also involves setting up firewall rules on each ESXi server the virtual machine will run on.'
  tag disa: 'VMCH-06-000034'

  

  vms.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'VM.restrict-host-info' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Do not send host information to guests'             # A human-readable title
  desc 'By enabling a VM to get detailed information about the physical host, an adversary could potentially use this information to inform further attacks on the host. If set to True a VM can obtain detailed information about the physical host. *The default value for the parameter is False but is displayed as Null. Setting to False is purely for audit purposes.*This setting should not be TRUE unless a particular VM requires this information for performance monitoring.'
  tag disa: 'VMCH-06-000039'
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.security.doc/GUID-2CF880DA-2435-4201-9AFB-A16A11951A2D.html"
  ref "reference", url: "https://www.vmware.com/pdf/vmware-tools-101-standalone-user-guide.pdf"

  

  vms.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'VM.TransparentPageSharing-inter-VM-Enabled' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Check for enablement of salted VM\'s that are sharing memory pages'             # A human-readable title
  desc 'When salting is enabled (Mem.ShareForceSalting=1 or 2) in order to share a page between two virtual machines both salt and the content of the page must be same. A salt value is a configurable vmx option for each virtual machine. You can manually specify the salt values in the virtual machine\'s vmx file with the new vmx option sched.mem.pshare.salt. If this option is not present in the virtual machine\'s vmx file, then the value of vc.uuid vmx option is taken as the default value. Since the vc.uuid is unique to each virtual machine, by default TPS happens only among the pages belonging to a particular virtual machine (Intra-VM).If a group of virtual machines are considered trustworthy, it is possible to share pages among them by setting a common salt value for all those virtual machines (inter-VM).Default value is null. When this happens the VM has a random salt value generated.'
  tag disa: 'VMCH-06-000040'
  ref "reference", url: "https://kb.vmware.com/kb/2080735"
  ref "reference", url: "​https://kb.vmware.com/kb/2097593"
  ref "reference", url: "​https://kb.vmware.com/kb/2091682"

  

  vms.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'VM.verify-network-filter' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Control access to VMs through the dvfilter network APIs'             # A human-readable title
  desc 'An attacker might compromise a VM by making use the dvFilter API. Configure only those VMs to use the API that need this access.This setting is considered an "Audit Only" guideline. If there is a value present, the admin should check it to ensure it is correct.'
  tag disa: 'VMCH-06-000041'
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.security.doc/GUID-CD0783C9-1734-4B9A-B821-ED17A77B0206.htmlUpdated reference URL"

  

  vms.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'VM.verify-PCI-Passthrough' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Audit all uses of PCI or PCIe passthrough functionality'             # A human-readable title
  desc 'Using the VMware DirectPath I/O feature to pass through a PCI or PCIe device to a virtual machine results in a potential security vulnerability.  The vulnerability can be triggered by buggy or malicious code running in privileged mode in the guest OS, such as a device driver.  Industry-standard hardware and firmware does not currently have sufficient error containment support to make it possible for ESXi to close the vulnerability fully.There can be a valid business reason for a VM to have this configured. This is an audit-only guideline. You should be aware of what virtual machines are configured with direct passthrough of PCI and PCIe devices and ensure that their guest OS is monitored carefully for malicious or buggy drivers that could crash the host.'
  tag disa: ''
  ref "reference", url: "​http://pubs.vmware.com/vsphere-67/topic/com.vmware.powercli.ug.doc/GUID-0E922C7E-67DF-4A05-B4C0-013FC4EC60F4.html"

  

  vms.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'vNetwork.enable-bpdu-filter' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Enable BPDU filter on the ESXi host to prevent being locked out of physical switch ports with Portfast and BPDU Guard enabled'             # A human-readable title
  desc 'BPDU Guard and Portfast are commonly enabled on the physical switch to which the ESXi host is directly connected to reduce the STP convergence delay. If a BPDU packet is sent from a virtual machine on the ESXi host to the physical switch so configured, a cascading lockout of all the uplink interfaces from the ESXi host can occur. To prevent this type of lockout, BPDU Filter can be enabled on the ESXi host to drop any BPDU packets being sent to the physical switch. The caveat is that certain SSL VPN which use Windows bridging capability can legitimately generate BPDU packets. The administrator should verify that there are no legitimate BPDU packets generated by virtual machines on the ESXi host prior to enabling BPDU Filter. If BPDU Filter is enabled in this situation, enabling Reject Forged Transmits on the virtual switch port group adds protection against Spanning Tree loops.In the 6.7 SCG this was changed to a site specific setting to be more in line with the guidelines intent. You need to be using BPDU in guest and have BPDU configured on a hardware switch. '
  tag disa: 'ESXI-06-000058'
  ref "reference", url: "http://kb.vmware.com/kb/2017193"
  ref "reference", url: "http://kb.vmware.com/kb/2047822"
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.security.doc/GUID-FA661AE0-C0B5-4522-951D-A3790DBE70B4.html"

  

  hosts.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'vNetwork.limit-network-healthcheck ' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Enable VDS network healthcheck only if you need it'             # A human-readable title
  desc 'Network Healthcheck is disabled by default. Once enabled, the healthcheck packets contain information on host#, vds# port#, which an attacker would find useful. It is recommended that network healthcheck be used for troubleshooting, and turned off when troubleshooting is finished.'
  tag disa: 'VCWN-06-000012'
  ref "reference", url: "​http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.security.doc/GUID-C590B7D3-4E28-4F2B-8A59-4CDB9C6F2DAA.html"
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.networking.doc/GUID-4A6C1E1C-8577-4AE6-8459-EEB942779A82.html"
  ref "reference", url: " "

  

  hosts.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'vNetwork.reject-forged-transmit-dvportgroup' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Ensure that the “Forged Transmits” policy is set to reject'             # A human-readable title
  desc 'If the virtual machine operating system changes the MAC address, the operating system can send frames with an impersonated source MAC address at any time. This allows an operating system to stage malicious attacks on the devices in a network by impersonating a network adaptor authorized by the receiving network. When the Forged transmits option is set to Accept, ESXi does not compare source and effective MAC addresses.To protect against MAC impersonation, you can set the Forged transmits option to Reject. If you do, the host compares the source MAC address being transmitted by the guest operating system with the effective MAC address for its virtual machine adapter to see if they match. If the addresses do not match, the ESXi host drops the packet. '
  tag disa: 'VCWN-06-000013'
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.networking.doc/GUID-891147DD-3E2E-45A1-9B50-7717C3443DD7.html"
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.security.doc/GUID-C590B7D3-4E28-4F2B-8A59-4CDB9C6F2DAA.html"

  

  dvsportgroup.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'vNetwork.reject-forged-transmit-StandardSwitch' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Ensure that the “Forged Transmits” policy is set to reject'             # A human-readable title
  desc 'If the virtual machine operating system changes the MAC address, the operating system can send frames with an impersonated source MAC address at any time. This allows an operating system to stage malicious attacks on the devices in a network by impersonating a network adaptor authorized by the receiving network. Forged transmissions is set to Accept by default. This means the virtual switch does not compare the source and effective MAC addresses. To protect against MAC address impersonation, all virtual switches should have forged transmissions set to Reject. Reject Forged Transmit can be set at the vSwitch and/or the Portgroup level. You can override switch level settings at the Portgroup level.'
  tag disa: 'ESXI-06-000059'
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.security.doc/GUID-7DC6486F-5400-44DF-8A62-6273798A2F80.html"
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.networking.doc/GUID-891147DD-3E2E-45A1-9B50-7717C3443DD7.html"

  

  vss.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'vNetwork.reject-mac-changes-dvportgroup' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Ensure that the “MAC Address Changes” policy is set to reject'             # A human-readable title
  desc 'If the virtual machine operating system changes the MAC address, it can send frames with an impersonated source MAC address at any time. This allows it to stage malicious attacks on the devices in a network by impersonating a network adaptor authorized by the receiving network. This will prevent VMs from changing their effective MAC address. It will affect applications that require this functionality. An example of an application like this is Microsoft Clustering, which requires systems to effectively share a MAC address. This will also affect how a layer 2 bridge will operate. This will also affect applications that require a specific MAC address for licensing. An exception should be made for the  dvPortgroups that these applications are connected to.'
  tag disa: 'VCWN-06-000014'
  ref "reference", url: "​http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.security.doc/GUID-C590B7D3-4E28-4F2B-8A59-4CDB9C6F2DAA.html"

  

  dvsportgroup.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'vNetwork.reject-mac-changes-StandardSwitch' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Ensure that the “MAC Address Changes” policy is set to reject'             # A human-readable title
  desc 'If the virtual machine operating system changes the MAC address, it can send frames with an impersonated source MAC address at any time. This allows it to stage malicious attacks on the devices in a network by impersonating a network adaptor authorized by the receiving network. This will prevent VMs from changing their effective MAC address. It will affect applications that require this functionality. An example of an application like this is Microsoft Clustering, which requires systems to effectively share a MAC address. This will also affect how a layer 2 bridge will operate. This will also affect applications that require a specific MAC address for licensing. An exception should be made for the port groups that these applications are connected to. Reject MAC Changes can be set at the vSwitch and/or the Portgroup level. You can override switch level settings at the Portgroup level.'
  tag disa: 'ESXI-06-000060'
  ref "reference", url: "​http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.security.doc/GUID-942BD3AA-731B-4A05-8196-66F2B4BF1ACB.html"

  

  vss.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'vNetwork.reject-promiscuous-mode-dvportgroup' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Ensure that the “Promiscuous Mode” policy is set to reject'             # A human-readable title
  desc 'When promiscuous mode is enabled for a dvPortgroup, all virtual machines connected to the dvPortgroup have the potential of reading all packets across that network, meaning only the virtual machines connected to that  dvPortgroup. Promiscuous mode is disabled by default on the ESXI Server, and this is the recommended setting. However, there might be a legitimate reason to enable it for debugging, monitoring or troubleshooting reasons. Security devices might require the ability to see all packets on a vSwitch.  An exception should be made for the dvPortgroups that these applications are connected to, in order to allow for full-time visibility to the traffic on that dvPortgroup.  Unlike standard vSwitches, dvSwitches only allow Promiscuous Mode at the dvPortgroup level'
  tag disa: 'VCWN-06-000015'
  ref "reference", url: "​http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.security.doc/GUID-C590B7D3-4E28-4F2B-8A59-4CDB9C6F2DAA.html"

  

  dvsportgroup.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'vNetwork.reject-promiscuous-mode-StandardSwitch' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Ensure that the “Promiscuous Mode” policy is set to reject'             # A human-readable title
  desc 'When promiscuous mode is enabled for a virtual switch all virtual machines connected to the Portgroup have the potential of reading all packets across that network, meaning only the virtual machines connected to that Portgroup. Promiscuous mode is disabled by default on the ESXI Server, and this is the recommended setting. However, there might be a legitimate reason to enable it for debugging, monitoring or troubleshooting reasons. Security devices might require the ability to see all packets on a vSwitch.  An exception should be made for the Portgroups that these applications are connected to, in order to allow for full-time visibility to the traffic on that Portgroup. Promiscous mode can be set at the vSwitch and/or the Portgroup level. You can override switch level settings at the Portgroup level.'
  tag disa: 'ESXI-06-000061'
  ref "reference", url: "​http://pubs.vmware.com/vsphere-67"
  ref "reference", url: "Update Reference and API URLs"
  ref "reference", url: "/topic/com.vmware.vsphere.security.doc/GUID-92F3AB1F-B4C5-4F25-A010-8820D7250350.html"

  

  vss.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'vNetwork.restrict-netflow-usage' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Ensure that VDS Netflow traffic is only being sent to authorized collector IPs'             # A human-readable title
  desc 'The vSphere VDS can export Netflow information about traffic crossing the VDS. Netflow exports are not encrypted and can contain information about the virtual network making it easier for  a MITM attack to be executed successfully.  If Netflow export is required, verify that all VDS Netflow target IP\'s are correct.'
  tag disa: 'VCWN-06-000016'
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.security.doc/GUID-FA661AE0-C0B5-4522-951D-A3790DBE70B4.html"
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.networking.doc/GUID-55FCEC92-74B9-4E5F-ACC0-4EA1C36F397A.html"

  

  dvs.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'vNetwork.restrict-port-level-overrides' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Restrict port-level configuration overrides on VDS '             # A human-readable title
  desc 'Port-level configuration overrides are disabled by default. Once enabled, this allows for different security settings to be set from what is established at the Port-Group level. There are cases where particular VM\'s require unique configurations, but this should be monitored so it is only used when authorized.  If overrides are not monitored, anyone who gains access to a VM with a less secure VDS configuration could surreptiously exploit that broader access.'
  tag disa: 'VCWN-06-000017'
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.security.doc/GUID-FA661AE0-C0B5-4522-951D-A3790DBE70B4.html"
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.networking.doc/GUID-DDF5CD98-454A-471D-9053-03ABB8FE86D1.html"

  

  vds.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


control 'vNetwork.verify-dvfilter-bind' do                        # A unique ID for this control
  impact 0.5                                # The criticality, if this control fails.
  title 'Audit use of dvfilter network APIs'             # A human-readable title
  desc 'If you are not using a product such as VMware NSX that make use of the dvfilter network API, the host should not be configured to send network information to a IP Address. If the API is enabled and the system running at the IP address referenced is compromised then there is potential for that system to provide unauthorized access to the network of other VMs on the host.  If you are using a product that makes use of this API then verify that the host has been configured correctly.'
  tag disa: 'ESXI-06-000062'
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.security.doc/GUID-CD0783C9-1734-4B9A-B821-ED17A77B0206.html"
  ref "reference", url: "http://pubs.vmware.com/vsphere-67/topic/com.vmware.vsphere.ext_solutions.doc/GUID-6013E15D-92CE-4970-953C-ACCB36ADA8AD.html"

  

  hosts.each do |h|  
    describe esxi(h) do
      its('something') { should cmp 'something'}
    end
  end
end


