#############################################################################################################
# Script Name: ucsmConfigurator
# Author(s): Stephen K
# Company: 
# Description: Builds and Configures UCS Pods
# Version: 1.3_dev
# Date Last Modified: 01/13/2015
#
#############################################################################################################

### To Do
	# Get Customer ID, and Contract ID from TAC

### Tested EMULATOR Versions:
	# 2.1.3a
	# 2.2.1b


### Change Log
	# 1.0 - 10/01/2013 - Initial Release
	# 1.1 - 11/14/2013 - LDAP Group to Role mapping added.
	# 1.2 - 11/21/2013 - Added DEV VSAN 21,22
	# 1.3 - 01/13/2014 - Fixed a ntp array

### Prerequisites
	# Microsoft PowerShell > 2.0
	# UCSM PowerShell Module: CiscoUcs-PowerTool-1.0.1.0 - http://www.cisco.com/en/US/docs/unified_computing/ucs/sw/msft_tools/powertools/ucs_powertool_book/ucs_pwrtool_bkl1.html#wp441379
	# UCSM 2.1.3a
	# Configure Fabric Interconnects with IP's
	# Create LDAP bind account and notate the DN's - http://www.cisco.com/en/US/docs/unified_computing/ucs/sw/sample_configurations/UCSM_1_4_LDAP_with_AD/b_Sample_Configuration_LDAP_with_AD.pdf
	# Create LDAP groups for delegation and notate the DN's

### POST Script Changes
	# Register with UCS Central
	# Create IPMI Policy (if you plan to use VMware DPM)
	# Create Intial Service Profile / Service Profile Template
	# Create Host Firmware and Management Firmware Policies
	# Setup Misc Administrative Settings
	
### Changes Requests


### Schema Definitions (Digital Aviation)
	#  A: Fabric A
	#  B: Fabric B
	#  X: Site ID
	#  P: Pod ID
	#  F: Fabric ( A / B)
	#  N: Adapter ID
	# 00: Server ID (HEX = 255)
	## MAC = 00:25:B5:XP:FN:00
	## WWNN = 20:00:00:25:B5:XP:FN:00
	## WWPN = 20:00:00:25:B5:XP:FN:00
	## FCoE = VSAN + 3000  ie VSAN11 will use FCoE vlan 3011
	


## Import Cisco UCS PowerShell Module (Required)
 if([IntPtr]::Size -eq 4)
    {                        
  		Import-Module "C:\Program Files\Cisco\Cisco UCS PowerTool\Modules\CiscoUcsPS\CiscoUcsPS.psd1" | Out-Null              
    }
 Else
    {                        
        Import-Module "C:\Program Files (x86)\Cisco\Cisco UCS PowerTool\Modules\CiscoUcsPS\CiscoUcsPS.psd1" | Out-Null
    }

## Connect to Target UCSM
 # Grab UCSM Address
 #$strUCSM = Read-Host "Enter FQDN or IP of target UCSM"
 $strUCSM = "10.1.91.240" #LAB
 # Grab Credentials 
  $global:credUCSM = Get-Credential
 
 Connect-UCS -Name $strUCSM -Credential $global:credUCSM  #-NotDefault
 
 ## Site and Pod Information
 $siteCode = Read-Host "Enter the 3 Character Site Code. ie DEN, LAS"
 $siteCode = $siteCode.ToUpper()
 
 ## Define Dynamic Variables
 $internalSiteID = Read-Host "Enter Site ID (0-F)"
 $internalPodID = Read-Host "Enter Pod ID (0-F)"
 $pairSitePod = "$internalSiteID" + "$internalPodID"
 $suffixSitePod = "-S$internalSiteID" + "-P$internalPodID"
 
 #Ldap providers and bind variables
 $ldapServers = ("ldap.corp.gds.jeppesen.com")
 $ldapProviderGrpName = "corp.gds.jeppesen.com" #This is just the provider group string.
 $ldapProviderGrpShortName = "corp" #This value is used for creating a domain in /User Management/Authentication/Authentication Domains - Limited to 16 chars.
 $baseDN = "DC=corp,DC=gds,DC=jeppesen,DC=com"
 $bindDN = "CN=svc_denucs_ldap,OU=Infrastructure,OU=DEN,OU=ServiceAccounts,OU=Restricted,DC=corp,DC=gds,DC=company,DC=com" #Non-admin user account for ldap read
 $bindPassword = Read-Host -assecurestring "Please enter the password for $bindDN"
 
 #Ldap delegation gorup dn's
 $usrAdmins = "CN=DEN-DEL-UCS-Admins,OU=Infrastructure,OU=DEN,OU=SecurityGroups,OU=Restricted,DC=corp,DC=gds,DC=jeppesen,DC=com"
 $usrEquipmentAdmins = "CN=DEN-DEL-UCS-EquipmentAdmins,OU=Infrastructure,OU=DEN,OU=SecurityGroups,OU=Restricted,DC=corp,DC=gds,DC=jeppesen,DC=com"
 $usrLanAdmins = "CN=DEN-DEL-UCS-LanAdmins,OU=Infrastructure,OU=DEN,OU=SecurityGroups,OU=Restricted,DC=corp,DC=gds,DC=jeppesen,DC=com"
 $usrOperations = "CN=DEN-DEL-UCS-Operations,OU=Infrastructure,OU=DEN,OU=SecurityGroups,OU=Restricted,DC=corp,DC=gds,DC=jeppesen,DC=com"
 $usrReadOnly = "CN=DEN-DEL-UCS-ReadOnly,OU=Infrastructure,OU=DEN,OU=SecurityGroups,OU=Restricted,DC=corp,DC=gds,DC=jeppesen,DC=com"
 $usrSanAdmins = "CN=DEN-DEL-UCS-SANAdmins,OU=Infrastructure,OU=DEN,OU=SecurityGroups,OU=Restricted,DC=corp,DC=gds,DC=jeppesen,DC=com"
 
## Define Static Variables
 # Management
 $mgmtCallHomeSmtpSrv = "mailhost.email.com"
 $mgmtCallHomePhysAddr = "5555 Inverness Drive East, City, CO. 00000"
 $mgmtCallHomeContactName = "UCS Administrators"
 $mgmtCallHomeContactPhone = "+13035555555"
 $mgmtCallHomeContactEmail = "ucsAdmins@company.com"
 $mgmtCallHomeCustomerId = ""
 $mgmtCallHomeContractId = ""
 $mgmtCallHomeSiteId = ""
 $mgmtCallHomeSmtpFrom = $siteCode + "UCS" + $pairSitePod + "-CallHome@jeppesen.com"
 $mgmtCallHomeSmtpRecipient = "ucsAdmins@company.com"
 $mgmtDNS = ("169.143.33.236","169.143.33.36")
 $mgmtNTP = ("ntp01.company.com","ntp02.company.com","ntp03.company.com")
 $mgmtChassisDiscPolAction = "2-link"
 $mgmtChassisDiscPolLnkAgr = "port-channel"
 $mgmtPowerPolicy = "grid"
 $mgmtTimezone = "America/Denver (Mountain Time)"
 
 # Management IP Adresses - Must be on same subnet as out of band mgmt IP of FI's - One IP per CIMC
 $lanMgmtIpBlockStart = "10.20.35.20"
 $lanMgmtIpBlockEnd = "10.20.35.29"
 $lanMgmtIpDefGw = "10.20.35.1"
 $lanMgmtIpSubnet = "255.255.255.0"
 
 
 # LAN Cloud
 $lanVLANsGlobal = (3,4,5,7,9,17,44,45,74,112,113,114,115,240,254,701,702,703,704,705,706,709,712,713,714,715,717,720,722,723,790,792,794,795,796,801,805)
 $lanVLANsVmMgmt = (790)
 $lanVLANsVmVmt = (792)
 $lanVLANsVmGuest = (3,4,5,7,9,17,44,45,74,112,113,114,115,254,701,702,703,704,705,706,709,712,713,714,715,717,720,722,723,794,795,796,801,805)
 $lanIscsiIPStart = "192.168.12.10"
 $lanIscsiIPEnd = "192.168.12.20"
 $lanIscsiIPDefGw = "192.168.12.1"
 $lanIscsiIPPriDns = "0.0.0.0"
 $lanIscsiIPSecDns = "0.0.0.0"
 $lanIscsiIPSubnetMask = "255.255.255.0"
 $lanMacBlockBase = "00:25:B5:" + $pairSitePod
 $lanMacNameBase = "MAC-Pool" + $suffixSitePod
 $lanMacNameA1 = $lanMacNameBase + "-A1"
 $lanMacNameA2 = $lanMacNameBase + "-A2"
 $lanMacNameB1 = $lanMacNameBase + "-B1"
 $lanMacNameB2 = $lanMacNameBase + "-B2"
 $lanMacStartA1 = $lanMacBlockBase + ":A1:00"
 $lanMacStartA2 = $lanMacBlockBase + ":A2:00"
 $lanMacStartB1 = $lanMacBlockBase + ":B1:00"
 $lanMacStartB2 = $lanMacBlockBase + ":B2:00"
 $lanMacEndA1 = $lanMacBlockBase + ":A1:FF"
 $lanMacEndA2 = $lanMacBlockBase + ":A2:FF"
 $lanMacEndB1 = $lanMacBlockBase + ":B1:FF"
 $lanMacEndB2 = $lanMacBlockBase + ":B2:FF"
 $lanNetConPol1Name = "CDP-ON_Link-Down"
 $lanNetConPol1CDP = "enabled"
 $lanNetConPol1UpFailAct = "link-down"
 $lanVnicTemplVmMgmtNameA1 = "vNIC-" + "A1-" + "MGMT"
 $lanVnicTemplVmMgmtNameB1 = "vNIC-" + "B1-" + "MGMT"
 $lanVnicTemplVmVmtNameA1 = "vNIC-" + "A1-" + "VMOTION"
 $lanVnicTemplVmVmtNameB1 = "vNIC-" + "B1-" + "VMOTION"
 $lanVnicTemplVmFtNameA1 = "vNIC-" + "A1-" + "FT"
 $lanVnicTemplVmFtNameB1 = "vNIC-" + "B1-" + "FT"
 $lanVnicTemplVmGstNameA1 = "vNIC-" + "A1-" + "GUEST"
 $lanVnicTemplVmGstNameB1 = "vNIC-" + "B1-" + "GUEST"

 # SAN Cloud
 $sanBootEnForceName = "no"
 $sanBootLunID = ""
 $sanBootSPA_aPrimary = ""
 $sanBootSPB_aSecondary = ""
 $sanBootSPB_bPrimary = ""
 $sanBootSPA_bSecondary = ""
 $sanVSANsA = (11,21)
 $sanVSANsB = (12,22)
 $sanVSANsBoot = (11,12,21,22)
 $sanWwnBlockBase = "20:00:00:25:B5:" + $pairSitePod
 $sanWwnnPoolName= "WWNN" + $suffixSitePod
 $sanWwnnBlockStart = $sanWwnBlockBase + ":00:00"
 $sanWwnnBlockEnd = $sanWwnBlockBase + ":00:FF"
 $sanWwpnPoolNameBase = "WWPN" + $suffixSitePod
 $sanWwpnPoolNameA1 = $sanWwpnPoolNameBase +"-A1"
 $sanWwpnPoolNameA2 = $sanWwpnPoolNameBase +"-A2"
 $sanWwpnPoolNameB1 = $sanWwpnPoolNameBase +"-B1"
 $sanWwpnPoolNameB2 = $sanWwpnPoolNameBase +"-B2"
 $sanWwpnStartA1 = $sanWwnBlockBase + ":A1:00"
 $sanWwpnStartA2 = $sanWwnBlockBase + ":A2:00"
 $sanWwpnStartB1 = $sanWwnBlockBase + ":B1:00"
 $sanWwpnStartB2 = $sanWwnBlockBase + ":B2:00"
 $sanWwpnEndA1 = $sanWwnBlockBase + ":A1:FF"
 $sanWwpnEndA2 = $sanWwnBlockBase + ":A2:FF"
 $sanWwpnEndB1 = $sanWwnBlockBase + ":B1:FF"
 $sanWwpnEndB2 = $sanWwnBlockBase + ":B2:FF"
 $sanVhbaTemplateBase = "vHBA"
 $sanVhbaTemplateNameA1 = $sanVhbaTemplateBase +"-A1"
 $sanVhbaTemplateNameA2 = $sanVhbaTemplateBase +"-A2"
 $sanVhbaTemplateNameB1 = $sanVhbaTemplateBase +"-B1"
 $sanVhbaTemplateNameB2 = $sanVhbaTemplateBase +"-B2"

 # Server tab variables 
 $srvUuidPoolName = "UUID" + $suffixSitePod
 $srvUuidBlockStart = "00" + $pairSitePod + "-000000000001"
 $srvUuidBlockEnd = "00" + $pairSitePod + "-000000000100"

### Begin Configuration ###

# Management Configuration
#--------------------------

#Equipment Options (Equipment/Global Policies)
Get-UcsChassisDiscoveryPolicy | Set-UcsChassisDiscoveryPolicy -Action $mgmtChassisDiscPolAction -Force

# Discovery Policy (Link Aggregation for 6200+ Series FI's)
 $getUcsFiAMod = Get-UcsFiModule -Dn sys/switch-A/slot-1
 If ($getUcsFiAMod.model -like "*61*")
    {
    #WriteLog "Chassis Link Aggregation does not apply to 6100 Series Interconnects" -Color Red
    }
 Else
    {
    #WriteLog "Change Chassis Link Aggregation Prefernce to $mgmtChassisDiscPolLnkAgr"
    Get-UcsChassisDiscoveryPolicy | Set-UcsChassisDiscoveryPolicy -LinkAggregationPref $mgmtChassisDiscPolLnkAgr -Force
    }

 # Power Policy (Redundancy)
 # WriteLog "Change Power Redundancy Policy to $mgmtPowerPolicy"
 Get-UcsPowerControlPolicy | Set-UcsPowerControlPolicy -Redundancy $mgmtPowerPolicy -Force

## Insert Global Power Allocation Policy - Future

 # Management Items
 # Call Home (Communication Management/Call Home)
 Start-UcsTransaction	# Allows all the code in between the Start-UcsTransaction and Complete-UcsTransaction to be gathered by the Cisco UCS PowerTool and optimized, then at the end one call is made to the API sending the complete data.
 $mo_0 = Get-UcsCallhome | Set-UcsCallhome -AdminState on -AlertThrottlingAdminState on -Force
 $mo_1 = Get-UcsCallhomeSmtp | Set-UcsCallhomeSmtp -Host $mgmtCallHomeSmtpSrv -Port 25 -Force
 $mo_2 = Get-UcsCallhomeSource | Set-UcsCallhomeSource -Addr $mgmtCallHomePhysAddr -Contact $mgmtCallHomeContactName -Email $mgmtCallHomeContactEmail -Contract $mgmtCallHomeContractId -Customer $mgmtCallHomeCustomerId -From $mgmtCallHomeSmtpFrom -Phone $mgmtCallHomeContactPhone -ReplyTo $mgmtCallHomeSmtpFrom -Site $mgmtCallHomeSiteId -Urgency debug -Force
 $mo_3 = Get-UcsCallhomeProfile -Name full_txt | Add-UcsCallhomeRecipient -Email $mgmtCallHomeSmtpRecipient
 Complete-UcsTransaction	# Allows all the code in between the Start-UcsTransaction and Complete-UcsTransaction to be gathered by the Cisco UCS PowerTool and optimized, then at the end one call is made to the API sending the complete data.
 # http://www.virtu-al.net/2012/05/14/optimized-powershell-performance-with-cisco-ucs-powertool/
 
 # DNS Servers (Communication Management/DNS)
 # Remove Existing Records (Manualy Created or DHCP entries)
 Get-UcsDnsServer | Remove-UcsDnsServer -Force
 #WriteLog "Create DNS Servers"
 foreach ($dns in $mgmtDNS)
    {
    #WriteLog "Adding DNS Entry: $dns"
    Add-UcsDnsServer -Name $dns
    }
    
 # Management Interface Monitoring Policy
 #WriteLog "Enable and Configure Management Interface Monitoring Policy"
 Set-UcsMgmtInterfaceMonitorPolicy -AdminState enabled -MonitorMechanism gatewayPing -force
 
 # NTP Servers (Time Zone Management)
 #WriteLog "Create NTP Servers"
 foreach ($ntp in $mgmtNTP)
    {
    #WriteLog "Adding NTP Entry: $ntp"
    Add-UcsNtpServer -Name $ntp
    }
 
 # Timezone (Time Zone Management)
 #WriteLog "Setting Timezone to $mgmtTimezone"
	Set-UcsTimezone -AdminState enabled -Timezone $mgmtTimezone -Force
 
## Sub-Organizations
 # Remove the Finance Default Org (root/Sub-Organization/Finance)
	Get-UcsOrg -Name Finance | Remove-UcsOrg -Force
 # VMware Sub-Org (root/Sub-Organization)
	Add-UcsOrg -Name VMware -Org org-root -Descr "VMware Org for Site $internalSiteID / Pod $internalPodID"
 
## LDAP Bind
 # Create a LDAP Provider and LDAP Group Rule.
 foreach ($ldapserver in $ldapServers)
 {
 add-UcsLdapProvider -Attribute "" -Basedn $baseDN -FilterValue 'sAMAccountName=$userid' -Name $ldapServer -Rootdn $bindDN -Key $bindPassword -XtraProperty @{vendor = "MS-AD";} | Add-UcsLdapGroupRule -Authorization "enable" -Traversal "recursive" -TargetAttr "memberOf" 
 }

# Create ldap provider group
Get-UcsLdapGlobalConfig | Add-UcsProviderGroup -Name $ldapProviderGrpName

# Add each ldap server to the provider group.
foreach ($ldapserver in $ldapServers)
	{
	Get-UcsProviderGroup -Name $ldapProviderGrpName  | Add-UcsProviderReference -Name $ldapServer
	}
	
# Configure ldap as the default authentication for ucsm
Get-UcsNativeAuth | Set-UcsNativeAuth -DefLogin ldap -Force
Get-UcsDefaultAuth | Set-UcsDefaultAuth -ProviderGroup $ldapProviderGrpName -Force

# Create the authentication domains, set ldap as the realm, and select the provider group created above.
$adAdd = Add-UcsAuthDomain -Name $ldapProviderGrpShortName
$adAdd | Get-UcsAuthDomainDefaultAuth | Set-UcsAuthDomainDefaultAuth -Realm ldap -ProviderGroup $ldapProviderGrpName -Force

# Create ldap group mappings for delegation
Add-UcsLdapGroupMap -Name $usrAdmins
Add-UcsLdapGroupMap -Name $usrEquipmentAdmins
Add-UcsLdapGroupMap -Name $usrLanAdmins
Add-UcsLdapGroupMap -Name $usrOperations
Add-UcsLdapGroupMap -Name $usrReadOnly
Add-UcsLdapGroupMap -Name $usrSanAdmins

 #Assign Groups to Roles # Added for version 1.1
 	Start-UcsTransaction
	$mo = Get-UcsLdapGroupMap -Name "$usrAdmins" | Set-UcsLdapGroupMap -Descr "" -Force
	$mo_1 = $mo | Add-UcsUserRole -Descr "" -Name "admin"
	Complete-UcsTransaction

	Start-UcsTransaction
	$mo = Get-UcsLdapGroupMap -Name "$usrEquipmentAdmins" | Set-UcsLdapGroupMap -Descr "" -Force
	$mo_1 = $mo | Add-UcsUserRole -Descr "" -Name "server-equipment"
	Complete-UcsTransaction

	Start-UcsTransaction
	$mo = Get-UcsLdapGroupMap -Name "$usrLanAdmins" | Set-UcsLdapGroupMap -Descr "" -Force
	$mo_1 = $mo | Add-UcsUserRole -Descr "" -Name "network"
	Complete-UcsTransaction

	Start-UcsTransaction
	$mo = Get-UcsLdapGroupMap -Name "$usrOperations" | Set-UcsLdapGroupMap -Descr "" -Force
	$mo_1 = $mo | Add-UcsUserRole -Descr "" -Name "operations"
	Complete-UcsTransaction

	Start-UcsTransaction
	$mo = Get-UcsLdapGroupMap -Name "$usrSanAdmins" | Set-UcsLdapGroupMap -Descr "" -Force
	$mo_1 = $mo | Add-UcsUserRole -Descr "" -Name "storage"
	Complete-UcsTransaction
 

# Server Pools and Policy Configuration
# -------------------------------------

## Pools
 # Remove Default Server Pool
 # WriteLog "Removing Default Server Pool" -Color Yellow
 # Remove-UcsServerPool -ServerPool default -Force
 
 # Remove ALL Server Pools
 Get-UcsServerPool | Remove-UcsServerPool -Force
 
  # Remove Default UUID Pool in the Root Org
  # WriteLog "Removing Default UUID Pool" -Color Yellow
  # Remove-UcsUuidSuffixPool -UuidSuffixPool default -Force
  
  # Remove ALL UUID Pools
  Get-UcsUuidSuffixPool | Remove-UcsUuidSuffixPool -Force
 
 # Create New UUID Pool 
 # WriteLog "Creating Global UUID Pool"
 Add-UcsUuidSuffixPool -name $srvUuidPoolName -org org-root -Descr "UUID Pool for Site $internalSiteID / Pod $internalPodID" -AssignmentOrder sequential
 Add-UcsUuidSuffixBlock -UuidSuffixPool $srvUuidPoolName -From $srvUuidBlockStart -To $srvUuidBlockEnd
 

 
## Server Policies
 # BIOS Policy - VMware
 # WriteLog "BIOS Policy: VMware"
 
 $biosVMware = Add-UcsBiosPolicy -Name "VMware" -RebootOnUpdate no -Org VMware
 Set-UcsBiosVfQuietBoot -BiosPolicy $biosVMware -VpQuietBoot disabled -Force

    # Processor
    Set-UcsBiosTurboBoost -BiosPolicy $biosVMware -VpIntelTurboBoostTech enabled -Force
    Set-UcsBiosEnhancedIntelSpeedStep -BiosPolicy $biosVMware -VpEnhancedIntelSpeedStepTech disabled -Force
    Set-UcsBiosHyperThreading -BiosPolicy $biosVMware -VpIntelHyperThreadingTech enabled -Force
    Set-UcsBiosVfCoreMultiProcessing -BiosPolicy $biosVMware -VpCoreMultiProcessing all -Force
    Set-UcsBiosExecuteDisabledBit -BiosPolicy $biosVMware -VpExecuteDisableBit enabled -Force
    Set-UcsBiosVfIntelVirtualizationTechnology -BiosPolicy $biosVMware -VpIntelVirtualizationTechnology enabled -Force
    Set-UcsBiosVfDirectCacheAccess -BiosPolicy $biosVMware -VpDirectCacheAccess enabled -Force
	Set-UcsBiosVfProcessorCState -BiosPolicy $biosVMware -VpProcessorCState disabled -Force
	Set-UcsBiosVfProcessorC1E -BiosPolicy $biosVMware -VpProcessorC1E disabled -Force
	Set-UcsBiosVfCPUPerformance -BiosPolicy $biosVMware -VpCPUPerformance enterprise -Force

    # Intel Directed IO
    Set-UcsBiosIntelDirectedIO -BiosPolicy $biosVMware -VpIntelVTForDirectedIO enabled -VpIntelVTDATSSupport platform-default -VpIntelVTDCoherencySupport platform-default -VpIntelVTDInterruptRemapping platform-default -VpIntelVTDPassThroughDMASupport platform-default -Force

    # RAS Memory
    Set-UcsBiosVfSelectMemoryRASConfiguration -BiosPolicy $biosVMware -VpSelectMemoryRASConfiguration maximum-performance -Force
    Set-UcsBiosNUMA -BiosPolicy $biosVMware -VpNUMAOptimized enabled -Force
    Set-UcsBiosLvDdrMode -BiosPolicy $biosVMware -VpLvDDRMode performance-mode -Force

    # Serial Port
    Set-UcsBiosVfSerialPortAEnable -BiosPolicy $biosVMware -VpSerialPortAEnable disabled -Force

 # Local Disk Configuration Policies
 
 	#WriteLog "Local Disk Config: Remove Default Config" -Color Yellow
 	#Remove-UcsLocalDiskConfigPolicy -LocalDiskConfigPolicy default -Force
 	get-UcsLocalDiskConfigPolicy | Remove-UcsLocalDiskConfigPolicy -Force
 
 	#WriteLog "Local Disk Config: NoLocalStorage Policy"
 	Add-UcsLocalDiskConfigPolicy -Name "NoLocalStorage" -Mode no-local-storage -ProtectConfig yes -Org org-root

 	#WriteLog "Local Disk Config: RAID1 Policy"
 	Add-UcsLocalDiskConfigPolicy -Name "RAID1" -Mode raid-mirrored -ProtectConfig yes -Org org-root
 


 # Maintenance Policy
 
 	# WriteLog "Remove Default Maintenance Policy" -Color Yellow
	# Remove-UcsMaintenancePolicy -MaintenancePolicy default -Force
	Get-UcsMaintenancePolicy | Remove-UcsMaintenancePolicy -Force
	# WriteLog "Create 'UserAck' Maintenance Policy"
	Add-UcsMaintenancePolicy -Name UserAck -UptimeDisr user-ack -Org org-root
 
	# Scrub Policy
 	#WriteLog "Remove Default Scrub Policy" -Color Yellow
 	#Get-UcsScrubPolicy -Name default | Remove-UcsScrubPolicy -Force
	Get-UcsScrubPolicy | Remove-UcsScrubPolicy -Force
	#WriteLog "Create 'NoScrub' Scrub Policy"
	Add-UcsScrubPolicy -Name NoScrub -BiosSettingsScrub no -DiskScrub no -Org org-root
	
# LAN Configuration
#------------------
## Delete Existing Pool Blocks and Pools
	Get-UcsIpPoolBlock | Remove-UcsIpPoolBlock -Force
	Remove-UcsIpPool -IpPool "ip-pool-1" -Force

## Create IP Pools 
 # iSCSI Initiator Pool
 #WriteLog "Create iSCSI Initiator Pool"
 Add-UcsIpPoolBlock -IpPool iscsi-initiator-pool -From $lanIscsiIPStart -To $lanIscsiIPEnd -DefGw $lanIscsiIPDefGw -PrimDns $lanIscsiIPPriDns -SecDns $lanIscsiIPSecDns -Subnet $lanIscsiIPSubnetMask

 # Management IP Pool (ext-mgmt)
 # WriteLog "Create Management IP Pool: From $lanMgmtIpBlockStart To $lanMgmtIpBlockEnd"
 Add-UcsIpPoolBlock -IpPool ext-mgmt -From $lanMgmtIpBlockStart -To $lanMgmtIpBlockEnd -Subnet $lanMgmtIpSubnet -DefGw $lanMgmtIpDefGw

## MAC Pools
	## Remove Default MAC Pool in the Root Org
 	#WriteLog "Removing Default MAC Pool" -Color Yellow
 	# Remove-UcsMacPool -MacPool default -Force
	
	## Delete Existing MAC Pool Blocks and MAC Pools
	Get-UcsMacPool | Remove-UcsMacPool -Force
 	
	# Fabric A
 	# WriteLog "Creating MAC Pools for A Fabric Adapters"
	Add-UcsMacPool -Name $lanMacNameA1 -Org org-root -Descr "MAC Pool for Site $internalSiteID / Pod $internalPodID / Fabric A / Adapter 1" -AssignmentOrder sequential
	Add-UcsMacMemberBlock -MacPool $lanMacNameA1 -From $lanMacStartA1 -To $lanMacEndA1
 	Add-UcsMacPool -Name $lanMacNameA2 -Org org-root -Descr "MAC Pool for Site $internalSiteID / Pod $internalPodID / Fabric A / Adapter 2" -AssignmentOrder sequential
	Add-UcsMacMemberBlock -MacPool $lanMacNameA2 -From $lanMacStartA2 -To $lanMacEndA2
 
	# Fabric B
	# WriteLog "Creating MAC Pools for B Fabric Adapters"
	Add-UcsMacPool -Name $lanMacNameB1 -Org org-root -Descr "MAC Pool for Site $internalSiteID / Pod $internalPodID / Fabric B / Adapter 1" -AssignmentOrder sequential
	Add-UcsMacMemberBlock -MacPool $lanMacNameB1 -From $lanMacStartB1 -To $lanMacEndB1
	Add-UcsMacPool -Name $lanMacNameB2 -Org org-root -Descr "MAC Pool for Site $internalSiteID / Pod $internalPodID / Fabric B / Adapter 2" -AssignmentOrder sequential
	Add-UcsMacMemberBlock -MacPool $lanMacNameB2 -From $lanMacStartB2 -To $lanMacEndB2 



## Create Network Control Policies

	# Delete Existing Network Control Policies
	Get-UcsNetworkControlPolicy | Remove-UcsNetworkControlPolicy -Force
 
 	#WriteLog "Create Network Control Policy $lanNetConPol1"
 	Add-UcsNetworkControlPolicy -Name $lanNetConPol1Name -Cdp $lanNetConPol1CDP -UplinkFailAction $lanNetConPol1UpFailAct -Org org-root
 
## Create Quality of Service Policies
 # Configure QoS System classes
 #Start-UcsTransaction
 #Set-UcsQosClass -QosClass platinum -Weight 9 -AdminState enabled -Force
 #Set-UcsQosClass -QosClass silver -Weight 6 -AdminState enabled -Force
 #Set-UcsQosClass -QosClass bronze -Weight best-effort -AdminState enabled -Force
 #Set-UcsBestEffortQosClass -Weight best-effort -Force
 #Set-UcsFcQosClass -Weight 9 -Force
 #Complete-UcsTransaction

 # Create QoS Policies for VMware Org
 # Delete Existing Policies
 Get-UcsQosPolicy | Remove-UcsQosPolicy -Force
 
 #WriteLog "Create Quality of Service Policy: 'esxi-fc' in Org VMware"
 Add-UcsQosPolicy -Name esxi-fc -Org VMware | Add-UcsVnicEgressPolicy -ModifyPresent -Burst 10240 -HostControl none -Prio fc -Rate line-rate

 #WriteLog "Create Quality of Service Policy: 'esxi-mgmt' in Org VMware"
 Add-UcsQosPolicy -Name esxi-mgmt -Org VMware | Add-UcsVnicEgressPolicy -ModifyPresent -Burst 10240 -HostControl none -Prio silver -Rate line-rate

 #WriteLog "Create Quality of Service Policy: 'esxi-vMotion' in Org VMware"
 Add-UcsQosPolicy -Name esxi-vMotion -Org VMware | Add-UcsVnicEgressPolicy -ModifyPresent -Burst 10240 -HostControl none -Prio bronze -Rate line-rate

 #WriteLog "Create Quality of Service Policy: 'esxi-vm' in Org VMware"
 Add-UcsQosPolicy -Name esxi-vm -Org VMware | Add-UcsVnicEgressPolicy -ModifyPresent -Burst 10240 -HostControl none -Prio platinum -Rate line-rate

## Create vNIC Templates
 # VMware Management vNIC's 
 #WriteLog "Create vNIC Templates (FI A) for VMware Management vNICs"
 Add-UcsVnicTemplate -Name $lanVnicTemplVmMgmtNameA1 -IdentPoolName $lanMacNameA1 -NwCtrlPolicyName $lanNetConPol1Name -QosPolicyName esxi-mgmt -SwitchId A -TemplType updating-template -Org org-root/org-VMware -Descr "VMware MGMT vNIC Template for Site $internalSiteID / Pod $internalPodID / Fabric A / Adapter 1"  
 
 #WriteLog "Create vNIC Templates (FI B) for VMware Management vNICs"
 Add-UcsVnicTemplate -Name $lanVnicTemplVmMgmtNameB1 -IdentPoolName $lanMacNameB1 -NwCtrlPolicyName $lanNetConPol1Name -QosPolicyName esxi-mgmt -SwitchId B -TemplType updating-template -Org org-root/org-VMware -Descr "VMware MGMT vNIC Template for Site $internalSiteID / Pod $internalPodID / Fabric B / Adapter 1"
 
 # VMware vMotion vNIC's 
 #WriteLog "Create vNIC Templates (FI A) for VMware vMotion vNICs"
 Add-UcsVnicTemplate -Name $lanVnicTemplVmVmtNameA1 -IdentPoolName $lanMacNameA1 -NwCtrlPolicyName $lanNetConPol1Name -QosPolicyName esxi-vMotion -SwitchId A -TemplType updating-template -Org org-root/org-VMware -Descr "VMware vMotion vNIC Template for Site $internalSiteID / Pod $internalPodID / Fabric A / Adapter 1"  
 
 #WriteLog "Create vNIC Templates (FI B) for VMware vMotion vNICs"
 Add-UcsVnicTemplate -Name $lanVnicTemplVmVmtNameB1 -IdentPoolName $lanMacNameB1 -NwCtrlPolicyName $lanNetConPol1Name -QosPolicyName esxi-vMotion -SwitchId B -TemplType updating-template -Org org-root/org-VMware -Descr "VMware vMotion vNIC Template for Site $internalSiteID / Pod $internalPodID / Fabric B / Adapter 1"
 
 # VMware Virtual Machine Traffic vNIC's 
 #WriteLog "Create vNIC Templates (FI A) for VMware Virtual Machine vNICs"
 Add-UcsVnicTemplate -Name $lanVnicTemplVmGstNameA1 -IdentPoolName $lanMacNameA1 -NwCtrlPolicyName $lanNetConPol1Name -QosPolicyName esxi-vm -SwitchId A -TemplType updating-template -Org org-root/org-VMware -Descr "VMware Guest vNIC Template for Site $internalSiteID / Pod $internalPodID / Fabric A / Adapter 1"  
 
 #WriteLog "Create vNIC Templates (FI B) for VMware Virtual Machine vNICs"
 Add-UcsVnicTemplate -Name $lanVnicTemplVmGstNameB1 -IdentPoolName $lanMacNameB1 -NwCtrlPolicyName $lanNetConPol1Name -QosPolicyName esxi-vm -SwitchId B -TemplType updating-template -Org org-root/org-VMware -Descr "VMware Guest vNIC Template for Site $internalSiteID / Pod $internalPodID / Fabric B / Adapter 1"

## Create VLAN's
 #WriteLog "Creating VLAN's"
 $lanCloud = Get-UcsLanCloud
 foreach ($vlan in $lanVLANsGlobal)
	{
    $vlanID = "{0:D4}" -f $vlan
    $vlanName = "$vlanID"
	#WriteLog "Creating $vlanName"
    Add-UcsVlan -Name $vlanName -Id $vlanID -LanCloud $lanCloud
    }

## Assign VLAN's to appropriate vNIC Templates
 # VMware Management vNIC's 
 # WriteLog "Assign VLAN's to VMware Management vNIC's"
 foreach ($vlan in $lanVLANsVmMgmt)
    {
    $vlanID = "{0:D4}" -f $vlan
    $vlanName = "$vlanID"
    Get-UcsVnicTemplate -Org VMware -Name $lanVnicTemplVmMgmtNameA1 | Add-UcsVnicInterface -Name $vlanName 
    Get-UcsVnicTemplate -Org VMware -Name $lanVnicTemplVmMgmtNameB1 | Add-UcsVnicInterface -Name $vlanName 
	}
    
 # VMware vMotion vNIC's 
 # WriteLog "Assign VLAN's to VMware vMotion vNIC Templates"
 foreach ($vlan in $lanVLANsVmVmt)
    {
    $vlanID = "{0:D4}" -f $vlan
    $vlanName = "$vlanID"
    Get-UcsVnicTemplate -Org VMware -Name $lanVnicTemplVmVmtNameA1 | Add-UcsVnicInterface -Name $vlanName 
    Get-UcsVnicTemplate -Org VMware -Name $lanVnicTemplVmVmtNameB1 | Add-UcsVnicInterface -Name $vlanName 
	}
    
 # VMware Virtual Machine Traffic vNIC's 
 # WriteLog "Assign VLAN's to VMware Virtual Machine Traffic vNIC Templates"
 foreach ($vlan in $lanVLANsVmGuest)
    {
    $vlanID = "{0:D4}" -f $vlan
    $vlanName = "$vlanID"
    Get-UcsVnicTemplate -Org VMware -Name $lanVnicTemplVmGstNameA1 | Add-UcsVnicInterface -Name $vlanName 
    Get-UcsVnicTemplate -Org VMware -Name $lanVnicTemplVmGstNameB1 | Add-UcsVnicInterface -Name $vlanName 
	}


# SAN Configuration
#------------------
# Remove Default Pools
Get-UcsWwnPool | Remove-UcsWwnPool -Force

# Remove Default IQN Pool in the Root Org
# WriteLog "Removing Default IQN Pool" -Color Yellow
 Remove-UcsIqnPoolPool -IqnPoolPool default -Force

## Create New WWNN Pool
 # Create WWNN Pool
 # WriteLog "Creating WWNN Pool $sanWwnnPoolName"
 Add-UcsWwnPool -Name $sanWwnnPoolName -Purpose node-wwn-assignment -Org org-root -Descr "WWNN Pool for Site $internalSiteID / Pod $internalPodID" -AssignmentOrder sequential

## Add WWNN Member Block to new WWNN Pool
 #WriteLog "Add WWNN Member Block $sanWwnnBlockStart to $sanWwnnPoolName"
 Add-UcsWwnMemberBlock -WwnPool $sanWwnnPoolName -From $sanWwnnBlockStart -To $sanWwnnBlockEnd
 
## Create WWPN Pools
 # Create WWPN Namespaces
 # WriteLog "Creating WWPN Pools for A Fabric Adapters"
 Add-UcsWwnPool -Name $sanWwpnPoolNameA1 -Purpose port-wwn-assignment -Org org-root -Descr "WWPN Pool for Site $internalSiteID / Pod $internalPodID / Fabric A / Adapter 1" -AssignmentOrder sequential
 Add-UcsWwnPool -Name $sanWwpnPoolNameA2 -Purpose port-wwn-assignment -Org org-root -Descr "WWPN Pool for Site $internalSiteID / Pod $internalPodID / Fabric A / Adapter 2" -AssignmentOrder sequential
 
 # WriteLog "Creating WWPN Pools for B Fabric Adapters"
 Add-UcsWwnPool -Name $sanWwpnPoolNameB1 -Purpose port-wwn-assignment -Org org-root -Descr "WWPN Pool for Site $internalSiteID / Pod $internalPodID / Fabric B / Adapter 1" -AssignmentOrder sequential
 Add-UcsWwnPool -Name $sanWwpnPoolNameB2 -Purpose port-wwn-assignment -Org org-root -Descr "WWPN Pool for Site $internalSiteID / Pod $internalPodID / Fabric B / Adapter 2" -AssignmentOrder sequential

 # Add WWPN Member Blocks to new WWPN Pools
 # WriteLog "Add WWPN Block to A Fabric Pools"
 Add-UcsWwnMemberBlock -WwnPool $sanWwpnPoolNameA1 -From $sanWwpnStartA1 -To $sanWwpnEndA1
 Add-UcsWwnMemberBlock -WwnPool $sanWwpnPoolNameA2 -From $sanWwpnStartA2 -To $sanWwpnEndA2
 
 # WriteLog "Add WWPN Block to B Fabric Pools"
 Add-UcsWwnMemberBlock -WwnPool $sanWwpnPoolNameB1 -From $sanWwpnStartB1 -To $sanWwpnEndB1
 Add-UcsWwnMemberBlock -WwnPool $sanWwpnPoolNameB2 -From $sanWwpnStartB2 -To $sanWwpnEndB2

## Create VSANs + FCOE VLANs + vHBA Templates
 # FI A
 # WriteLog "Creating VSANs and vHBA Templates (FI A)"
 $fabricA = Get-UcsFiSanCloud -Id A
 foreach ($vsan in $sanVSANsA)
	{
    $vsanID = "{0:D4}" -f $vsan
    $A1vHBA = $sanVhbaTemplateNameA1 + "-" + $vsanID
    $A2vHBA = $sanVhbaTemplateNameA2 + "-" + $vsanID
    $fcoeID = $vsan + 3000
    $vsanName = "$vsanID-A"
    
    # Add VSAN
    Add-UcsVsan -Name $vsanName -Id $vsanID -FcoeVlan $fcoeID -FiSanCloud $fabricA
    
    # Create New vHBA Templates
    Add-UcsVhbaTemplate -Name $A1vHBA -IdentPoolName $sanWwpnPoolNameA1 -MaxDataFieldSize 2048 -QosPolicyName esxi-fc -SwitchId A -TemplType updating-template -Org org-root/org-VMware -Descr "VMware vHBA Template for Site $internalSiteID / Pod $internalPodID / Fabric A / Adapter 1 / $vsanName"    
    Add-UcsVhbaTemplate -Name $A2vHBA -IdentPoolName $sanWwpnPoolNameA2 -MaxDataFieldSize 2048 -QosPolicyName esxi-fc -SwitchId A -TemplType updating-template -Org org-root/org-VMware -Descr "VMware vHBA Template for Site $internalSiteID / Pod $internalPodID / Fabric A / Adapter 2 / $vsanName"
    
    # Set VSAN on new vHBA Templates
    Get-UcsVhbaTemplate -Org VMware -Name $A1vHBA | Add-UcsVhbaInterface -Name $vsanName
    Get-UcsVhbaTemplate -Org VMware -Name $A2vHBA | Add-UcsVhbaInterface -Name $vsanName
    }
	
 # FI B
 # WriteLog "Creating VSANs and vHBA Templates (FI B)"
 $fabricB = Get-UcsFiSanCloud -Id B
 foreach ($vsan in $sanVSANsB)
	{
    $vsanID = "{0:D4}" -f $vsan
    $B1vHBA = $sanVhbaTemplateNameB1 + "-" + $vsanID
    $B2vHBA = $sanVhbaTemplateNameB2 + "-" + $vsanID
    $fcoeID = $vsan + 3000
    $vsanName = "$vsanID-B"
    
    # Add VSAN
    Add-UcsVsan -Name $vsanName -Id $vsanID -FcoeVlan $fcoeID -FiSanCloud $fabricB
    
    # Create New vHBA Templates
    Add-UcsVhbaTemplate -Name $B1vHBA -IdentPoolName $sanWwpnPoolNameB1 -MaxDataFieldSize 2048 -QosPolicyName esxi-fc -SwitchId B -TemplType updating-template -Org org-root/org-VMware -Descr "VMware vHBA Template for Site $internalSiteID / Pod $internalPodID / Fabric B / Adapter 1 / $vsanName"    
    Add-UcsVhbaTemplate -Name $B2vHBA -IdentPoolName $sanWwpnPoolNameB2 -MaxDataFieldSize 2048 -QosPolicyName esxi-fc -SwitchId B -TemplType updating-template -Org org-root/org-VMware -Descr "VMware vHBA Template for Site $internalSiteID / Pod $internalPodID / Fabric B / Adapter 2 / $vsanName"
    
    # Set VSAN on new vHBA Templates
    Get-UcsVhbaTemplate -Org VMware -Name $B1vHBA | Add-UcsVhbaInterface -Name $vsanName
    Get-UcsVhbaTemplate -Org VMware -Name $B2vHBA | Add-UcsVhbaInterface -Name $vsanName
	}

## Disconnect Active UCS Instance
## Disconnect-Ucs
## Exit
