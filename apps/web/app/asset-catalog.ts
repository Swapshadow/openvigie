export type ProductDefinition = {
  id: string;
  name: string;
  family: string;
  part: 'a' | 'o' | 'h';
  cpeVendor?: string;
  cpeProduct?: string;
  versions: string[];
  advisoryUrl: string;
  versionOptional?: boolean;
};

export type VendorDefinition = {
  id: string;
  name: string;
  short: string;
  products: ProductDefinition[];
};

export const vendorCatalog: VendorDefinition[] = [
  {
    id: 'fortinet',
    name: 'Fortinet',
    short: 'FG',
    products: [
      {
        id: 'fortios', name: 'FortiOS / FortiGate', family: 'Pare-feu', part: 'o',
        cpeVendor: 'fortinet', cpeProduct: 'fortios',
        versions: ['7.6.3', '7.4.7', '7.4.6', '7.4.5', '7.4.4', '7.4.3', '7.4.2', '7.2.10', '7.2.9', '7.0.16', '6.4.15'],
        advisoryUrl: 'https://www.fortiguard.com/psirt',
      },
      {
        id: 'fortimanager', name: 'FortiManager', family: 'Administration', part: 'a',
        cpeVendor: 'fortinet', cpeProduct: 'fortimanager',
        versions: ['7.6.2', '7.4.5', '7.2.8', '7.0.13', '6.4.15'],
        advisoryUrl: 'https://www.fortiguard.com/psirt',
      },
    ],
  },
  {
    id: 'cisco',
    name: 'Cisco',
    short: 'CX',
    products: [
      {
        id: 'ios-xe', name: 'IOS XE / Catalyst', family: 'Commutation & routage', part: 'o',
        cpeVendor: 'cisco', cpeProduct: 'ios_xe',
        versions: ['17.15.3', '17.12.4', '17.9.6', '17.9.4a', '17.6.6a', '16.12.11'],
        advisoryUrl: 'https://sec.cloudapps.cisco.com/security/center/publicationListing.x',
      },
      {
        id: 'nx-os', name: 'NX-OS / Nexus', family: 'Datacenter', part: 'o',
        cpeVendor: 'cisco', cpeProduct: 'nx-os',
        versions: ['10.5.2', '10.4.4', '10.3.6', '9.3.13'],
        advisoryUrl: 'https://sec.cloudapps.cisco.com/security/center/publicationListing.x',
      },
    ],
  },
  {
    id: 'aruba',
    name: 'HPE Aruba Networking',
    short: 'AR',
    products: [
      {
        id: 'aos-cx', name: 'AOS-CX / Aruba CX', family: 'Commutation', part: 'o',
        cpeVendor: 'arubanetworks', cpeProduct: 'aoscx',
        versions: ['10.15.1000', '10.14.1010', '10.13.1040', '10.13.1000', '10.12.1100'],
        advisoryUrl: 'https://support.hpe.com/connect/s/securitybulletinlibrary',
      },
      {
        id: 'arubaos', name: 'ArubaOS / Mobility Controller', family: 'Wi-Fi', part: 'o',
        cpeVendor: 'arubanetworks', cpeProduct: 'arubaos',
        versions: ['10.7.0.0', '10.6.0.2', '8.12.0.3', '8.10.0.14'],
        advisoryUrl: 'https://support.hpe.com/connect/s/securitybulletinlibrary',
      },
    ],
  },
  {
    id: 'palo-alto',
    name: 'Palo Alto Networks',
    short: 'PA',
    products: [
      {
        id: 'pan-os', name: 'PAN-OS', family: 'Pare-feu', part: 'o',
        cpeVendor: 'paloaltonetworks', cpeProduct: 'pan-os',
        versions: ['11.2.4', '11.1.6', '11.0.6', '10.2.12', '10.1.14'],
        advisoryUrl: 'https://security.paloaltonetworks.com/',
      },
    ],
  },
  {
    id: 'juniper',
    name: 'Juniper Networks',
    short: 'JN',
    products: [
      {
        id: 'junos', name: 'Junos OS', family: 'Commutation & routage', part: 'o',
        cpeVendor: 'juniper', cpeProduct: 'junos',
        versions: ['24.4R1', '23.4R2', '22.4R3', '21.4R3'],
        advisoryUrl: 'https://supportportal.juniper.net/s/global-search/%40uri?language=en_US#sort=relevancy&f:ctype=[Security%20Advisories]',
      },
    ],
  },
  {
    id: 'vmware',
    name: 'VMware by Broadcom',
    short: 'VM',
    products: [
      {
        id: 'esxi', name: 'VMware ESXi', family: 'Virtualisation', part: 'o',
        cpeVendor: 'vmware', cpeProduct: 'esxi',
        versions: ['8.0.3', '8.0.2', '8.0.1', '7.0.3'],
        advisoryUrl: 'https://support.broadcom.com/web/ecx/security-advisory',
      },
      {
        id: 'vcenter', name: 'vCenter Server', family: 'Virtualisation', part: 'a',
        cpeVendor: 'vmware', cpeProduct: 'vcenter_server',
        versions: ['8.0.3', '8.0.2', '7.0.3'],
        advisoryUrl: 'https://support.broadcom.com/web/ecx/security-advisory',
      },
    ],
  },
  {
    id: 'sentinelone',
    name: 'SentinelOne',
    short: 'S1',
    products: [
      {
        id: 'singularity-agent', name: 'Singularity Agent', family: 'EDR', part: 'a',
        versions: ['25.1', '24.3', '24.2', '24.1', '23.4'],
        advisoryUrl: 'https://www.sentinelone.com/vulnerability-database/',
      },
    ],
  },
  {
    id: 'checkpoint', name: 'Check Point', short: 'CP', products: [
      { id: 'gaia', name: 'Gaia OS / Quantum', family: 'Pare-feu', part: 'o', cpeVendor: 'checkpoint', cpeProduct: 'gaia_os', versions: ['R82.10', 'R82', 'R81.20', 'R81.10'], advisoryUrl: 'https://support.checkpoint.com/results/sk/sk165052' },
    ],
  },
  {
    id: 'sophos', name: 'Sophos', short: 'SO', products: [
      { id: 'sfos', name: 'Sophos Firewall OS', family: 'Pare-feu', part: 'o', cpeVendor: 'sophos', cpeProduct: 'sfos', versions: ['21.5', '21.0', '20.0', '19.5'], advisoryUrl: 'https://www.sophos.com/en-us/security-advisories' },
    ],
  },
  {
    id: 'sonicwall', name: 'SonicWall', short: 'SW', products: [
      { id: 'sonicos', name: 'SonicOS', family: 'Pare-feu & VPN', part: 'o', cpeVendor: 'sonicwall', cpeProduct: 'sonicos', versions: ['7.2', '7.1', '7.0', '6.5'], advisoryUrl: 'https://psirt.global.sonicwall.com/vuln-list' },
      { id: 'sma', name: 'Secure Mobile Access', family: 'VPN', part: 'a', cpeVendor: 'sonicwall', cpeProduct: 'secure_mobile_access', versions: ['12.4', '10.2', '10.0'], advisoryUrl: 'https://psirt.global.sonicwall.com/vuln-list' },
    ],
  },
  {
    id: 'f5', name: 'F5 Networks', short: 'F5', products: [
      { id: 'big-ip', name: 'BIG-IP', family: 'ADC / VPN', part: 'a', cpeVendor: 'f5', cpeProduct: 'big-ip', versions: ['17.5', '17.1', '16.1', '15.1'], advisoryUrl: 'https://my.f5.com/manage/s/article/K000137207' },
    ],
  },
  {
    id: 'ivanti', name: 'Ivanti', short: 'IV', products: [
      { id: 'connect-secure', name: 'Connect Secure', family: 'VPN', part: 'a', cpeVendor: 'ivanti', cpeProduct: 'connect_secure', versions: ['22.8', '22.7', '22.6', '9.1'], advisoryUrl: 'https://forums.ivanti.com/s/article/Security-Advisory-Landing-Page' },
    ],
  },
  {
    id: 'citrix', name: 'Citrix', short: 'CT', products: [
      { id: 'netscaler', name: 'NetScaler ADC / Gateway', family: 'ADC / VPN', part: 'a', cpeVendor: 'citrix', cpeProduct: 'netscaler_gateway', versions: ['14.1', '13.1', '13.0'], advisoryUrl: 'https://support.citrix.com/support-home/kbsearch?query=security%20bulletin' },
    ],
  },
  {
    id: 'microsoft', name: 'Microsoft', short: 'MS', products: [
      { id: 'windows-server', name: 'Windows Server', family: 'Système serveur', part: 'o', cpeVendor: 'microsoft', cpeProduct: 'windows_server_2022', versions: ['2025', '2022', '2019', '2016'], advisoryUrl: 'https://msrc.microsoft.com/update-guide/' },
      { id: 'defender-endpoint', name: 'Defender for Endpoint', family: 'EDR', part: 'a', versions: [], versionOptional: true, advisoryUrl: 'https://msrc.microsoft.com/update-guide/' },
    ],
  },
  {
    id: 'crowdstrike', name: 'CrowdStrike', short: 'CS', products: [
      { id: 'falcon-sensor', name: 'Falcon Sensor', family: 'EDR', part: 'a', versions: ['7.24', '7.23', '7.22', '7.21'], advisoryUrl: 'https://www.crowdstrike.com/en-us/blog/category/product-tech/' },
    ],
  },
  {
    id: 'zscaler', name: 'Zscaler', short: 'ZS', products: [
      { id: 'zia', name: 'Zscaler Internet Access', family: 'SSE / Proxy', part: 'a', versions: [], versionOptional: true, advisoryUrl: 'https://trust.zscaler.com/' },
      { id: 'zpa', name: 'Zscaler Private Access', family: 'ZTNA', part: 'a', versions: [], versionOptional: true, advisoryUrl: 'https://trust.zscaler.com/' },
    ],
  },
  {
    id: 'ubiquiti', name: 'Ubiquiti', short: 'UI', products: [
      { id: 'unifi', name: 'UniFi Network', family: 'Réseau & Wi-Fi', part: 'a', cpeVendor: 'ui', cpeProduct: 'unifi_network_application', versions: ['9.4', '9.3', '9.2', '8.6'], advisoryUrl: 'https://community.ui.com/releases/Security-Advisories' },
    ],
  },
  {
    id: 'dell', name: 'Dell Technologies', short: 'DE', products: [
      { id: 'os10', name: 'SmartFabric OS10', family: 'Commutation', part: 'o', cpeVendor: 'dell', cpeProduct: 'smartfabric_os10', versions: ['10.6.0', '10.5.6', '10.5.5'], advisoryUrl: 'https://www.dell.com/support/security/en-us' },
    ],
  },
  {
    id: 'extreme', name: 'Extreme Networks', short: 'EX', products: [
      { id: 'exos', name: 'ExtremeXOS', family: 'Commutation', part: 'o', cpeVendor: 'extremenetworks', cpeProduct: 'extremexos', versions: ['32.7', '32.6', '31.7', '30.7'], advisoryUrl: 'https://www.extremenetworks.com/support/security-advisories' },
    ],
  },
  {
    id: 'netapp', name: 'NetApp', short: 'NA', products: [
      { id: 'ontap', name: 'ONTAP', family: 'Stockage', part: 'o', cpeVendor: 'netapp', cpeProduct: 'ontap', versions: ['9.16.1', '9.15.1', '9.14.1', '9.13.1'], advisoryUrl: 'https://security.netapp.com/advisory/' },
    ],
  },
  {
    id: 'synology', name: 'Synology', short: 'SY', products: [
      { id: 'dsm', name: 'DiskStation Manager', family: 'NAS', part: 'o', cpeVendor: 'synology', cpeProduct: 'diskstation_manager', versions: ['7.2.2', '7.2.1', '7.1.1'], advisoryUrl: 'https://www.synology.com/security/advisory' },
    ],
  },
  {
    id: 'qnap', name: 'QNAP', short: 'QN', products: [
      { id: 'qts', name: 'QTS', family: 'NAS', part: 'o', cpeVendor: 'qnap', cpeProduct: 'qts', versions: ['5.2', '5.1', '5.0'], advisoryUrl: 'https://www.qnap.com/en/security-advisories' },
    ],
  },
  {
    id: 'veeam', name: 'Veeam', short: 'VB', products: [
      { id: 'backup-replication', name: 'Backup & Replication', family: 'Sauvegarde', part: 'a', versions: ['13', '12.3', '12.2', '12.1'], advisoryUrl: 'https://www.veeam.com/kb4649' },
    ],
  },
  {
    id: 'proxmox', name: 'Proxmox', short: 'PX', products: [
      { id: 'pve', name: 'Proxmox VE', family: 'Virtualisation', part: 'o', cpeVendor: 'proxmox', cpeProduct: 'virtual_environment', versions: ['9.0', '8.4', '8.3', '8.2'], advisoryUrl: 'https://www.proxmox.com/en/services/security' },
    ],
  },
  {
    id: 'kubernetes', name: 'Kubernetes', short: 'K8', products: [
      { id: 'kubernetes', name: 'Kubernetes', family: 'Orchestration', part: 'a', cpeVendor: 'kubernetes', cpeProduct: 'kubernetes', versions: ['1.34', '1.33', '1.32', '1.31'], advisoryUrl: 'https://kubernetes.io/docs/reference/issues-security/official-cve-feed/' },
    ],
  },
  {
    id: 'redhat', name: 'Red Hat', short: 'RH', products: [
      { id: 'rhel', name: 'Red Hat Enterprise Linux', family: 'Système serveur', part: 'o', cpeVendor: 'redhat', cpeProduct: 'enterprise_linux', versions: ['10.0', '9.6', '9.5', '8.10'], advisoryUrl: 'https://access.redhat.com/security/security-updates/' },
    ],
  },
  {
    id: 'canonical', name: 'Canonical Ubuntu', short: 'UB', products: [
      { id: 'ubuntu', name: 'Ubuntu Linux (Server / Desktop)', family: 'Système Linux', part: 'o', cpeVendor: 'canonical', cpeProduct: 'ubuntu_linux', versions: ['26.04', '25.10', '25.04', '24.04', '22.04', '20.04'], advisoryUrl: 'https://ubuntu.com/security/notices' },
    ],
  },
  {
    id: 'debian', name: 'Debian', short: 'DEB', products: [
      { id: 'debian-linux', name: 'Debian GNU/Linux', family: 'Système Linux', part: 'o', cpeVendor: 'debian', cpeProduct: 'debian_linux', versions: ['13', '12', '11', '10'], advisoryUrl: 'https://www.debian.org/security/' },
    ],
  },
  {
    id: 'fedora', name: 'Fedora Project', short: 'FD', products: [
      { id: 'fedora-linux', name: 'Fedora Linux', family: 'Système Linux', part: 'o', cpeVendor: 'fedoraproject', cpeProduct: 'fedora', versions: ['43', '42', '41', '40'], advisoryUrl: 'https://bodhi.fedoraproject.org/updates/?type=security' },
    ],
  },
  {
    id: 'sekoia',
    name: 'Sekoia.io',
    short: 'SK',
    products: [
      {
        id: 'xdr', name: 'Sekoia.io XDR', family: 'XDR / SIEM', part: 'a',
        versions: [], versionOptional: true,
        advisoryUrl: 'https://www.sekoia.io/en/blog/',
      },
    ],
  },
  // ── Postes de travail, navigateurs, applicatif et sécurité française ──────
  // Versions issues du dictionnaire CPE du NVD : une version absente de cette
  // base ne remonterait aucune CVE et se lirait à tort comme « aucun risque ».
  {
    id: 'apple',
    name: 'Apple',
    short: 'AP',
    products: [
      {
        id: 'macos', name: 'macOS', family: 'Poste de travail', part: 'o',
        cpeVendor: 'apple', cpeProduct: 'macos',
        versions: ['26.6.1', '26.5.2', '26.5', '26.4', '26.3.1', '26.3', '26.2', '26.1', '26.0.0', '26.0', '15.7.9', '15.7.7'],
        advisoryUrl: 'https://support.apple.com/en-us/HT201222',
      },
      {
        id: 'ios', name: 'iOS / iPhone', family: 'Mobile', part: 'o',
        cpeVendor: 'apple', cpeProduct: 'iphone_os',
        versions: ['26.5.2', '26.5', '26.4.2', '26.4', '26.3.1', '26.3', '26.2', '26.1', '26.0.0', '26.0', '18.7.9', '18.7.8'],
        advisoryUrl: 'https://support.apple.com/en-us/HT201222',
      },
      {
        id: 'ipados', name: 'iPadOS', family: 'Mobile', part: 'o',
        cpeVendor: 'apple', cpeProduct: 'ipados',
        versions: ['26.5.2', '26.5', '26.4.2', '26.4', '26.3.1', '26.3', '26.2', '26.1', '26.0.0', '26.0', '18.7.9', '18.7.8'],
        advisoryUrl: 'https://support.apple.com/en-us/HT201222',
      },
      {
        id: 'safari', name: 'Safari', family: 'Navigateur', part: 'a',
        cpeVendor: 'apple', cpeProduct: 'safari',
        versions: ['26.6.1', '26.6', '26.5.2', '26.5', '26.4', '26.3', '26.2', '26.1', '26.0', '22', '18.6', '18.5'],
        advisoryUrl: 'https://support.apple.com/en-us/HT201222',
      },
    ],
  },
  {
    id: 'stormshield',
    name: 'Stormshield',
    short: 'SS',
    products: [
      {
        id: 'sns', name: 'Stormshield Network Security', family: 'Pare-feu', part: 'o',
        cpeVendor: 'stormshield', cpeProduct: 'stormshield_network_security',
        versions: ['4.7.2', '4.7.1', '4.7.0', '4.6.10', '4.6.9', '4.6.6', '4.6.5', '4.6.4', '4.6.3', '4.6.2', '4.6.1', '4.6.0'],
        advisoryUrl: 'https://advisories.stormshield.eu/',
      },
    ],
  },
  {
    id: 'google',
    name: 'Google',
    short: 'GO',
    products: [
      {
        id: 'chrome', name: 'Chrome', family: 'Navigateur', part: 'a',
        cpeVendor: 'google', cpeProduct: 'chrome',
        versions: ['152.0.7977.65', '151.0.7922.173', '151.0.7922.169', '151.0.7922.137', '151.0.7922.109', '151.0.7922.72', '150.0.7871.187', '150.0.7871.186', '150.0.7871.182', '150.0.7871.128', '150.0.7871.125', '150.0.7871.115'],
        advisoryUrl: 'https://chromereleases.googleblog.com/',
      },
      {
        id: 'android', name: 'Android', family: 'Mobile', part: 'o',
        cpeVendor: 'google', cpeProduct: 'android',
        versions: ['15.0', '14.0', '13.0.0', '13.0', '12.1', '12.0l', '12.0', '12l', '11.0', '10.0', '9.0', '8.1'],
        advisoryUrl: 'https://source.android.com/docs/security/bulletin',
      },
    ],
  },
  {
    id: 'mozilla',
    name: 'Mozilla',
    short: 'MZ',
    products: [
      {
        id: 'firefox', name: 'Firefox', family: 'Navigateur', part: 'a',
        cpeVendor: 'mozilla', cpeProduct: 'firefox',
        versions: ['155.0.0', '154.0.1', '154.0.0', '153.2.0', '153.1.0', '153.0.4', '153.0.3', '153.0.1', '153.0.0', '152.0.6', '152.0.5', '152.0.4'],
        advisoryUrl: 'https://www.mozilla.org/en-US/security/advisories/',
      },
      {
        id: 'firefox-esr', name: 'Firefox ESR', family: 'Navigateur', part: 'a',
        cpeVendor: 'mozilla', cpeProduct: 'firefox_esr',
        versions: ['115.7', '115.6', '115.5.0', '115.4.1', '115.4', '115.2', '115.1', '115.0.3', '115.0.2', '115.0.1', '115.0', '102.15'],
        advisoryUrl: 'https://www.mozilla.org/en-US/security/advisories/',
      },
      {
        id: 'thunderbird', name: 'Thunderbird', family: 'Messagerie', part: 'a',
        cpeVendor: 'mozilla', cpeProduct: 'thunderbird',
        versions: ['155.0', '154.0', '153.2.0', '153.1.1', '153.1.0', '153.0.3', '153.0.2', '153.0.1', '151.0.1', '149.0.2', '149.0', '148.0.1'],
        advisoryUrl: 'https://www.mozilla.org/en-US/security/advisories/',
      },
    ],
  },
  {
    id: 'wallix',
    name: 'Wallix',
    short: 'WX',
    products: [
      {
        id: 'bastion', name: 'WALLIX Bastion', family: 'PAM / Accès privilégiés', part: 'a',
        cpeVendor: 'wallix', cpeProduct: 'bastion',
        versions: ['10.0.5', '10.0', '9.0.9'],
        advisoryUrl: 'https://www.wallix.com/security-advisories/',
      },
    ],
  },
  {
    id: 'spip',
    name: 'SPIP',
    short: 'SP',
    products: [
      {
        id: 'spip', name: 'SPIP', family: 'CMS', part: 'a',
        cpeVendor: 'spip', cpeProduct: 'spip',
        versions: ['5.0.0', '4.4.15', '4.4.14', '4.4.13', '4.4.12', '4.4.11', '4.4.10', '4.4.9', '4.4.8', '4.4.7', '4.4.6', '4.4.5'],
        advisoryUrl: 'https://spip.net/fr_article6867.html',
      },
    ],
  },
  {
    id: 'glpi',
    name: 'GLPI Project',
    short: 'GL',
    products: [
      {
        id: 'glpi', name: 'GLPI', family: 'ITSM / Inventaire', part: 'a',
        cpeVendor: 'glpi-project', cpeProduct: 'glpi',
        versions: ['11.0.7', '11.0.6', '11.0.5', '11.0.4', '11.0.3', '11.0.2', '11.0.1', '11.0.0', '10.0.25', '10.0.24', '10.0.23', '10.0.22'],
        advisoryUrl: 'https://github.com/glpi-project/glpi/security/advisories',
      },
    ],
  },
  {
    id: 'nextcloud',
    name: 'Nextcloud',
    short: 'NC',
    products: [
      {
        id: 'server', name: 'Nextcloud Server', family: 'Collaboration', part: 'a',
        cpeVendor: 'nextcloud', cpeProduct: 'nextcloud_server',
        versions: ['34.0.0', '33.0.5', '33.0.4', '33.0.3', '33.0.2', '33.0.1', '33.0.0', '32.0.11', '32.0.10', '32.0.9', '32.0.8', '32.0.7'],
        advisoryUrl: 'https://nextcloud.com/security/advisories/',
      },
    ],
  },
  {
    id: 'zimbra',
    name: 'Zimbra',
    short: 'ZB',
    products: [
      {
        id: 'collaboration', name: 'Zimbra Collaboration', family: 'Messagerie', part: 'a',
        cpeVendor: 'zimbra', cpeProduct: 'collaboration',
        versions: ['10.1.5', '10.1.4', '10.1.3', '10.1.2', '10.1.1', '10.1.0', '10.0.13', '10.0.12', '10.0.11', '10.0.10', '10.0.9', '10.0.8'],
        advisoryUrl: 'https://wiki.zimbra.com/wiki/Security_Center',
      },
    ],
  },
  {
    id: 'atlassian',
    name: 'Atlassian',
    short: 'AT',
    products: [
      {
        id: 'confluence', name: 'Confluence Server / DC', family: 'Collaboration', part: 'a',
        cpeVendor: 'atlassian', cpeProduct: 'confluence_server',
        versions: ['10.0.2', '10.0.0', '9.2.7', '9.2.0', '8.9.4', '8.9.2', '8.9.0', '8.8.1', '8.8.0', '8.7.2', '8.7.1', '8.7.0'],
        advisoryUrl: 'https://confluence.atlassian.com/security/',
      },
      {
        id: 'jira', name: 'Jira Server / DC', family: 'Gestion de projet', part: 'a',
        cpeVendor: 'atlassian', cpeProduct: 'jira_server',
        versions: ['11.1.0', '11.0.0', '10.3.12', '10.3.0', '9.12.28', '9.12.25', '9.12.24', '9.12.23', '9.12.22', '9.12.20', '9.12.19', '9.12.18'],
        advisoryUrl: 'https://confluence.atlassian.com/security/',
      },
    ],
  },
  {
    id: 'elastic',
    name: 'Elastic',
    short: 'EL',
    products: [
      {
        id: 'elasticsearch', name: 'Elasticsearch', family: 'Moteur de recherche', part: 'a',
        cpeVendor: 'elastic', cpeProduct: 'elasticsearch',
        versions: ['9.5.2', '9.5.1', '9.5.0', '9.4.6', '9.4.5', '9.4.4', '9.4.3', '9.4.2', '9.4.1', '9.4.0', '9.3.8', '9.3.7'],
        advisoryUrl: 'https://discuss.elastic.co/c/announcements/security-announcements/31',
      },
      {
        id: 'kibana', name: 'Kibana', family: 'Visualisation', part: 'a',
        cpeVendor: 'elastic', cpeProduct: 'kibana',
        versions: ['9.4.4', '9.4.3', '9.4.2', '9.4.1', '9.4.0', '9.3.8', '9.3.7', '9.3.6', '9.3.5', '9.3.4', '9.3.3', '9.3.2'],
        advisoryUrl: 'https://discuss.elastic.co/c/announcements/security-announcements/31',
      },
    ],
  },
  {
    id: 'wordpress',
    name: 'WordPress',
    short: 'WP',
    products: [
      {
        id: 'core', name: 'WordPress Core', family: 'CMS', part: 'a',
        cpeVendor: 'wordpress', cpeProduct: 'wordpress',
        versions: ['7.0.2', '7.0.1', '7.0', '6.9.5', '6.9.4', '6.9.3', '6.9.2', '6.9.1', '6.9', '6.8.6', '6.8.5', '6.8.4'],
        advisoryUrl: 'https://wordpress.org/news/category/security/',
      },
    ],
  },
  {
    id: 'postgresql',
    name: 'PostgreSQL',
    short: 'PG',
    products: [
      {
        id: 'postgresql', name: 'PostgreSQL', family: 'Base de données', part: 'a',
        cpeVendor: 'postgresql', cpeProduct: 'postgresql',
        versions: ['18.5', '18.4', '18.3', '18.2', '18.1', '18.0', '17.11', '17.10', '17.9', '17.8', '17.7', '17.6'],
        advisoryUrl: 'https://www.postgresql.org/support/security/',
      },
    ],
  },
  {
    id: 'oracle-mysql',
    name: 'Oracle MySQL',
    short: 'MY',
    products: [
      {
        id: 'mysql', name: 'MySQL Server', family: 'Base de données', part: 'a',
        cpeVendor: 'oracle', cpeProduct: 'mysql',
        versions: ['9.5.0', '9.3.0', '9.2.0', '9.1.0', '9.0.1', '9.0.0', '8.4.7', '8.4.5', '8.4.4', '8.4.2', '8.4.0', '8.3.0'],
        advisoryUrl: 'https://www.oracle.com/security-alerts/',
      },
    ],
  },
  {
    id: 'apache',
    name: 'Apache Software Foundation',
    short: 'AS',
    products: [
      {
        id: 'httpd', name: 'Apache HTTP Server', family: 'Serveur web', part: 'a',
        cpeVendor: 'apache', cpeProduct: 'http_server',
        versions: ['3.1', '2.4.68', '2.4.67', '2.4.66', '2.4.65', '2.4.64', '2.4.63', '2.4.62', '2.4.61', '2.4.60', '2.4.59', '2.4.58'],
        advisoryUrl: 'https://httpd.apache.org/security_report.html',
      },
      {
        id: 'tomcat', name: 'Apache Tomcat', family: 'Serveur applicatif', part: 'a',
        cpeVendor: 'apache', cpeProduct: 'tomcat',
        versions: ['11.0.24', '11.0.23', '11.0.22', '11.0.21', '11.0.20', '11.0.18', '11.0.17', '11.0.16', '11.0.15', '11.0.14', '11.0.13', '11.0.12'],
        advisoryUrl: 'https://tomcat.apache.org/security.html',
      },
    ],
  },
  {
    id: 'nginx',
    name: 'nginx (F5)',
    short: 'NX',
    products: [
      {
        id: 'nginx', name: 'nginx', family: 'Serveur web', part: 'a',
        cpeVendor: 'f5', cpeProduct: 'nginx',
        versions: ['1.34.2', '1.34.1', '1.29.3', '1.29.2', '1.29.1', '1.29.0', '1.28.0', '1.27.5', '1.27.4', '1.27.3', '1.27.2', '1.27.1'],
        advisoryUrl: 'https://nginx.org/en/security_advisories.html',
      },
    ],
  },
  {
    id: 'openssl',
    name: 'OpenSSL',
    short: 'SL',
    products: [
      {
        id: 'openssl', name: 'OpenSSL', family: 'Bibliothèque cryptographique', part: 'a',
        cpeVendor: 'openssl', cpeProduct: 'openssl',
        versions: ['4.0.0', '3.6.3', '3.6.2', '3.6.1', '3.6.0', '3.5.7', '3.5.6', '3.5.5', '3.5.4', '3.5.3', '3.5.2', '3.5.1'],
        advisoryUrl: 'https://openssl-library.org/news/vulnerabilities/',
      },
    ],
  },
  {
    id: 'gitlab',
    name: 'GitLab',
    short: 'GI',
    products: [
      {
        id: 'gitlab', name: 'GitLab CE / EE', family: 'Forge logicielle', part: 'a',
        cpeVendor: 'gitlab', cpeProduct: 'gitlab',
        versions: ['19.3.1', '19.3.0', '19.2.5', '19.2.4', '19.2.3', '19.2.2', '19.2.1', '19.2.0', '19.1.7', '19.1.6', '19.1.5', '19.1.4'],
        advisoryUrl: 'https://about.gitlab.com/releases/categories/releases/',
      },
    ],
  },
  {
    id: 'jenkins',
    name: 'Jenkins',
    short: 'JK',
    products: [
      {
        id: 'jenkins', name: 'Jenkins', family: 'Intégration continue', part: 'a',
        cpeVendor: 'jenkins', cpeProduct: 'jenkins',
        versions: ['5.555.3', '5.555.1', '5.555', '2.568', '2.567', '2.566', '2.565', '2.564', '2.563', '2.562', '2.561', '2.560'],
        advisoryUrl: 'https://www.jenkins.io/security/advisories/',
      },
    ],
  },
  {
    id: 'grafana',
    name: 'Grafana Labs',
    short: 'GF',
    products: [
      {
        id: 'grafana', name: 'Grafana', family: 'Supervision', part: 'a',
        cpeVendor: 'grafana', cpeProduct: 'grafana',
        versions: ['13.0.2', '13.0.1', '13.0.0', '12.4.4', '12.4.3', '12.4.2', '12.4.1', '12.4.0', '12.3.7', '12.3.6', '12.3.5', '12.3.4'],
        advisoryUrl: 'https://grafana.com/security/security-advisories/',
      },
    ],
  },
  {
    id: 'opnsense',
    name: 'OPNsense',
    short: 'OP',
    products: [
      {
        id: 'opnsense', name: 'OPNsense', family: 'Pare-feu', part: 'o',
        cpeVendor: 'opnsense', cpeProduct: 'opnsense',
        versions: ['26.7', '26.1.8', '26.1.7', '26.1.6', '26.1.5', '26.1.4', '26.1.3', '26.1.2', '26.1.1', '26.1.a', '26.1', '25.7.11'],
        advisoryUrl: 'https://docs.opnsense.org/security.html',
      },
    ],
  },
  {
    id: 'pfsense',
    name: 'Netgate pfSense',
    short: 'PF',
    products: [
      {
        id: 'pfsense', name: 'pfSense', family: 'Pare-feu', part: 'o',
        cpeVendor: 'pfsense', cpeProduct: 'pfsense',
        versions: ['2.6.0', '2.5.2', '2.5.1', '2.5.0', '2.4.5', '2.4.4', '2.4.1', '2.4.0', '2.3.4.1', '2.3.4', '2.3.3.1', '2.3.3'],
        advisoryUrl: 'https://docs.netgate.com/pfsense/en/latest/releases/',
      },
    ],
  },
  {
    id: 'mikrotik',
    name: 'MikroTik',
    short: 'MT',
    products: [
      {
        id: 'routeros', name: 'RouterOS', family: 'Routage', part: 'o',
        cpeVendor: 'mikrotik', cpeProduct: 'routeros',
        versions: ['7.18', '7.12', '7.11.2', '7.11.1', '7.11', '7.10.2', '7.10.1', '7.10', '7.9.2', '7.9.1', '7.9', '7.8'],
        advisoryUrl: 'https://mikrotik.com/download/changelogs',
      },
    ],
  },
  {
    id: 'openvpn',
    name: 'OpenVPN',
    short: 'OV',
    products: [
      {
        id: 'openvpn', name: 'OpenVPN', family: 'VPN', part: 'a',
        cpeVendor: 'openvpn', cpeProduct: 'openvpn',
        versions: ['3.6.1', '3.6', '2.8.3', '2.8.1', '2.8.0', '2.7.5', '2.7.4', '2.7.3', '2.7.2', '2.7.1', '2.7', '2.7.0'],
        advisoryUrl: 'https://openvpn.net/security-advisories/',
      },
    ],
  },
  {
    id: 'microsoft-endpoint',
    name: 'Microsoft (poste & messagerie)',
    short: 'MW',
    products: [
      {
        id: 'windows-11', name: 'Windows 11', family: 'Poste de travail', part: 'o',
        cpeVendor: 'microsoft', cpeProduct: 'windows_11_24h2',
        versions: ['24H2', '23H2', '22H2'],
        advisoryUrl: 'https://msrc.microsoft.com/update-guide',
        versionOptional: true,
      },
      {
        id: 'windows-10', name: 'Windows 10', family: 'Poste de travail', part: 'o',
        cpeVendor: 'microsoft', cpeProduct: 'windows_10_22h2',
        versions: ['22H2', '21H2'],
        advisoryUrl: 'https://msrc.microsoft.com/update-guide',
        versionOptional: true,
      },
      {
        id: 'exchange', name: 'Exchange Server', family: 'Messagerie', part: 'a',
        cpeVendor: 'microsoft', cpeProduct: 'exchange_server',
        versions: ['2019', '2016', 'SE'],
        advisoryUrl: 'https://msrc.microsoft.com/update-guide',
        versionOptional: true,
      },
      {
        id: 'sharepoint', name: 'SharePoint Server', family: 'Collaboration', part: 'a',
        cpeVendor: 'microsoft', cpeProduct: 'sharepoint_server',
        versions: ['Subscription Edition', '2019', '2016'],
        advisoryUrl: 'https://msrc.microsoft.com/update-guide',
        versionOptional: true,
      },
    ],
  },
];

export function findVendor(vendorId: string) {
  return vendorCatalog.find((vendor) => vendor.id === vendorId) ?? vendorCatalog[0];
}

export function findProduct(vendorId: string, productId: string) {
  const vendor = findVendor(vendorId);
  return vendor.products.find((product) => product.id === productId) ?? vendor.products[0];
}
