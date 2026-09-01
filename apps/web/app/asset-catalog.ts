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
];

export function findVendor(vendorId: string) {
  return vendorCatalog.find((vendor) => vendor.id === vendorId) ?? vendorCatalog[0];
}

export function findProduct(vendorId: string, productId: string) {
  const vendor = findVendor(vendorId);
  return vendor.products.find((product) => product.id === productId) ?? vendor.products[0];
}
