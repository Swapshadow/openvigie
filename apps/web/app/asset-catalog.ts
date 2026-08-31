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
        advisoryUrl: 'https://www.sentinelone.com/labs/category/vulnerability/',
      },
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
