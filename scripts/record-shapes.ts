type RData = Record<string, unknown>;

// Write inputs use prefixed field names; the server reports each record type's rData with its own names and enum labels.
const names: Record<string, string> = {
  naptrOrder: 'order', naptrPreference: 'preference', naptrFlags: 'flags', naptrServices: 'services', naptrRegexp: 'regexp', naptrReplacement: 'replacement',
  sshfpAlgorithm: 'algorithm', sshfpFingerprintType: 'fingerprintType', sshfpFingerprint: 'fingerprint', tlsaCertificateUsage: 'certificateUsage',
  tlsaSelector: 'selector', tlsaMatchingType: 'matchingType', tlsaCertificateAssociationData: 'certificateAssociationData',
  uriPriority: 'priority', uriWeight: 'weight', recordData: 'data', rdata: 'value',
};
const enums: Record<string, Record<number, string>> = {
  algorithm: { 13: 'ECDSAP256SHA256' }, digestType: { 2: 'SHA256' }, sshfpAlgorithm: { 1: 'RSA', 2: 'DSA' },
  sshfpFingerprintType: { 2: 'SHA256' }, tlsaCertificateUsage: { 0: 'PKIX-TA', 2: 'DANE-TA', 3: 'DANE-EE' }, tlsaSelector: { 1: 'SPKI' }, tlsaMatchingType: { 1: 'SHA2-256' },
};

export function serverRData(rData: RData): RData {
  return Object.fromEntries(Object.entries(rData).map(([key, value]): [string, unknown] => {
    const label = enums[key];
    const text = String(value);
    return [names[key] ?? key, key === 'characterStringsBase64' ? [value] : key === 'svcParams' ? Object.fromEntries([text.split('|')])
      : key === 'rdata' ? text.match(/../g)!.join(':').toUpperCase() : label ? label[Number(value)] ?? text : value];
  }));
}

export function serverRecords<T extends { rData: RData }>(records: T[]): T[] {
  return records.map(record => ({ ...record, rData: serverRData(record.rData) }));
}
