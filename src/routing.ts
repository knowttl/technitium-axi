import { ToolError } from './errors.js';

// DnsWebService.GetClusterNodeTypeForPath at vendor revision 0dd592aad21eced4221a9a46204cb1a299972ca0.
const primary = new Set(['003', '008', '009', '010', '011', '013', '057', '058', '059', '060', '063', '064', '065', '066', '070', '071', '072', '073', '074', '076', '099', '102', '104', '105', '107', '109', '110', '115', '116', '117', '142']);
const local = new Set(['001', '002', '005', '006', '007']);

export function routing(id: string) {
  const number = id.slice(3);
  return { target: primary.has(number) ? 'primary via vendor proxy' : local.has(number) ? 'current node' : 'selected or named node via vendor proxy',
    cluster: ['OP-017', 'OP-018'].includes(id) ? 'aggregate' : ['OP-082', 'OP-083'].includes(id) ? 'asynchronous relay' : 'unsupported',
    ...(id === 'OP-080' ? { replication: 'Listeners and local settings stay local; cluster parameters propagate through the primary' } : {}) };
}

export function validateNode(id: string, node: unknown): void {
  if (node === 'cluster' && routing(id).cluster === 'unsupported') throw new ToolError('USAGE', 'node=cluster is unsupported for this operation', 'Select a named node or omit node to use the configured server');
}
