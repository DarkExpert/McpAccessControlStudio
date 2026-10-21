export type Identity = 'viewer' | 'operator' | 'admin'

export interface Scenario {
  id: string
  title: string
  description: string
  tool: string
  arguments: Record<string, unknown>
  category: 'Read' | 'Write' | 'Sensitive'
}

// These are safe demo inputs, never policy outcomes. Authorization comes from the gateway.
export const scenarios: Scenario[] = [
  { id: 'customer', title: 'Read customer', description: 'Retrieve one seeded CRM record', tool: 'crm.get_customer', arguments: { customerId: 'customer-1' }, category: 'Read' },
  { id: 'orders', title: 'List orders', description: 'Read the seeded order list', tool: 'crm.list_orders', arguments: {}, category: 'Read' },
  { id: 'update-within', title: 'Update within limit', description: 'Set a demo order amount to 50', tool: 'crm.update_order', arguments: { orderId: 'order-1', amount: 50 }, category: 'Write' },
  { id: 'update-over', title: 'Update above limit', description: 'Try an amount above the configured threshold', tool: 'crm.update_order', arguments: { orderId: 'order-1', amount: 1001 }, category: 'Write' },
  { id: 'update-malformed', title: 'Malformed amount', description: 'Send a string where a number is required', tool: 'crm.update_order', arguments: { orderId: 'order-1', amount: '50' }, category: 'Write' },
  { id: 'delete', title: 'Delete customer', description: 'Attempt a privileged demo operation', tool: 'crm.delete_customer', arguments: { customerId: 'customer-1' }, category: 'Sensitive' },
  { id: 'export', title: 'Export customers', description: 'Attempt a privileged demo export', tool: 'crm.export_customers', arguments: {}, category: 'Sensitive' },
]

export const identities: { id: Identity; name: string; summary: string; initials: string }[] = [
  { id: 'viewer', name: 'Viewer', summary: 'Read-only demo identity', initials: 'V' },
  { id: 'operator', name: 'Operator', summary: 'Reads and bounded updates', initials: 'O' },
  { id: 'admin', name: 'Admin', summary: 'Privileged demo identity', initials: 'A' },
]

export const toolLabels: Record<string, string> = {
  'crm.get_customer': 'Get customer',
  'crm.list_orders': 'List orders',
  'crm.update_order': 'Update order',
  'crm.delete_customer': 'Delete customer',
  'crm.export_customers': 'Export customers',
}
