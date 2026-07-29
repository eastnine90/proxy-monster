// non-admins: read your OWN audit records (per-record condition)
permit(principal, action == Action::"audit.read", resource)
  when { resource is AuditRecord && resource.principal == principal };
// auditors: read anything — individual records AND the whole log (collection)
permit(principal in Role::"auditor", action == Action::"audit.read", resource);
