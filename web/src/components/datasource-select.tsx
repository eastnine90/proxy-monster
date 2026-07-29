'use client'

// Datasource selector reused by the editor, policy, and access surfaces. Loads
// the datasource list (SWR) and renders a shadcn Select; the caller owns the id.
import { useEffect } from 'react'
import { Database } from 'lucide-react'
import { useDatasources } from '@/lib/hooks'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'

interface Props {
  value: number | null
  onChange: (id: number | null) => void
  /** When true, offer an "All datasources" option mapping to null. */
  allowAll?: boolean
  allLabel?: string
  placeholder?: string
  id?: string
  className?: string
  size?: 'sm' | 'default'
  /** When true, list only datasources the caller can connect to (the query picker). The request
   *  composers omit this so a user can pick a datasource they cannot yet connect to and request access. */
  connectableOnly?: boolean
}

const ALL = '__all__'

export function DatasourceSelect({
  value,
  onChange,
  allowAll = false,
  allLabel = 'All datasources',
  placeholder = 'Select datasource',
  id,
  className,
  size = 'sm',
  connectableOnly = false,
}: Props) {
  const { data, isLoading } = useDatasources(connectableOnly)
  const datasources = data ?? []

  // Auto-select the first datasource for scoped (non-"all") pickers.
  useEffect(() => {
    if (!allowAll && value == null && data && data.length > 0) onChange(data[0].id)
  }, [allowAll, value, data, onChange])

  const current = value == null ? (allowAll ? ALL : null) : String(value)
  const nameOf = (v: string) =>
    v === ALL ? allLabel : (datasources.find((d) => String(d.id) === v)?.name ?? '')

  return (
    <Select
      value={current}
      onValueChange={(v: string | null) =>
        onChange(v == null || v === ALL ? null : Number(v))
      }
      disabled={isLoading}
    >
      <SelectTrigger id={id} size={size} className={className}>
        <Database className="text-muted-foreground size-3.5" />
        <SelectValue placeholder={placeholder}>
          {(v: string | null) => (v ? nameOf(v) : placeholder)}
        </SelectValue>
      </SelectTrigger>
      <SelectContent>
        {allowAll && <SelectItem value={ALL}>{allLabel}</SelectItem>}
        {datasources.map((ds) => (
          <SelectItem key={ds.id} value={String(ds.id)}>
            {ds.name}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}
