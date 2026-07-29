'use client'

import { useEffect, useRef, useState, type FormEvent } from 'react'
import { useTranslations } from 'next-intl'
import { mutate } from 'swr'
import { toast } from 'sonner'
import { createApproval, discoverApprovalRoles, ApiError } from '@/lib/api/client'
import type { AccessRequest, DiscoverRolesResponse } from '@/lib/api/types'
import { swrKeys, useAuditEvent, useDatasources } from '@/lib/hooks'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { DatasourceSelect } from '@/components/datasource-select'
import { ErrorState, LoadingState } from '@/components/page-scaffold'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'

function errorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    try {
      const parsed = JSON.parse(err.message) as { error?: string }
      return parsed.error ?? err.message
    } catch {
      return err.message
    }
  }
  return err instanceof Error ? err.message : String(err)
}

function formatTimestamp(iso: string | null): string {
  return iso ? new Date(iso).toLocaleString() : '—'
}

export function QueryRequestComposer({
  sourceDecisionId,
  sourceDecisionError,
  onCreated,
  onCancel,
}: {
  sourceDecisionId: number | null
  sourceDecisionError?: string | null
  onCreated: (request: AccessRequest) => void
  onCancel: () => void
}) {
  const t = useTranslations('Workflows')
  const { data: record, error, isLoading } = useAuditEvent(sourceDecisionId)
  const { data: datasources } = useDatasources()
  const [datasourceId, setDatasourceId] = useState<number | null>(null)
  const [sql, setSql] = useState('')
  const [title, setTitle] = useState('')
  const [reason, setReason] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [submitError, setSubmitError] = useState<string | null>(null)
  const [roleId, setRoleId] = useState<string | null>(null)
  const [discovery, setDiscovery] = useState<DiscoverRolesResponse | null>(null)
  const [discovering, setDiscovering] = useState(false)
  const [discoverError, setDiscoverError] = useState<string | null>(null)

  const fromDenied = sourceDecisionId != null
  // A query approval always runs under an elevation role R (execute-under-R), so a role must be picked from
  // discovery before submitting — there is no requester-run / no-elevation mode.
  const canSubmit = roleId != null && (fromDenied
    ? reason.trim().length > 0 && record?.decision === 'DENY'
    : datasourceId != null && sql.trim().length > 0 && title.trim().length > 0 && reason.trim().length > 0)

  // Effective (datasourceId, sql) used for role discovery, per composer branch.
  const effectiveSql = fromDenied ? (record?.statement ?? null) : sql.trim() || null
  const effectiveDatasourceId = fromDenied
    ? (datasources?.find((d) => d.name === record?.datasource)?.id ?? null)
    : datasourceId
  const canDiscover = effectiveDatasourceId != null && !!effectiveSql

  // Every discovery (and every effective-input change) bumps this generation counter. A response is
  // applied only if its generation is still current, so a role picked against stale SQL/datasource can
  // neither be shown nor submitted — even if an in-flight request resolves AFTER the inputs changed.
  const discoverSeq = useRef(0)

  // Staleness guard: reset the picker whenever the effective inputs change, and invalidate any
  // in-flight discovery so its late response can't repopulate options for the old SQL/datasource.
  useEffect(() => {
    discoverSeq.current += 1
    setDiscovery(null)
    setRoleId(null)
    setDiscoverError(null)
    setDiscovering(false)
  }, [effectiveSql, effectiveDatasourceId])

  const handleDiscover = async () => {
    if (!canDiscover) return
    // Start a fresh generation; drop any prior selection so it can't be submitted against the reload.
    const seq = (discoverSeq.current += 1)
    setDiscovery(null)
    setRoleId(null)
    setDiscovering(true)
    setDiscoverError(null)
    try {
      const res = await discoverApprovalRoles({
        datasourceId: effectiveDatasourceId!,
        sql: effectiveSql!,
      })
      if (seq !== discoverSeq.current) return // inputs changed (or a newer discovery started) → stale
      setDiscovery(res)
    } catch {
      if (seq !== discoverSeq.current) return
      // Discovery is a non-blocking helper — surface a friendly, actionable message
      // (you can still submit with no elevation) rather than the raw API error.
      setDiscoverError(t('queryComposer.discoverFailed'))
    } finally {
      if (seq === discoverSeq.current) setDiscovering(false)
    }
  }

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!canSubmit) return
    setSubmitting(true)
    setSubmitError(null)
    try {
      const pickedRoleId = roleId != null ? Number(roleId) : undefined
      const res = fromDenied
        ? await createApproval({
            sourceDecisionId: sourceDecisionId!,
            title: title.trim() || undefined,
            reason: reason.trim(),
            roleId: pickedRoleId,
          })
        : await createApproval({
            datasourceId: datasourceId!,
            sql: sql.trim(),
            title: title.trim(),
            reason: reason.trim(),
            roleId: pickedRoleId,
          })
      if (res.wouldAllow) {
        toast.info(t('queryComposer.wouldAllowToast'))
      }
      void mutate(
        swrKeys.myApprovals(undefined),
        (requests: AccessRequest[] | undefined) => [
          res.request,
          ...(requests ?? []).filter((request) => request.id !== res.request.id),
        ],
        { revalidate: true },
      )
      void mutate(swrKeys.approvalInbox)
      onCreated(res.request)
    } catch (err) {
      setSubmitError(errorMessage(err))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div data-workflow-composer-kind="QUERY" className="space-y-4">
      {sourceDecisionError != null ? (
        <ErrorState error={sourceDecisionError} />
      ) : fromDenied && isLoading && !record ? (
        <LoadingState label={t('queryComposer.loadingDenied')} />
      ) : fromDenied && error ? (
        <ErrorState error={error} />
      ) : fromDenied && record && record.decision !== 'DENY' ? (
        <ErrorState error={t('queryComposer.onlyDeniedApproval')} />
      ) : (
        <form className="space-y-4" onSubmit={handleSubmit}>
          {fromDenied && record ? (
            <Card>
              <CardHeader>
                <CardTitle>{t('queryComposer.deniedDecisionTitle', { id: sourceDecisionId })}</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <p className="text-muted-foreground text-[10px] font-semibold tracking-widest uppercase">
                      {t('fields.datasource')}
                    </p>
                    <p className="font-mono">{record.datasource}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground text-[10px] font-semibold tracking-widest uppercase">
                      {t('fields.timestamp')}
                    </p>
                    <p className="font-mono">{formatTimestamp(record.ts)}</p>
                  </div>
                </div>
                <div>
                  <p className="text-muted-foreground text-[10px] font-semibold tracking-widest uppercase">
                    {t('fields.denyReason')}
                  </p>
                  <p className="mt-1 text-sm">{record.detail ?? '—'}</p>
                </div>
                <div>
                  <p className="text-muted-foreground text-[10px] font-semibold tracking-widest uppercase">
                    {t('fields.sql')}
                  </p>
                  <pre className="border-border bg-muted/40 text-foreground/90 mt-1 overflow-x-auto rounded-lg border p-3 font-mono text-xs leading-relaxed whitespace-pre-wrap break-words">
                    {record.statement}
                  </pre>
                </div>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardHeader>
                <CardTitle>{t('queryComposer.queryToReview')}</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-1.5">
                  <Label htmlFor="approval-datasource">{t('fields.datasource')}</Label>
                  <DatasourceSelect
                    id="approval-datasource"
                    value={datasourceId}
                    onChange={setDatasourceId}
                    size="default"
                    className="w-full"
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="approval-sql">{t('fields.sql')}</Label>
                  <Textarea
                    id="approval-sql"
                    value={sql}
                    onChange={(e) => setSql(e.target.value)}
                    placeholder="SELECT id, rrn FROM users WHERE id = 1"
                    rows={8}
                    required
                    className="font-mono text-xs"
                  />
                </div>
              </CardContent>
            </Card>
          )}

          {canDiscover && (
            <Card>
              <CardHeader>
                <CardTitle>{t('fields.role')}</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={handleDiscover}
                  disabled={!canDiscover || discovering}
                >
                  {discovering ? t('queryComposer.discovering') : t('queryComposer.discoverRoles')}
                </Button>

                {discoverError && (
                  <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">
                    {discoverError}
                  </div>
                )}

                {discovery && (
                  <div className="space-y-1.5">
                    <Label htmlFor="approval-role">{t('fields.role')}</Label>
                    <Select
                      value={roleId ?? undefined}
                      onValueChange={(value: string | null) => setRoleId(value)}
                    >
                      <SelectTrigger id="approval-role" className="w-full">
                        <SelectValue placeholder={t('queryComposer.selectRole')} />
                      </SelectTrigger>
                      <SelectContent>
                        {discovery.options.map((option) => (
                          <SelectItem key={option.roleId} value={String(option.roleId)}>
                            {option.roleName}
                            {option.unmasksColumns.length > 0
                              ? ` — ${t('queryComposer.unmasksHint', { columns: option.unmasksColumns.join(', ') })}`
                              : ''}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>

                    {discovery.options.length === 0 && (
                      <p className="text-muted-foreground text-sm">
                        {discovery.baselineAllowed
                          ? t('queryComposer.alreadyAllowed')
                          : t('queryComposer.noRolesFound')}
                      </p>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {submitError && (
            <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">
              {submitError}
            </div>
          )}

          <div className="space-y-1.5">
            <Label htmlFor="approval-title">
              {fromDenied ? t('queryComposer.titleOptional') : t('queryComposer.titleRequired')}
            </Label>
            <Input
              id="approval-title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder={t('queryComposer.titlePlaceholder')}
              required={!fromDenied}
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="approval-reason">{t('fields.reasonRequired')}</Label>
            <Textarea
              id="approval-reason"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder={t('queryComposer.reasonPlaceholder')}
              rows={4}
              required
            />
          </div>

          <div className="flex justify-end gap-2">
            <Button type="button" variant="outline" onClick={onCancel} disabled={submitting}>
              {t('actions.cancel')}
            </Button>
            <Button type="submit" disabled={!canSubmit || submitting}>
              {submitting ? t('actions.submitting') : t('actions.submitRequest')}
            </Button>
          </div>
        </form>
      )}
    </div>
  )
}
