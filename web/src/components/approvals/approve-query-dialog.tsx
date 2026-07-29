'use client'

import { useState } from 'react'
import { useTranslations } from 'next-intl'
import { mutate } from 'swr'
import { toast } from 'sonner'
import { approveApproval, ApiError } from '@/lib/api/client'
import type { AccessRequest } from '@/lib/api/types'
import { swrKeys } from '@/lib/hooks'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'

type Translator = ReturnType<typeof useTranslations>

function errorMessage(err: unknown, t: Translator): string {
  if (err instanceof ApiError) {
    try {
      const parsed = JSON.parse(err.message) as { error?: string }
      return parsed.error ?? err.message
    } catch {
      return err.message
    }
  }
  return err instanceof Error ? err.message : t('approveDialog.approveFailed')
}

export function ApproveQueryDialog({
  request,
  onClose,
  onApproved,
}: {
  request: AccessRequest | null
  onClose: () => void
  onApproved?: () => void
}) {
  const t = useTranslations('Workflows')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleOpenChange = (open: boolean) => {
    if (!open && !busy) onClose()
  }

  const handleApprove = async () => {
    if (!request) return
    setBusy(true)
    setError(null)
    try {
      await approveApproval(request.id)
      toast.success(t('approveDialog.approvedToast', { principal: request.principal }))
      mutate(swrKeys.approvalInbox)
      mutate(swrKeys.approval(request.id))
      onApproved?.()
      onClose()
    } catch (err) {
      setError(errorMessage(err, t))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={request !== null} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t('approveDialog.title')}</DialogTitle>
          <DialogDescription>
            {request
              ? t('approveDialog.descriptionWithPrincipal', { principal: request.principal })
              : t('approveDialog.descriptionFallback')}
          </DialogDescription>
        </DialogHeader>

        {error && (
          <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">
            {error}
          </div>
        )}

        <p className="text-muted-foreground text-sm">{t('approveDialog.executeUnderRNote')}</p>

        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            {t('actions.cancel')}
          </Button>
          <Button onClick={handleApprove} disabled={busy}>
            {busy ? t('actions.approving') : t('actions.approve')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
