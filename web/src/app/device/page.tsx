'use client'

// /device — the browser-facing verification step of the pmon device-login flow.
// `pmon login` prints a URL + short code and polls the control-plane; the user
// lands here (auto-opened as /device?user_code=WDJB-MJHT, or bare /device when
// the link was clicked manually), confirms the code, and continues into the
// control-plane authorize endpoint, which approves or bounces through /login.
// Styled to match /login (same header, card, and UI components).

import { Suspense, useState, type FormEvent } from 'react'
import { useSearchParams } from 'next/navigation'
import { useTranslations } from 'next-intl'
import { ShieldHalf } from 'lucide-react'
import { API_BASE } from '@/lib/api/client'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

/** Uppercase, strip non-alphanumerics, cap at the 8 significant characters. */
function normalizeCode(raw: string): string {
  return raw.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8)
}

/** Render the 8-char code as the familiar XXXX-XXXX (hyphen appears after 4 chars). */
function formatCode(clean: string): string {
  return clean.length > 4 ? `${clean.slice(0, 4)}-${clean.slice(4)}` : clean
}

function DeviceInner() {
  const t = useTranslations('Device')
  const params = useSearchParams()
  const initialCode = normalizeCode(params.get('user_code') ?? '')
  const prefilled = initialCode.length > 0

  const [code, setCode] = useState(initialCode)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const complete = code.length === 8

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    if (!complete || submitting) return
    setError(null)
    setSubmitting(true)
    // The CP wants the human-readable code with its hyphen (e.g. WDJB-MJHT).
    const userCode = formatCode(code)
    try {
      const res = await fetch(`${API_BASE}/auth/device/confirm`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ userCode }),
      })
      if (!res.ok) {
        setError(t('error'))
        setSubmitting(false)
        return
      }
      // Full-page navigation (NOT fetch): the authorize endpoint issues browser
      // redirects — it either approves (already logged in) or bounces through /login.
      window.location.href = `${API_BASE}/auth/device/authorize?user_code=${encodeURIComponent(userCode)}`
    } catch {
      setError(t('error'))
      setSubmitting(false)
    }
  }

  return (
    <div className="flex min-h-svh flex-col items-center justify-center gap-6 px-4">
      <div className="flex flex-col items-center gap-2">
        <div className="flex items-center gap-2">
          <ShieldHalf className="size-5" />
          <span className="font-mono text-lg font-semibold tracking-tight">proxy-monster</span>
        </div>
        <p className="text-muted-foreground text-sm">{t('tagline')}</p>
      </div>

      <div className="bg-card w-full max-w-sm rounded-xl border p-6 shadow-sm">
        <h1 className="mb-1 text-base font-semibold">{t('title')}</h1>
        <p className="text-muted-foreground mb-4 text-sm">
          {prefilled ? t('confirm') : t('instruction')}
        </p>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="user_code">{t('codeLabel')}</Label>
            <Input
              id="user_code"
              value={formatCode(code)}
              onChange={(e) => setCode(normalizeCode(e.target.value))}
              autoComplete="off"
              autoCapitalize="characters"
              spellCheck={false}
              maxLength={9}
              autoFocus={!prefilled}
              className="text-center font-mono text-lg tracking-[0.35em] uppercase"
            />
          </div>

          {error && <p className="text-sm text-red-500">{error}</p>}

          <Button type="submit" className="w-full" disabled={!complete || submitting}>
            {submitting ? t('continuing') : t('continue')}
          </Button>
        </form>
      </div>
    </div>
  )
}

export default function DevicePage() {
  return (
    <Suspense>
      <DeviceInner />
    </Suspense>
  )
}
