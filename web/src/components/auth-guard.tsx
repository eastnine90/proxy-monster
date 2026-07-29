'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { Loader2 } from 'lucide-react'
import { useAuth } from '@/lib/auth'

/** Gates the authenticated shell: redirects to /login when unauthenticated, shows a spinner while resolving. */
export function AuthGuard({ children }: { children: React.ReactNode }) {
  const { status, unauthReason } = useAuth()
  const router = useRouter()

  useEffect(() => {
    if (status === 'unauthenticated') {
      router.replace(unauthReason === 'displaced' ? '/displaced' : '/login')
    }
  }, [status, unauthReason, router])

  if (status !== 'authenticated') {
    return (
      <div className="flex h-svh items-center justify-center">
        <Loader2 className="text-muted-foreground size-5 animate-spin" />
      </div>
    )
  }
  return <>{children}</>
}
