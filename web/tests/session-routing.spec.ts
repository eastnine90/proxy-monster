import { expect, test, type Page } from 'playwright/test'

const SESSION_CONFIG = {
  heartbeatMs: 90_000,
  idleWarnLeadMs: 60_000,
  absoluteWarnLeadMs: 300_000,
  absoluteCapAmount: 2,
  absoluteCapUnit: 'hours',
}

async function mockAppBootstrap(page: Page, meResponse: { status: number; body: object }) {
  await page.route('**/auth/config', (route) => route.fulfill({
    contentType: 'application/json',
    body: JSON.stringify({ oidcEnabled: false, authDebug: true, session: SESSION_CONFIG }),
  }))
  await page.route('**/auth/me', (route) => route.fulfill({
    status: meResponse.status,
    contentType: 'application/json',
    body: JSON.stringify(meResponse.body),
  }))
}

test('a displaced session lands on the displacement interstitial', async ({ page }) => {
  await mockAppBootstrap(page, { status: 401, body: { reason: 'displaced' } })

  await page.goto('/query')

  await expect(page).toHaveURL(/\/displaced$/)
  await expect(page.getByRole('heading', { name: 'You were signed in on another device' })).toBeVisible()
})

for (const reason of ['expired', 'none']) {
  test(`a ${reason} session lands on login`, async ({ page }) => {
    await mockAppBootstrap(page, { status: 401, body: { reason } })

    await page.goto('/query')

    await expect(page).toHaveURL(/\/login$/)
  })
}

for (const locale of ['en', 'ko'] as const) {
  test(`session-expired login banner renders in ${locale}`, async ({ context, page }) => {
    await context.addCookies([{
      name: 'NEXT_LOCALE',
      value: locale,
      url: 'http://localhost:41310',
    }])
    await mockAppBootstrap(page, { status: 401, body: { reason: 'none' } })

    await page.goto('/login?reason=session_expired')

    const copy = locale === 'en'
      ? 'Your session has ended — please sign in again.'
      : '세션이 종료되었습니다 — 다시 로그인해 주세요.'
    await expect(page.getByText(copy)).toBeVisible()
  })
}
