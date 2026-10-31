import { NextResponse } from 'next/server';

/**
 * Lightweight pass-through middleware.
 *
 * The previous deployment forwarded visitor IPs and page-view data to an
 * optional Umami container. Samaritan does not require or contact an external
 * analytics service; this matcher is retained only to keep app routes and
 * static map assets out of middleware work.
 */
export function middleware() {
  return NextResponse.next();
}

export const config = {
  matcher: [
    '/((?!api|_next/static|_next/image|vendor|favicon.ico|sitemap.xml|robots.txt|.*\\.(?:svg|png|jpg|jpeg|gif|webp|mjs|js|css|json|pbf|mvt|woff|woff2|ico|txt)$).*)',
  ],
};
