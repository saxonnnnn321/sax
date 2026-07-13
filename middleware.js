// ============================================================
// Password gate for the whole dashboard (Vercel Edge Middleware).
//
// It asks the browser for a username + password (HTTP Basic Auth)
// before serving any page. Your browser remembers it, so you log in
// once per device.
//
// The username/password are NOT stored here — they come from Vercel
// Environment Variables SITE_USER and SITE_PASS. Until BOTH are set,
// this gate stays OPEN (no lock), so you can never lock yourself out
// by accident. Set them in Vercel, redeploy, and the lock turns on.
//
// To change the password later: edit SITE_PASS in Vercel + redeploy.
// To turn protection off: delete the two env vars (or this file) + redeploy.
// ============================================================

export const config = {
  // Protect everything except Vercel's internal paths and the favicon.
  matcher: ['/((?!_vercel|favicon.ico).*)'],
};

export default function middleware(request) {
  const USER = process.env.SITE_USER;
  const PASS = process.env.SITE_PASS;

  // Not configured yet -> stay open (prevents accidental lockout).
  if (!USER || !PASS) return;

  const header = request.headers.get('authorization');
  if (header) {
    const [scheme, encoded] = header.split(' ');
    if (scheme === 'Basic' && encoded) {
      const decoded = atob(encoded);
      const i = decoded.indexOf(':');
      const user = decoded.slice(0, i);
      const pass = decoded.slice(i + 1);
      if (user === USER && pass === PASS) return; // correct -> let it through
    }
  }

  return new Response('Authentication required.', {
    status: 401,
    headers: { 'WWW-Authenticate': 'Basic realm="Saxons Dashboard", charset="UTF-8"' },
  });
}
