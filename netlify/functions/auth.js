const CLIENT_ID = '1000669204362-eqv8cn2kr2b26q8j7ldv2e0rd8pbferk.apps.googleusercontent.com';
const CLIENT_SECRET = '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';
const REDIRECT_URI = 'https://itp-photos.netlify.app/.netlify/functions/auth/callback';

exports.handler = async (event) => {
  const path = event.path.replace('/.netlify/functions/auth', '') || '/';
  const params = event.queryStringParameters || {};

  // ── /callback  — Google redirects here after sign-in ──────────────────────
  if (path === '/callback') {
    const code = params.code;
    const state = params.state || '/';
    if (!code) return redirect(state + '?error=no_code');

    try {
      const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code,
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET,
          redirect_uri: REDIRECT_URI,
          grant_type: 'authorization_code',
        }),
      });
      const tokens = await tokenRes.json();
      if (tokens.error) return redirect(state + '?error=' + tokens.error);

      // Get user info
      const userRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
        headers: { Authorization: 'Bearer ' + tokens.access_token },
      });
      const user = await userRes.json();

      // Pass tokens back to the app via URL fragment (never hits server logs)
      const payload = encodeURIComponent(JSON.stringify({
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        expires_in: tokens.expires_in,
        email: user.email,
        name: user.name,
      }));

      return {
        statusCode: 302,
        headers: { Location: `/?auth=${payload}` },
      };
    } catch (e) {
      return redirect('/?error=auth_failed');
    }
  }

  // ── /refresh  — app calls this to get a new access token ──────────────────
  if (path === '/refresh' && event.httpMethod === 'POST') {
    let body = {};
    try { body = JSON.parse(event.body || '{}'); } catch(e) {}
    const refreshToken = body.refresh_token;
    if (!refreshToken) return json(400, { error: 'no_refresh_token' });

    try {
      const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          refresh_token: refreshToken,
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET,
          grant_type: 'refresh_token',
        }),
      });
      const tokens = await tokenRes.json();
      if (tokens.error) return json(401, { error: tokens.error });
      return json(200, {
        access_token: tokens.access_token,
        expires_in: tokens.expires_in,
      });
    } catch (e) {
      return json(500, { error: 'refresh_failed' });
    }
  }

  // ── /login  — start OAuth flow ─────────────────────────────────────────────
  const authUrl = 'https://accounts.google.com/o/oauth2/v2/auth?' + new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: 'https://www.googleapis.com/auth/drive.file https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile',
    access_type: 'offline',
    prompt: 'consent',
    state: params.state || '/',
  });

  return { statusCode: 302, headers: { Location: authUrl } };
};

function redirect(url) {
  return { statusCode: 302, headers: { Location: url } };
}
function json(status, body) {
  return {
    statusCode: status,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
    body: JSON.stringify(body),
  };
}

