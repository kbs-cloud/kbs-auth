import React, { useState, useEffect } from 'react';

export default function App() {
  const [isRegister, setIsRegister] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [user, setUser] = useState<any>(null);

  // Password set/change states
  const [showPasswordForm, setShowPasswordForm] = useState(false);
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [pwError, setPwError] = useState('');
  const [pwSuccess, setPwSuccess] = useState('');
  const [pwLoading, setPwLoading] = useState(false);

  // Parse URL search parameters
  const params = new URLSearchParams(window.location.search);
  const clientId = params.get('client_id') || '';
  const redirectUri = params.get('redirect_uri') || '';

  // Get localized sci-fi styling/naming based on client app requesting auth
  const getClientDetails = () => {
    if (!clientId) return { name: 'KBS Cloud Identity', theme: 'portal' };
    const lowerId = clientId.toLowerCase();
    if (lowerId.includes('swarm') || lowerId.includes('starswarm')) {
      return { name: 'Star-Swarm Terminal', theme: 'starswarm', subtitle: 'SECURE COMMAND PROTOCOL' };
    }
    if (lowerId.includes('ticker') || lowerId.includes('clash') || lowerId.includes('tickerclash')) {
      return { name: 'Ticker-Clash Market Node', theme: 'ticker-clash', subtitle: 'TRADER CLEARING SYSTEM' };
    }
    return { name: clientId, theme: 'generic', subtitle: 'EXTERNAL CLIENT SSO' };
  };

  const clientInfo = getClientDetails();

  useEffect(() => {
    // Check if user has an active SSO session
    checkSession();
  }, []);

  const checkSession = async () => {
    try {
      const res = await fetch('/api/auth/me');
      if (res.ok) {
        const data = await res.json();
        setUser(data.user);
        
        // If we have an active session and client_id/redirect_uri are present,
        // trigger the authorize endpoint to auto-redirect the user back with an auth code
        if (clientId && redirectUri) {
          window.location.href = `/api/auth/authorize?client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}`;
        }
      }
    } catch (err) {
      console.log('No active session.');
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccess('');

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, client_id: clientId, redirect_uri: redirectUri })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to authenticate.');
      }

      setSuccess('Access Granted. Establishing connection...');
      
      // If server returned a redirectUri (due to client redirect SSO code), go there
      if (data.redirectUri) {
        setTimeout(() => {
          window.location.href = data.redirectUri;
        }, 1200);
      } else {
        // Otherwise load current portal dashboard
        setUser(data.user);
      }
    } catch (err: any) {
      setError(err.message || 'Server connection failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccess('');

    if (password.length < 8) {
      setError('Password must be at least 8 characters long.');
      setLoading(false);
      return;
    }

    try {
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, displayName })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to register.');
      }

      setSuccess('Account created successfully! Please sign in.');
      setIsRegister(false);
      setPassword('');
    } catch (err: any) {
      setError(err.message || 'Registration failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleLogin = () => {
    // Redirect to backend google auth route, passing client_id/redirect_uri context
    window.location.href = `/api/auth/google?client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}`;
  };

  const handleUpdatePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setPwError('');
    setPwSuccess('');

    if (newPassword.length < 8) {
      setPwError('New password must be at least 8 characters long.');
      return;
    }

    if (newPassword !== confirmPassword) {
      setPwError('New passwords do not match.');
      return;
    }

    setPwLoading(true);

    try {
      const res = await fetch('/api/auth/change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          currentPassword: user?.hasPassword ? currentPassword : '',
          newPassword
        })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to update password.');
      }

      setPwSuccess(user?.hasPassword ? 'Password updated successfully!' : 'Password set successfully! You can now log in using this password.');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      
      setUser((prev: any) => ({ ...prev, hasPassword: true }));
    } catch (err: any) {
      setPwError(err.message || 'Server connection failed.');
    } finally {
      setPwLoading(false);
    }
  };

  const handleLogout = async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
      setUser(null);
      setSuccess('Logged out successfully.');
    } catch (err) {
      setError('Failed to log out.');
    }
  };

  return (
    <>
      <div className="background-grid"></div>
      <div className="aurora"></div>

      <div className="auth-container">
        {user ? (
          // Authenticated Dashboard
          <div>
            <div className="auth-header">
              <h1>SSO PORTAL</h1>
              <p>CONNECTION SECURE</p>
              <div className="client-badge">SSO USER: {user.display_name || user.email}</div>
            </div>

            <div className="alert alert-success">
              You are signed into your central KBS Cloud account.
            </div>

            {clientId && redirectUri ? (
              <div style={{ textAlign: 'center', margin: '2rem 0' }}>
                <div className="spinner" style={{ marginBottom: '1rem' }}></div>
                <p style={{ color: 'var(--color-primary)' }}>Redirecting you back to {clientInfo.name}...</p>
              </div>
            ) : (
              <div style={{ padding: '1rem 0' }}>
                <p style={{ color: 'var(--text-muted)', marginBottom: '1.5rem', fontSize: '0.9rem' }}>
                  No target app redirect configured. You can use this login session to access any KBS game (Star-Swarm, Ticker-Clash, etc.) by navigating back to their pages.
                </p>

                <div className="account-details" style={{ borderTop: '1px solid rgba(255, 255, 255, 0.08)', paddingTop: '1.5rem', marginBottom: '1.5rem' }}>
                  <h2 style={{ fontFamily: 'var(--font-mono)', fontSize: '1.1rem', color: 'var(--color-primary)', marginBottom: '0.8rem', letterSpacing: '1px' }}>
                    ACCOUNT SECURITY
                  </h2>
                  <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '1.25rem', lineHeight: '1.5' }}>
                    <p style={{ marginBottom: '0.4rem' }}>
                      Google Connection: <span style={{ color: user.isGoogleLinked ? 'var(--color-accent)' : 'var(--color-secondary)' }}>{user.isGoogleLinked ? 'CONNECTED' : 'NOT LINKED'}</span>
                    </p>
                    <p>
                      Password Access: <span style={{ color: user.hasPassword ? 'var(--color-accent)' : 'var(--color-secondary)' }}>{user.hasPassword ? 'ACTIVE' : 'NOT CONFIGURED'}</span>
                    </p>
                  </div>

                  {pwError && <div className="alert alert-error" style={{ margin: '0.5rem 0 1rem' }}>{pwError}</div>}
                  {pwSuccess && <div className="alert alert-success" style={{ margin: '0.5rem 0 1rem' }}>{pwSuccess}</div>}

                  {showPasswordForm ? (
                    <form onSubmit={handleUpdatePassword}>
                      {user.hasPassword && (
                        <div className="form-group">
                          <label htmlFor="currentPassword">CURRENT PASSWORD</label>
                          <div className="input-wrapper">
                            <input
                              id="currentPassword"
                              type="password"
                              placeholder="••••••••"
                              value={currentPassword}
                              onChange={(e) => setCurrentPassword(e.target.value)}
                              required
                            />
                          </div>
                        </div>
                      )}

                      <div className="form-group">
                        <label htmlFor="newPassword">{user.hasPassword ? 'NEW PASSWORD' : 'SET PASSWORD'}</label>
                        <div className="input-wrapper">
                          <input
                            id="newPassword"
                            type="password"
                            placeholder="••••••••"
                            value={newPassword}
                            onChange={(e) => setNewPassword(e.target.value)}
                            required
                          />
                        </div>
                      </div>

                      <div className="form-group">
                        <label htmlFor="confirmPassword">CONFIRM PASSWORD</label>
                        <div className="input-wrapper">
                          <input
                            id="confirmPassword"
                            type="password"
                            placeholder="••••••••"
                            value={confirmPassword}
                            onChange={(e) => setConfirmPassword(e.target.value)}
                            required
                          />
                        </div>
                      </div>

                      <div style={{ display: 'flex', gap: '0.75rem', marginTop: '1.25rem' }}>
                        <button type="submit" className="btn-primary" disabled={pwLoading} style={{ flex: 2 }}>
                          {pwLoading ? (
                            <span className="flex-center">
                              <span className="spinner"></span>
                              SAVING...
                            </span>
                          ) : (
                            user.hasPassword ? 'UPDATE PASSWORD' : 'SET PASSWORD'
                          )}
                        </button>
                        <button type="button" className="btn-google" onClick={() => { setShowPasswordForm(false); setPwError(''); setPwSuccess(''); }} style={{ flex: 1, margin: 0 }}>
                          CANCEL
                        </button>
                      </div>
                    </form>
                  ) : (
                    <button className="btn-google" style={{ width: '100%', marginBottom: '1rem' }} onClick={() => setShowPasswordForm(true)}>
                      {user.hasPassword ? 'CHANGE LOCAL PASSWORD' : 'CREATE LOCAL PASSWORD'}
                    </button>
                  )}
                </div>

                <button className="btn-primary" onClick={handleLogout}>
                  Terminate Session (Log Out)
                </button>
              </div>
            )}
          </div>
        ) : (
          // Login / Register Form
          <div>
            <div className="auth-header">
              <h1>KBS CLOUD</h1>
              <p>{clientInfo.subtitle || 'CENTRAL ACCESS POINT'}</p>
              {clientId && (
                <div className="client-badge">
                  Connecting to: {clientInfo.name}
                </div>
              )}
            </div>

            {error && <div className="alert alert-error">{error}</div>}
            {success && <div className="alert alert-success">{success}</div>}

            <form onSubmit={isRegister ? handleRegister : handleLogin}>
              {isRegister && (
                <div className="form-group">
                  <label htmlFor="displayName">NAME / CALLSIGN</label>
                  <div className="input-wrapper">
                    <input
                      id="displayName"
                      type="text"
                      placeholder="e.g. Commander Nova"
                      value={displayName}
                      onChange={(e) => setDisplayName(e.target.value)}
                      required
                    />
                  </div>
                </div>
              )}

              <div className="form-group">
                <label htmlFor="email">EMAIL ADDRESS</label>
                <div className="input-wrapper">
                  <input
                    id="email"
                    type="email"
                    placeholder="email@example.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                  />
                </div>
              </div>

              <div className="form-group">
                <label htmlFor="password">PASSWORD</label>
                <div className="input-wrapper">
                  <input
                    id="password"
                    type="password"
                    placeholder="••••••••"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                  />
                </div>
              </div>

              <button type="submit" className="btn-primary" disabled={loading}>
                {loading ? (
                  <span className="flex-center">
                    <span className="spinner"></span>
                    PROCESSING...
                  </span>
                ) : (
                  isRegister ? 'CREATE ACCOUNT' : 'ESTABLISH CONNECT'
                )}
              </button>
            </form>

            <div className="divider">OR CHOOSE OAUTH</div>

            <button className="btn-google" onClick={handleGoogleLogin}>
              <svg viewBox="0 0 24 24" width="24" height="24">
                <path
                  fill="#EA4335"
                  d="M12 5.04c1.67 0 3.2.58 4.38 1.71l3.27-3.27C17.67 1.62 15.01 1 12 1 7.37 1 3.42 3.65 1.5 7.5l3.85 3c.92-2.73 3.47-4.46 6.65-4.46z"
                />
                <path
                  fill="#4285F4"
                  d="M23.49 12.27c0-.81-.07-1.59-.2-2.27H12v4.51h6.47c-.29 1.48-1.14 2.73-2.4 3.58l3.7 2.87c2.16-2 3.72-4.94 3.72-8.69z"
                />
                <path
                  fill="#FBBC05"
                  d="M5.35 14.5c-.24-.72-.37-1.49-.37-2.3s.13-1.58.37-2.3L1.5 6.9c-.92 1.83-1.5 3.96-1.5 6.1s.58 4.27 1.5 6.1l3.85-3z"
                />
                <path
                  fill="#34A853"
                  d="M12 23c3.24 0 5.97-1.07 7.96-2.92l-3.7-2.87c-1.03.69-2.35 1.11-3.96 1.11-3.18 0-5.73-1.73-6.65-4.46L1.5 16.5C3.42 20.35 7.37 23 12 23z"
                />
              </svg>
              Sign in with Google
            </button>

            <div className="auth-footer">
              {isRegister ? (
                <>
                  Already registered?{' '}
                  <button onClick={() => setIsRegister(false)}>
                    Sign In
                  </button>
                </>
              ) : (
                <>
                  New commander or trader?{' '}
                  <button onClick={() => setIsRegister(true)}>
                    Create Account
                  </button>
                </>
              )}
            </div>
          </div>
        )}
      </div>
    </>
  );
}
