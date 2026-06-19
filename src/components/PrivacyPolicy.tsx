import React from 'react';

interface PrivacyPolicyProps {
  onBack: () => void;
}

export default function PrivacyPolicy({ onBack }: PrivacyPolicyProps) {
  return (
    <div style={{
      position: 'fixed',
      background: 'rgba(5, 3, 13, 0.9)',
      backdropFilter: 'blur(12px)',
      WebkitBackdropFilter: 'blur(12px)',
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
      zIndex: 1000,
      height: '100dvh',
      width: '100vw',
      top: 0,
      left: 0,
      paddingBottom: '24px',
      flexDirection: 'column',
    }}>
      {/* Header */}
      <div style={{
        width: '100%',
        padding: '24px 40px 12px',
        display: 'flex',
        alignItems: 'center',
        gap: '16px',
        flexShrink: 0,
        maxWidth: '800px',
        flexDirection: 'column'
      }}>
        <button
          onClick={onBack}
          style={{
            padding: '8px 18px',
            fontSize: '12px',
            backgroundColor: 'rgba(255, 255, 255, 0.05)',
            border: '1px solid rgba(0, 255, 255, 0.15)',
            color: 'var(--text-main)',
            borderRadius: '6px',
            cursor: 'pointer',
            fontFamily: 'var(--font-mono)',
            letterSpacing: '1px',
            transition: 'all 0.2s ease',
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.backgroundColor = 'rgba(255, 255, 255, 0.1)';
            e.currentTarget.style.borderColor = 'rgba(0, 255, 255, 0.4)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.backgroundColor = 'rgba(255, 255, 255, 0.05)';
            e.currentTarget.style.borderColor = 'rgba(0, 255, 255, 0.15)';
          }}
        >
          ← BACK TO SIGN IN
        </button>
        <h1 style={{
          fontFamily: 'var(--font-mono)',
          fontSize: '24px',
          fontWeight: 700,
          letterSpacing: '3px',
          color: 'var(--color-primary)',
          textShadow: '0 0 15px rgba(0, 255, 255, 0.3)',
          marginTop: '12px',
        }}>
          KBS IDENTITY PRIVACY POLICY
        </h1>
      </div>

      {/* Scrollable Content */}
      <div style={{
        flex: 1,
        minHeight: 0,
        width: '100%',
        maxWidth: '800px',
        overflowY: 'auto',
        padding: '0 40px 40px'
      }}>
        <div style={{
          padding: '32px',
          lineHeight: '1.7',
          fontSize: '14px',
          color: 'var(--text-main)',
          border: '1px solid rgba(0, 255, 255, 0.15)',
          borderRadius: '12px',
          background: 'rgba(12, 8, 29, 0.6)',
          boxShadow: '0 8px 32px 0 rgba(0, 0, 0, 0.37)',
        }}>
          <p style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '12px', marginBottom: '24px' }}>
            Last Updated: June 18, 2026
          </p>

          <Section title="1. OVERVIEW">
            This Privacy Policy explains how KBS Identity ("the Service") collects, uses, hashes, and protects user authentication profiles.
          </Section>

          <Section title="2. INFORMATION WE COLLECT">
            <SubSection title="SSO Login Credentials">
              During registration and authentication:
              <ul style={{ paddingLeft: '20px', margin: '8px 0' }}>
                <li>Email address.</li>
                <li>Display name or callsign.</li>
                <li>Bcrypt-hashed password (passwords are never stored in plain text).</li>
                <li>Google account identifiers (if connecting via Google OAuth SSO).</li>
              </ul>
            </SubSection>
            <SubSection title="Session & Device Identifiers">
              For account security and maintaining active sessions:
              <ul style={{ paddingLeft: '20px', margin: '8px 0' }}>
                <li>Secure HTTP-only session cookies.</li>
                <li>CSRF validation tokens to prevent Cross-Site Request Forgery.</li>
                <li>Basic network headers (IP addresses, client browser signatures) logged temporarily for rate-limiting.</li>
              </ul>
            </SubSection>
          </Section>

          <Section title="3. HOW WE USE YOUR INFORMATION">
            Your login and profile records are used to:
            <ul style={{ paddingLeft: '20px', margin: '8px 0' }}>
              <li>Authenticate your identity and authorize client applications.</li>
              <li>Manage credential setup and password modification.</li>
              <li>Send SSO callback redirects to verified client systems.</li>
              <li>Mitigate rate-limit breaches or coordinate lockouts on excessive failed login attempts.</li>
            </ul>
          </Section>

          <Section title="4. DATA SECURITY & ENCRYPTION">
            <ul style={{ paddingLeft: '20px', margin: '8px 0' }}>
              <li>All user passwords are hashed using bcrypt before database insertion.</li>
              <li>Session tokens are protected with HTTP-only and SameSite flags where applicable.</li>
              <li>OAuth client secret handshakes are completed backend-to-backend.</li>
            </ul>
          </Section>

          <Section title="5. COOKIES USE">
            The Service issues:
            <ul style={{ paddingLeft: '20px', margin: '8px 0' }}>
              <li><strong>SSO Session Cookie</strong> — maintains your login state.</li>
              <li><strong>CSRF Cookie</strong> — protects request boundaries.</li>
            </ul>
          </Section>

          <Section title="6. DATA SHARING & REDIRECTION">
            <ul style={{ paddingLeft: '20px', margin: '8px 0' }}>
              <li>We never sell or distribute your data.</li>
              <li>When logging into a client application (e.g. Star-Swarm), KBS Identity passes your authorized account email and display name to that client's callback system. Please refer to each client's specific privacy policy.</li>
              <li><strong>Google OAuth</strong> — authentication requests are routed to Google's identity API.</li>
            </ul>
          </Section>

          <Section title="7. DATA RETENTION">
            Credentials and logs are preserved inside our SQLite user database until an account deletion is requested.
          </Section>

          <Section title="8. YOUR RIGHTS">
            You may change your callsign, update your password, or request complete account deletion at any time.
          </Section>

          <Section title="9. CONTACT">
            For security issues, vulnerability disclosures, or inquiries, please open an issue on our{' '}
            <a
              href="https://github.com/kbs-cloud/kbs-auth"
              target="_blank"
              rel="noopener noreferrer"
              style={{ color: 'var(--color-primary)', textDecoration: 'underline' }}
            >
              GitHub repository
            </a>.
          </Section>
        </div>
      </div>
    </div>
  );
}

const Section: React.FC<{ title: string; children: React.ReactNode }> = ({ title, children }) => (
  <div style={{ marginBottom: '24px' }}>
    <h3 style={{
      fontFamily: 'var(--font-mono)',
      fontSize: '13px',
      fontWeight: 600,
      letterSpacing: '1.5px',
      color: 'var(--color-primary)',
      marginBottom: '10px',
      textShadow: '0 0 8px rgba(0, 255, 255, 0.2)'
    }}>
      {title}
    </h3>
    <div>{children}</div>
  </div>
);

const SubSection: React.FC<{ title: string; children: React.ReactNode }> = ({ title, children }) => (
  <div style={{ marginBottom: '12px' }}>
    <h4 style={{
      fontSize: '12px',
      fontWeight: 600,
      letterSpacing: '0.5px',
      color: 'var(--text-main)',
      marginBottom: '6px'
    }}>
      {title}
    </h4>
    <div>{children}</div>
  </div>
);
