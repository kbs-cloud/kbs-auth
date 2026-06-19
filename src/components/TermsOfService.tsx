import React from 'react';

interface TermsOfServiceProps {
  onBack: () => void;
}

export default function TermsOfService({ onBack }: TermsOfServiceProps) {
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
          KBS IDENTITY TERMS OF SERVICE
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

          <Section title="1. ACCEPTANCE OF TERMS">
            By accessing, creating an account, or authenticating via KBS Identity ("the Service" or "the Auth Portal"), you agree to be bound by these Terms of Service ("Terms"). If you do not agree, do not use the Service. KBS Identity is an open-source project licensed under the MIT License.
          </Section>

          <Section title="2. DESCRIPTION OF SERVICE">
            KBS Identity is a secure identity management and Single Sign-On (SSO) service. It allows users to register central accounts, secure their credentials, and authenticate seamlessly across authorized client applications (such as KBS Cloud, Star-Swarm, Ticker-Clash, etc.). The Service is provided as-is, free of charge, and may be modified or discontinued at any time.
          </Section>

          <Section title="3. USER ACCOUNTS & CREDENTIALS">
            <ul style={{ paddingLeft: '20px', margin: '8px 0' }}>
              <li>Accounts can be created using email/password credentials or via Google OAuth.</li>
              <li>You are solely responsible for maintaining the confidentiality of your password and authentication sessions.</li>
              <li>You agree to provide true and accurate info (email address, display name) during registration.</li>
              <li>Brute-force attempts, session stealing, credential stuffing, or other unauthorized access vector testing against the login portal is strictly prohibited.</li>
            </ul>
          </Section>

          <Section title="4. INTEGRATED CLIENT APPLICATIONS">
            <ul style={{ paddingLeft: '20px', margin: '8px 0' }}>
              <li>KBS Identity passes authentication tokens or authorization codes to integrated applications (e.g. `starswarm` or `tickerclash`) only when you explicitly log in or choose to authorize.</li>
              <li>Each integrated client application is governed by its own respective Terms of Service and Privacy Policy. The operators of KBS Identity are not responsible for client application behavior.</li>
            </ul>
          </Section>

          <Section title="5. INTELLECTUAL PROPERTY">
            KBS Identity's codebase is released under the MIT License. You are free to copy, modify, distribute, and/or sublicense the source code, subject to the conditions of the license. Original identity portal logos and branding remain the property of the KBS contributors.
          </Section>

          <Section title="6. DISCLAIMER OF WARRANTIES">
            THE IDENTITY SERVICE IS PROVIDED "AS IS" AND "AS AVAILABLE" WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED. THE DEVELOPERS AND INSTANCE OPERATORS DO NOT WARRANT THAT THE SERVICE WILL BE UNINTERRUPTED, COMPLETELY SECURE, ERRORS-FREE, OR FREE OF HARMFUL VULNERABILITIES.
          </Section>

          <Section title="7. LIMITATION OF LIABILITY">
            IN NO EVENT SHALL THE KBS IDENTITY CONTRIBUTORS OR OPERATORS BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, OR PUNITIVE DAMAGES (INCLUDING LOSS OF ACCOUNT CREDENTIALS OR SECURITY BREACHES) ARISING FROM YOUR USE OF THE SERVICE.
          </Section>

          <Section title="8. MODIFICATIONS TO TERMS">
            We reserve the right to modify these Terms at any time. Continued use of the login portal after changes constitutes acceptance of the modified Terms.
          </Section>

          <Section title="9. GOVERNING LAW">
            These Terms shall be governed by applicable laws. Any disputes shall be resolved through good-faith negotiation or arbitration.
          </Section>

          <Section title="10. CONTACT">
            For security audits, questions, or issues, please open an issue on our{' '}
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
