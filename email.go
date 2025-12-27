package secureauth

import (
    "bytes"
    "context"
    "fmt"
    "html/template"
    "net/smtp"
    "strings"
)

// EmailSender is the interface for sending magic link emails.
// Implement this interface to use your preferred email service.
type EmailSender interface {
    // SendMagicLink sends a magic link email to the specified address.
    // link is the full URL the user should click.
    // expiresInMinutes indicates how long the link is valid.
    SendMagicLink(ctx context.Context, to, link string, expiresInMinutes int) error
}

// SMTPConfig holds configuration for the SMTP email sender.
type SMTPConfig struct {
    Host     string // SMTP server host (e.g., "smtp.gmail.com")
    Port     int    // SMTP server port (e.g., 587)
    Username string // SMTP username (often the email address)
    Password string // SMTP password or app-specific password
    From     string // From address (e.g., "noreply@yourapp.com")
    FromName string // From name (e.g., "YourApp")
}

// SMTPEmailSender sends emails via SMTP.
type SMTPEmailSender struct {
    cfg     SMTPConfig
    baseURL string // App base URL for branding
}

// NewSMTPEmailSender creates a new SMTP email sender.
func NewSMTPEmailSender(cfg SMTPConfig, appBaseURL string) *SMTPEmailSender {
    return &SMTPEmailSender{
        cfg:     cfg,
        baseURL: appBaseURL,
    }
}

// SendMagicLink sends a magic link email via SMTP.
func (s *SMTPEmailSender) SendMagicLink(ctx context.Context, to, link string, expiresInMinutes int) error {
    subject := "Sign in to your account"

    // Build HTML email body
    htmlBody, err := s.buildMagicLinkEmail(link, expiresInMinutes)
    if err != nil {
        return fmt.Errorf("build email body: %w", err)
    }

    // Build plain text alternative
    textBody := s.buildMagicLinkTextEmail(link, expiresInMinutes)

    // Build the email message with multipart MIME
    msg := s.buildMIMEMessage(to, subject, textBody, htmlBody)

    // Send via SMTP
    addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
    auth := smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)

    if err := smtp.SendMail(addr, auth, s.cfg.From, []string{to}, msg); err != nil {
        return fmt.Errorf("smtp send: %w", err)
    }

    return nil
}

func (s *SMTPEmailSender) buildMIMEMessage(to, subject, textBody, htmlBody string) []byte {
    var buf bytes.Buffer
    boundary := "==MagicLinkBoundary=="

    // Headers
    fromHeader := s.cfg.From
    if s.cfg.FromName != "" {
        fromHeader = fmt.Sprintf("%s <%s>", s.cfg.FromName, s.cfg.From)
    }

    buf.WriteString(fmt.Sprintf("From: %s\r\n", fromHeader))
    buf.WriteString(fmt.Sprintf("To: %s\r\n", to))
    buf.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
    buf.WriteString("MIME-Version: 1.0\r\n")
    buf.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"\r\n", boundary))
    buf.WriteString("\r\n")

    // Plain text part
    buf.WriteString(fmt.Sprintf("--%s\r\n", boundary))
    buf.WriteString("Content-Type: text/plain; charset=\"UTF-8\"\r\n")
    buf.WriteString("Content-Transfer-Encoding: 7bit\r\n")
    buf.WriteString("\r\n")
    buf.WriteString(textBody)
    buf.WriteString("\r\n")

    // HTML part
    buf.WriteString(fmt.Sprintf("--%s\r\n", boundary))
    buf.WriteString("Content-Type: text/html; charset=\"UTF-8\"\r\n")
    buf.WriteString("Content-Transfer-Encoding: 7bit\r\n")
    buf.WriteString("\r\n")
    buf.WriteString(htmlBody)
    buf.WriteString("\r\n")

    // End boundary
    buf.WriteString(fmt.Sprintf("--%s--\r\n", boundary))

    return buf.Bytes()
}

func (s *SMTPEmailSender) buildMagicLinkTextEmail(link string, expiresInMinutes int) string {
    return fmt.Sprintf(`Sign in to your account

Click the link below to sign in. This link expires in %d minutes.

%s

If you didn't request this email, you can safely ignore it.

---
This email was sent from %s
`, expiresInMinutes, link, s.baseURL)
}

func (s *SMTPEmailSender) buildMagicLinkEmail(link string, expiresInMinutes int) (string, error) {
    const emailTemplate = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in to your account</title>
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f8fafc;">
    <table role="presentation" style="width: 100%; border-collapse: collapse;">
        <tr>
            <td style="padding: 40px 20px;">
                <table role="presentation" style="max-width: 480px; margin: 0 auto; background-color: #ffffff; border-radius: 16px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">
                    <tr>
                        <td style="padding: 40px;">
                            <div style="text-align: center; margin-bottom: 24px;">
                                <div style="display: inline-block; width: 48px; height: 48px; background-color: #dbeafe; border-radius: 50%; line-height: 48px; font-size: 24px;">
                                    &#128274;
                                </div>
                            </div>

                            <h1 style="margin: 0 0 16px; font-size: 24px; font-weight: 600; text-align: center; color: #1e293b;">
                                Sign in to your account
                            </h1>

                            <p style="margin: 0 0 24px; font-size: 16px; line-height: 24px; text-align: center; color: #64748b;">
                                Click the button below to sign in. This link will expire in <strong>{{.ExpiresInMinutes}} minutes</strong>.
                            </p>

                            <div style="text-align: center; margin-bottom: 24px;">
                                <a href="{{.Link}}" style="display: inline-block; padding: 14px 32px; background-color: #3b82f6; color: #ffffff; text-decoration: none; font-size: 16px; font-weight: 500; border-radius: 12px;">
                                    Sign in
                                </a>
                            </div>

                            <p style="margin: 0 0 16px; font-size: 14px; line-height: 20px; text-align: center; color: #94a3b8;">
                                If the button doesn't work, copy and paste this link into your browser:
                            </p>

                            <p style="margin: 0 0 24px; font-size: 12px; line-height: 18px; text-align: center; word-break: break-all; color: #3b82f6;">
                                {{.Link}}
                            </p>

                            <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 24px 0;">

                            <p style="margin: 0; font-size: 12px; line-height: 18px; text-align: center; color: #94a3b8;">
                                If you didn't request this email, you can safely ignore it.
                            </p>
                        </td>
                    </tr>
                </table>

                <p style="margin: 24px 0 0; font-size: 12px; line-height: 18px; text-align: center; color: #94a3b8;">
                    Sent from {{.BaseURL}}
                </p>
            </td>
        </tr>
    </table>
</body>
</html>`

    tmpl, err := template.New("email").Parse(emailTemplate)
    if err != nil {
        return "", err
    }

    var buf bytes.Buffer
    err = tmpl.Execute(&buf, map[string]interface{}{
        "Link":             link,
        "ExpiresInMinutes": expiresInMinutes,
        "BaseURL":          s.baseURL,
    })
    if err != nil {
        return "", err
    }

    return buf.String(), nil
}

// Validate checks that all required SMTP configuration fields are set.
func (cfg SMTPConfig) Validate() error {
    var missing []string
    if cfg.Host == "" {
        missing = append(missing, "Host")
    }
    if cfg.Port == 0 {
        missing = append(missing, "Port")
    }
    if cfg.Username == "" {
        missing = append(missing, "Username")
    }
    if cfg.Password == "" {
        missing = append(missing, "Password")
    }
    if cfg.From == "" {
        missing = append(missing, "From")
    }
    if len(missing) > 0 {
        return fmt.Errorf("missing SMTP configuration: %s", strings.Join(missing, ", "))
    }
    return nil
}

// LoggingEmailSender is a no-op sender that logs the magic link instead of sending.
// Useful for development and testing.
type LoggingEmailSender struct {
    LogFunc func(format string, args ...interface{})
}

// NewLoggingEmailSender creates a sender that logs magic links.
// If logFunc is nil, it uses fmt.Printf.
func NewLoggingEmailSender(logFunc func(format string, args ...interface{})) *LoggingEmailSender {
    if logFunc == nil {
        logFunc = func(format string, args ...interface{}) {
            fmt.Printf(format, args...)
        }
    }
    return &LoggingEmailSender{LogFunc: logFunc}
}

// SendMagicLink logs the magic link instead of sending an email.
func (l *LoggingEmailSender) SendMagicLink(ctx context.Context, to, link string, expiresInMinutes int) error {
    l.LogFunc("[MAGIC LINK] To: %s | Link: %s | Expires in: %d minutes\n", to, link, expiresInMinutes)
    return nil
}
