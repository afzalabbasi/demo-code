package service

import (
	"bytes"
	"fmt"
	"github.com/sirupsen/logrus"
	"net/smtp"
)

type EmailOptions struct {
	FromName    string
	FromEmail   string
	Subject     string
	ToName      string
	ToEmail     string
	TextContent string
	HtmlContent string
}

// SendEmail method accepts email options data
// Converts string into buffer and
// Send email to users.
func SendEmail(options EmailOptions) {
	smtpHost := "smtp.sendgrid.net"
	smtpPort := "587"
	emailAuth := smtp.PlainAuth("", "apikey", "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", smtpHost)
	to := []string{
		options.ToEmail,
	}
	mime := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
	var b bytes.Buffer

	// Write strings to the Buffer.
	b.WriteString("From: ")
	b.WriteString("iem.saad@hotmail.com")
	b.WriteString("\n")
	b.WriteString("To: ")
	b.WriteString(options.ToEmail)
	b.WriteString("\n")
	b.WriteString("Subject :")
	b.WriteString(options.Subject)
	b.WriteString(mime)
	b.WriteString("\n")
	b.WriteString("\n")
	b.WriteString(options.HtmlContent)
	// Converts to a string and print it.
	addr := fmt.Sprintf("%s:%s", smtpHost, smtpPort)
	if err := smtp.SendMail(addr, emailAuth, "iem.saad@hotmail.com", to, []byte(b.String())); err != nil {
		logrus.Errorln("Send Email Error:", err.Error())
		return
	}

	logrus.Infoln("Email Sent Successfully!")
}
