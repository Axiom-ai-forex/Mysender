# Example implementation in your email sender
handler = Fedora41SMTPHandler()

# Simulate SMTP response processing
smtp_response = "550 5.1.1 User unknown in virtual mailbox table"
result = handler.handle_smtp_response(smtp_response, "invalid@example.com", attempt_count=1)

print(f"Should retry: {result['should_retry']}")
print(f"Bounce reason: {result['bounce_analysis']['subcategory']}")
print(f"Recommended action: {result['action']}")

