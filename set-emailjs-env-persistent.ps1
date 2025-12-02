# Persists EmailJS credentials at the current user's environment scope.
setx EMAILJS_SERVICE_ID  "service_sb5qepo"
setx EMAILJS_TEMPLATE_ID "Quote_Request"
setx EMAILJS_PUBLIC_KEY  "Akl6ld5gZ8KH5KsPp"
setx EMAILJS_UPLOAD_TEMPLATE_ID "Quote_Request"
setx EMAILJS_DESIGN_TEMPLATE_ID "Quote_Request"

Write-Host "EmailJS environment variables saved. Open a new PowerShell session to load them."
Write-Host "Note: Set EMAILJS_PRIVATE_KEY separately only if your EmailJS account requires it."

