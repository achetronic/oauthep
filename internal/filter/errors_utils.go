package filter

import (
	"bytes"
	"text/template"
)

var (
	ErrorPageTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authentication Error - Oauthep</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
            background: #f8f6f1;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #1f2937;
        }
        
        .container {
            background: #ffffff;
            border-radius: 20px;
            padding: 3rem 2.5rem;
            max-width: 480px;
            width: 90%;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05), 0 10px 25px rgba(0, 0, 0, 0.08);
            text-align: center;
            border: 1px solid #f3f4f6;
        }
        
        .icon {
            width: 48px;
            height: 48px;
            margin: 0 auto 1.5rem;
            background: #ff7875;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 20px;
            color: white;
            box-shadow: 0 2px 6px rgba(255, 120, 117, 0.2);
        }
        
        h1 {
            font-size: 1.375rem;
            font-weight: 600;
            margin-bottom: 0.75rem;
            color: #111827;
        }
        
        .error-message {
            color: #6b7280;
            margin-bottom: 1.5rem;
            font-size: 0.95rem;
        }
        
        .error-code {
            background: #f9fafb;
            border: 1px solid #f3f4f6;
            border-radius: 8px;
            padding: 1rem;
            margin: 1.5rem 0;
            font-family: monospace;
            font-size: 0.8rem;
            color: #6b7280;
            font-weight: 500;
        }
        
        .actions {
            display: flex;
            gap: 0.75rem;
            margin-top: 2rem;
        }
        
        .btn {
            flex: 1;
            padding: 0.875rem 1.25rem;
            border: none;
            border-radius: 8px;
            font-weight: 500;
            cursor: pointer;
            text-decoration: none;
            font-size: 0.875rem;
            transition: all 0.15s ease;
        }
        
        .btn-primary {
            background: #6366f1;
            color: white;
        }
        
        .btn-primary:hover {
            background: #5b5bd6;
            transform: translateY(-1px);
        }
        
        .btn-secondary {
            background: #f2f1ee;
            color: #6b7280;
            border: 1px solid #e6e3dc;
        }
        
        .btn-secondary:hover {
            background: #edeae5;
        }
        
        .details {
            margin-top: 2rem;
            padding-top: 1.5rem;
            border-top: 1px solid #f3f4f6;
            font-size: 0.8rem;
            color: #9ca3af;
        }
        
        .brand {
            margin-top: 1.5rem;
            font-size: 0.75rem;
            font-weight: 500;
            color: #6b7280;
            letter-spacing: 0.1em;
        }
        
        @media (max-width: 480px) {
            .container { padding: 2rem 1.5rem; margin: 1rem; }
            .actions { flex-direction: column; gap: 0.5rem; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">⚠</div>
        <h1>Authentication Failed</h1>
        <p class="error-message">{{.Message}}</p>
        
        <div class="error-code">
            Error Code: {{.Code}} • Attempt {{.Attempts}}
        </div>
        
        <div class="actions">
            <a href="/" class="btn btn-primary">Try Again</a>
            <a href="{{.LogoutPath}}" class="btn btn-secondary">Sign Out</a>
        </div>
        
        <div class="details">
            If this problem persists, please contact your administrator.
        </div>
        
        <div class="brand">Oauthep</div>
    </div>
</body>
</html>
`
)

func (f *HttpFilter) generateErrorPageHTML(code int, attempts int) string {

	tmpl := template.Must(template.New("error").Parse(ErrorPageTemplate))

	data := struct {
		Message    string
		Code       int
		Attempts   int
		LogoutPath string
	}{
		Message:    ErrorCodeMessages[code],
		Code:       code,
		Attempts:   attempts,
		LogoutPath: f.config.LogoutPath,
	}

	var buf bytes.Buffer
	_ = tmpl.Execute(&buf, data)
	return buf.String()
}
