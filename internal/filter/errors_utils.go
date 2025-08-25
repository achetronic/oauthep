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
    <title>Authentication Error</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #333;
        }
        
        .container {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 16px;
            padding: 2.5rem;
            max-width: 480px;
            width: 90%;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            text-align: center;
        }
        
        .icon {
            width: 64px;
            height: 64px;
            margin: 0 auto 1.5rem;
            background: #ff6b6b;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 28px;
            color: white;
        }
        
        h1 {
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
            color: #2d3748;
        }
        
        .error-message {
            color: #718096;
            margin-bottom: 1.5rem;
            line-height: 1.6;
        }
        
        .error-code {
            background: #f7fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 0.75rem;
            margin: 1rem 0;
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 0.875rem;
            color: #4a5568;
        }
        
        .actions {
            display: flex;
            gap: 1rem;
            margin-top: 2rem;
        }
        
        .btn {
            flex: 1;
            padding: 0.875rem 1.5rem;
            border: none;
            border-radius: 8px;
            font-weight: 500;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            transition: all 0.2s ease;
            font-size: 0.95rem;
        }
        
        .btn-primary {
            background: #4299e1;
            color: white;
        }
        
        .btn-primary:hover {
            background: #3182ce;
            transform: translateY(-1px);
        }
        
        .btn-secondary {
            background: #edf2f7;
            color: #4a5568;
        }
        
        .btn-secondary:hover {
            background: #e2e8f0;
        }
        
        .details {
            margin-top: 1.5rem;
            padding-top: 1.5rem;
            border-top: 1px solid #e2e8f0;
            font-size: 0.875rem;
            color: #718096;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">⚠</div>
        <h1>Authentication Required</h1>
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
