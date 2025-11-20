import React from 'react'
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Link,
  useLocation,
} from 'react-router-dom'

// Note: The Python backend (app.py) must be running at port 5000
// for the logging to function correctly.
const LOG_ENDPOINT = "/log"   // Relative path works when served by Flask at /log

/**
 * Sends a log event to the backend endpoint.
 * @param {object} event - The specific event data (e.g., login attempt details).
 */
async function sendLog(event) {
  try {
    const payload = {
      ...event,
      ts: new Date().toISOString(),
      ua: navigator.userAgent,
      ref: document.referrer || null,
      bot: navigator.webdriver || false,
    }
    // Use the relative path. Flask's CORS configuration handles the connection.
    await fetch(LOG_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      mode: 'no-cors', // Still use no-cors to accommodate potential external testing
    })
  } catch (e) { 
    console.warn('Honeypot log failed:', e) 
  }
}

/**
 * Custom hook to log page views on route changes.
 */
function usePageLog() {
  const location = useLocation()
  React.useEffect(() => {
    const params = new URLSearchParams(location.search)
    sendLog({
      type: 'pageview',
      page: location.pathname + location.search,
      query: Object.fromEntries(params),
    })
  }, [location])
}

/**
 * Reusable component for various fake login forms (Lures).
 */
function Generic976Login({ title, fields, logType, error = 'Invalid credentials' }) {
  const [loading, setLoading] = React.useState(false)
  usePageLog()

  const onSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    const fd = new FormData(e.target)
    const data = Object.fromEntries(fd)
    
    // Log the attempted credentials
    await sendLog({ type: logType, data })
    
    // Added random delay to simulate a real server check
    await new Promise(r => setTimeout(r, 1000 + Math.random() * 1000)) 
    
    setLoading(false)
    // Using console.error/alert as a simple response to the intruder
    console.error(error)
    alert(error) 
  }

  return (
    <div className="page small login-page">
      <h2>{title}</h2>
      <form onSubmit={onSubmit}>
        {fields.map(f => (
          <label key={f.name}>
            {f.label}
            <input name={f.name} type={f.type || 'text'} required />
          </label>
        ))}
        <div className="form-options">
          <label><input type="checkbox" name="remember" /> Remember Me</label>
        </div>
        <button type="submit" disabled={loading}>
          {loading ? 'Processing...' : 'Submit'}
        </button>
      </form>
      <p className="meta-links">
        <a href="#">Forgot Password?</a>
      </p>
    </div>
  )
}

// --- Page Components ---

function Home() {
  usePageLog()
  return (
    <div className="page">
      <header className="site-header">
        <h1>Acme Web Portal: Internal Access</h1>
        <nav>
          <Link to="/">Home</Link> | <Link to="/login">Login</Link> | <Link to="/admin">Admin</Link> | <Link to="/support.html">Support</Link> | <a href="#">Documents</a>
        </nav>
      </header>
      <main className="content">
        <h2>Welcome to the Legacy Portal</h2>
        <p>This application is for internal use only. All access is logged and audited.</p>
        
        <h3>System Status</h3>
        <ul>
          <li>DB Connection: <span style={{color:'green', fontWeight:'bold'}}>OK</span></li>
          <li>Last Backup: Yesterday @ 02:00 UTC</li>
          <li>Pending Migrations: <span style={{color:'red', fontWeight:'bold'}}>3</span> (Scheduled for Q3)</li>
        </ul>

        <h3>Quick Links (Potential Lures)</h3>
        <ul>
          <li><Link to="/wp-login.php">WordPress CMS Login</Link></li>
          <li><Link to="/phpmyadmin.php">phpMyAdmin Database Console</Link></li>
          <li><Link to="/.env">Deployment Environment Variables</Link></li>
        </ul>
      </main>
      <footer>
        <small>Version 1.4.1 (Build 976). Licensed to Acme Corp. Contact SysAdmin for support.</small>
      </footer>
    </div>
  )
}

function Login()       { return <Generic976Login title="Portal Login"           logType="login-attempt" fields={[{label:'Username',name:'username'},{label:'Password',name:'password',type:'password'}]} /> }
function WPLogin()     { return <Generic976Login title="WordPress Login" logType="wp-login"      fields={[{label:'Username or Email',name:'log'},{label:'Password',name:'pwd',type:'password'}]} error="ERROR: Invalid password" /> }
function PhpMyAdmin()  { return <Generic976Login title="phpMyAdmin"      logType="pma-login"     fields={[{label:'Username',name:'pma_username'},{label:'Password',name:'pma_password',type:'password'}]} error="Cannot log in to MySQL" /> }

function Admin() {
  usePageLog()
  return (
    <div className="page">
      <h2>Administrator Dashboard</h2>
      <p>Welcome, Administrator. Please select an action.</p>
      <h3>File Directory (Read-Only)</h3>
      <pre className="log-area">
Type   Last Write Time     Length   Name
----   ---------------     ------   ----
d----- 10/25/2025 09:12 AM         bin
d----- 10/25/2025 09:12 AM         config
-a---- 10/25/2025 09:12 AM     4096 logs/access.log
-a---- 10/25/2025 09:12 AM       42 config/database.ini  &lt;-- Check this file
-a---- 10/25/2025 09:12 AM       78 .htaccess
      </pre>
      <p>Unauthorized access will trigger an immediate alert to SysAdmin team.</p>
    </div>
  )
}

function DotEnv() {
  usePageLog()
  return (
    <div className="page small">
      <h2>Contents of .env</h2>
      <p>Warning: This file should not be publicly accessible (403 expected).</p>
      <pre className="raw-file">
# Production environment variables
APP_NAME="Acme Portal v1.4.1"
APP_ENV=production
# Critical Database Credentials - DO NOT SHARE
DB_HOST=192.168.1.10
DB_USER=acme_admin
DB_PASS=SuperSecret123!
# API Keys
STRIPE_KEY=sk_test_1337...
JWT_SECRET=9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c
MAINTENANCE_MODE=false
      </pre>
    </div>
  )
}

function NotFound() {
  const loc = useLocation()
  React.useEffect(() => sendLog({ type: '404', page: loc.pathname }), [loc])
  return <div className="page"><h2>404 Not Found</h2><p>The requested URL **{loc.pathname}** was not found on this server.</p><p>Error reference: Acme/404/2025-11</p></div>
}

export default function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/login" element={<Login />} />
        <Route path="/admin" element={<Admin />} />
        <Route path="/wp-login.php" element={<WPLogin />} />
        <Route path="/phpmyadmin.php" element={<PhpMyAdmin />} />
        <Route path="/.env" element={<DotEnv />} />
        <Route path="*" element={<NotFound />} />
      </Routes>
      <style dangerouslySetInnerHTML={{ __html: CSS_STYLES }} />
    </Router>
  )
}

const CSS_STYLES = `
  body{margin:0;font-family:Tahoma, Geneva, sans-serif;background:#e9e9e9;color:#333}
  a{color:#003087;text-decoration:none}
  a:hover{text-decoration:underline}
  .page{max-width:960px;margin:20px auto;padding:25px;background:#fff;min-height:90vh;border:1px solid #ccc;box-shadow:2px 2px 5px rgba(0,0,0,0.2);border-radius: 4px;}
  .small{max-width:480px;margin-top:50px}
  .site-header{background:#003087;color:#fff;padding:15px 25px;margin: -25px -25px 20px -25px; border-bottom: 5px solid #ffcc00;}
  .site-header h1{margin:0;font-size:24px;}
  .site-header nav a{color:#fff;margin-right:15px;font-size:14px;text-transform:uppercase;font-weight: bold;}
  h2{border-bottom:2px solid #ccc;padding-bottom:10px;margin-top:20px;color:#003087}
  h3{color: #666; margin-top: 30px; font-size: 1.1em;}
  form label{display:block;margin:15px 0;font-weight:bold;}
  input[type="text"], input[type="password"]{width:100%;padding:10px;font-size:14px;border:1px solid #999;border-radius:0;box-sizing:border-box}
  .form-options{font-weight:normal; font-size: 13px; margin: -10px 0 20px 0;}
  .form-options input[type="checkbox"]{width:auto;}
  button{padding:10px 20px;background:#5cb85c;color:#fff;border:1px solid #3d8b3d;border-radius:4px;cursor:pointer;font-size:16px;text-transform:uppercase;font-weight:bold;}
  button:disabled{opacity:0.6; cursor: not-allowed;}
  .meta-links{font-size:13px; text-align: right; border-top: 1px dotted #ccc; padding-top: 10px;}
  pre{background:#222;color:#f00;padding:15px;overflow-x:auto;font-family:'Courier New', monospace;font-size:12px;border:1px solid #444;border-radius:0;}
  .raw-file{color:#ffcc00;} /* Yellow for exposed env vars */
  .log-area{color:#0f0; white-space: pre;} /* Green for fake admin logs, ensure whitespace for columnar view */
  footer{text-align:center;padding:15px;color:#666;font-size:11px;border-top:1px dotted #ccc;margin-top:30px}
`;