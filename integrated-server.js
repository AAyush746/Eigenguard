const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const morgan = require('morgan');
const cors = require('cors');

// Configuration
const PORT = process.env.PORT || 3000;
const FRONTEND_DIR = path.join(__dirname, 'frontend');
const DATA_DIR = path.join(__dirname, 'collected_data');
const LOG_FILE = path.join(DATA_DIR, 'request_log.json');

// Create Express app
const app = express();

// Ensure data directory exists
async function ensureDataDir() {
    try {
        await fs.mkdir(DATA_DIR, { recursive: true });
        console.log('Data directory ensured:', DATA_DIR);
    } catch (error) {
        console.error('Error creating data directory:', error);
    }
}

// Initialize log file if it doesn't exist
async function initializeLogFile() {
    try {
        await fs.access(LOG_FILE);
    } catch {
        await fs.writeFile(LOG_FILE, JSON.stringify([]));
        console.log('Log file initialized:', LOG_FILE);
    }
}

// Request logging middleware (for terminal output)
app.use(morgan('[:date[iso]] :remote-addr - :method :url :status :res[content-length] - :response-time ms'));

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Custom middleware to log detailed request data
app.use((req, res, next) => {
    const start = Date.now();
    const originalUrl = req.originalUrl || req.url;

    next();

    res.on('finish', async () => {
        const requestData = {
            timestamp: new Date().toISOString(),
            ip: req.ip || req.socket.remoteAddress,
            method: req.method,
            url: originalUrl,
            query: req.query,
            headers: req.headers,
            body: req.body && Object.keys(req.body).length ? req.body : null,
            userAgent: req.headers['user-agent'] || 'Unknown',
            status: res.statusCode,
            responseTime: Date.now() - start,
            responseSize: res.get('Content-Length') || 0
        };

        await saveRequestData(requestData);
    });
});

// API endpoints
app.get('/api/collected-data', async (req, res) => {
    console.log('Handling GET /api/collected-data');
    try {
        const data = JSON.parse(await fs.readFile(LOG_FILE));
        res.json(data);
    } catch (error) {
        console.error('Error reading collected data:', error);
        res.status(500).json({ error: 'Failed to read collected data' });
    }
});

app.post('/api/clear-data', async (req, res) => {
    console.log('Handling POST /api/clear-data');
    try {
        const data = JSON.parse(await fs.readFile(LOG_FILE));
        if (data.length > 0) {
            const archiveFile = path.join(DATA_DIR, `requests_${Date.now()}.json`);
            await fs.writeFile(archiveFile, JSON.stringify(data, null, 2));
        }

        await fs.writeFile(LOG_FILE, JSON.stringify([]));
        res.json({ success: true, message: 'Data cleared successfully' });
    } catch (error) {
        console.error('Error clearing data:', error);
        res.status(500).json({ error: 'Failed to clear data' });
    }
});

app.get('/api/stats', async (req, res) => {
    console.log('Handling GET /api/stats');
    try {
        const data = JSON.parse(await fs.readFile(LOG_FILE));

        const totalRequests = data.length;
        const methodCounts = {};
        const statusCounts = {};
        const ipCounts = {};

        data.forEach(item => {
            methodCounts[item.method] = (methodCounts[item.method] || 0) + 1;
            statusCounts[item.status] = (statusCounts[item.status] || 0) + 1;
            ipCounts[item.ip] = (ipCounts[item.ip] || 0) + 1;
        });

        res.json({
            totalRequests,
            methodCounts,
            statusCounts,
            ipCounts,
            lastRequest: data.length > 0 ? data[data.length - 1] : null
        });
    } catch (error) {
        console.error('Error generating stats:', error);
        res.status(500).json({ error: 'Failed to generate stats' });
    }
});

// Save request data to the dataset
async function saveRequestData(requestData) {
    try {
        const data = JSON.parse(await fs.readFile(LOG_FILE));
        data.push(requestData);
        await fs.writeFile(LOG_FILE, JSON.stringify(data, null, 2));

        if (data.length > 1000) {
            const archiveFile = path.join(DATA_DIR, `requests_${Date.now()}.json`);
            await fs.writeFile(archiveFile, JSON.stringify(data, null, 2));
            await fs.writeFile(LOG_FILE, JSON.stringify([]));
        }
    } catch (error) {
        console.error('Error saving request data:', error);
    }
}

// Serve static frontend files
app.use(express.static(FRONTEND_DIR));

// Serve index.html for non-API routes
app.get('/', (req, res) => {
    console.log('Handling GET /');
    res.sendFile(path.join(FRONTEND_DIR, 'index.html'), (err) => {
        if (err) {
            console.error('Error serving index.html:', err);
            res.status(500).send('Server error');
        }
    });
});

// Start the server
async function startServer() {
    await ensureDataDir();
    await initializeLogFile();
    app.listen(PORT, () => {
        console.log(`Server running at http://localhost:${PORT}`);
        console.log(`Frontend files served from: ${FRONTEND_DIR}`);
        console.log(`Request data is being saved to: ${LOG_FILE}`);
        console.log('Press Ctrl+C to stop the server');
    });
}

startServer();