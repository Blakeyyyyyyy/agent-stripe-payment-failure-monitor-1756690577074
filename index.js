const express = require('express');
const nodemailer = require('nodemailer');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const crypto = require('crypto');

const app = express();
app.use(express.raw({ type: 'application/json' }));
app.use(express.json());

// In-memory logs for monitoring
let logs = [];
function addLog(level, message, data = null) {
    const logEntry = {
        timestamp: new Date().toISOString(),
        level,
        message,
        data: data ? JSON.stringify(data, null, 2) : null
    };
    logs.push(logEntry);
    // Keep only last 100 logs
    if (logs.length > 100) logs.shift();
    console.log(`[${level.toUpperCase()}] ${message}`, data || '');
}

// Gmail transporter setup
const transporter = nodemailer.createTransporter({
    service: 'gmail',
    auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_APP_PASSWORD
    }
});

// Verify webhook signature
function verifySignature(payload, signature, secret) {
    try {
        const elements = signature.split(',');
        const signatureHash = elements.find(el => el.startsWith('v1=')).split('v1=')[1];
        const timestamp = elements.find(el => el.startsWith('t=')).split('t=')[1];
        
        const payloadString = timestamp + '.' + payload;
        const expectedSignature = crypto.createHmac('sha256', secret).update(payloadString, 'utf8').digest('hex');
        
        return crypto.timingSafeEqual(Buffer.from(expectedSignature), Buffer.from(signatureHash));
    } catch (error) {
        addLog('error', 'Signature verification failed', error);
        return false;
    }
}

// Format payment failure email
function formatFailureEmail(event) {
    const eventType = event.type;
    const data = event.data.object;
    
    let subject = '';
    let details = '';
    
    if (eventType === 'charge.failed') {
        subject = `🚨 Stripe Payment Failed - ${data.amount ? '$' + (data.amount / 100).toFixed(2) : 'Amount Unknown'}`;
        details = `
<h2>Charge Failed</h2>
<p><strong>Charge ID:</strong> ${data.id}</p>
<p><strong>Amount:</strong> $${data.amount ? (data.amount / 100).toFixed(2) : 'Unknown'} ${data.currency ? data.currency.toUpperCase() : ''}</p>
<p><strong>Customer:</strong> ${data.customer || 'Unknown'}</p>
<p><strong>Customer Email:</strong> ${data.billing_details?.email || data.receipt_email || 'Not provided'}</p>
<p><strong>Failure Code:</strong> ${data.failure_code || 'Not specified'}</p>
<p><strong>Failure Message:</strong> ${data.failure_message || 'No message provided'}</p>
<p><strong>Payment Method:</strong> ${data.payment_method_details?.type || 'Unknown'}</p>
${data.payment_method_details?.card ? `
<p><strong>Card Details:</strong> **** **** **** ${data.payment_method_details.card.last4} (${data.payment_method_details.card.brand.toUpperCase()})</p>
<p><strong>Card Country:</strong> ${data.payment_method_details.card.country || 'Unknown'}</p>
` : ''}
<p><strong>Created:</strong> ${new Date(data.created * 1000).toLocaleString()}</p>
<p><strong>Description:</strong> ${data.description || 'No description'}</p>
${data.metadata && Object.keys(data.metadata).length > 0 ? `
<h3>Metadata:</h3>
<ul>
${Object.entries(data.metadata).map(([key, value]) => `<li><strong>${key}:</strong> ${value}</li>`).join('')}
</ul>
` : ''}
        `;
    } 
    else if (eventType === 'payment_intent.payment_failed') {
        subject = `🚨 Stripe Payment Intent Failed - ${data.amount ? '$' + (data.amount / 100).toFixed(2) : 'Amount Unknown'}`;
        details = `
<h2>Payment Intent Failed</h2>
<p><strong>Payment Intent ID:</strong> ${data.id}</p>
<p><strong>Amount:</strong> $${data.amount ? (data.amount / 100).toFixed(2) : 'Unknown'} ${data.currency ? data.currency.toUpperCase() : ''}</p>
<p><strong>Customer:</strong> ${data.customer || 'Unknown'}</p>
<p><strong>Status:</strong> ${data.status}</p>
<p><strong>Last Payment Error:</strong> ${data.last_payment_error?.message || 'No error message'}</p>
<p><strong>Payment Method:</strong> ${data.payment_method || 'Unknown'}</p>
<p><strong>Created:</strong> ${new Date(data.created * 1000).toLocaleString()}</p>
<p><strong>Description:</strong> ${data.description || 'No description'}</p>
${data.metadata && Object.keys(data.metadata).length > 0 ? `
<h3>Metadata:</h3>
<ul>
${Object.entries(data.metadata).map(([key, value]) => `<li><strong>${key}:</strong> ${value}</li>`).join('')}
</ul>
` : ''}
        `;
    }
    else if (eventType === 'invoice.payment_failed') {
        subject = `🚨 Stripe Invoice Payment Failed - ${data.amount_due ? '$' + (data.amount_due / 100).toFixed(2) : 'Amount Unknown'}`;
        details = `
<h2>Invoice Payment Failed</h2>
<p><strong>Invoice ID:</strong> ${data.id}</p>
<p><strong>Invoice Number:</strong> ${data.number || 'Not assigned'}</p>
<p><strong>Amount Due:</strong> $${data.amount_due ? (data.amount_due / 100).toFixed(2) : 'Unknown'} ${data.currency ? data.currency.toUpperCase() : ''}</p>
<p><strong>Customer:</strong> ${data.customer || 'Unknown'}</p>
<p><strong>Customer Email:</strong> ${data.customer_email || 'Not provided'}</p>
<p><strong>Status:</strong> ${data.status}</p>
<p><strong>Attempt Count:</strong> ${data.attempt_count || 0}</p>
<p><strong>Due Date:</strong> ${data.due_date ? new Date(data.due_date * 1000).toLocaleDateString() : 'No due date'}</p>
<p><strong>Created:</strong> ${new Date(data.created * 1000).toLocaleString()}</p>
<p><strong>Description:</strong> ${data.description || 'No description'}</p>
${data.metadata && Object.keys(data.metadata).length > 0 ? `
<h3>Metadata:</h3>
<ul>
${Object.entries(data.metadata).map(([key, value]) => `<li><strong>${key}:</strong> ${value}</li>`).join('')}
</ul>
` : ''}
        `;
    }

    return {
        subject,
        html: `
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        h2 { color: #d32f2f; }
        h3 { color: #666; }
        p { margin: 8px 0; }
        ul { margin: 10px 0; padding-left: 20px; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    ${details}
    
    <div class="footer">
        <p><strong>Event Details:</strong></p>
        <p>Event ID: ${event.id}</p>
        <p>Event Type: ${event.type}</p>
        <p>Event Time: ${new Date(event.created * 1000).toLocaleString()}</p>
        <p>This alert was generated by your Stripe Payment Failure Monitor.</p>
    </div>
</body>
</html>
        `
    };
}

// Send email notification
async function sendFailureNotification(event) {
    try {
        const emailContent = formatFailureEmail(event);
        
        const mailOptions = {
            from: process.env.GMAIL_USER,
            to: 'balkeecom02@gmail.com',
            subject: emailContent.subject,
            html: emailContent.html
        };

        const result = await transporter.sendMail(mailOptions);
        addLog('info', `Email notification sent successfully`, { 
            messageId: result.messageId,
            eventType: event.type,
            eventId: event.id 
        });
        return result;
    } catch (error) {
        addLog('error', 'Failed to send email notification', error);
        throw error;
    }
}

// Routes
app.get('/', (req, res) => {
    res.json({
        name: 'Stripe Payment Failure Monitor',
        status: 'running',
        description: 'Monitors Stripe for failed payments and sends email notifications',
        endpoints: {
            'GET /': 'This status page',
            'GET /health': 'Health check',
            'GET /logs': 'View recent logs',
            'POST /test': 'Test email notification',
            'POST /webhook': 'Stripe webhook endpoint'
        },
        notificationEmail: 'balkeecom02@gmail.com',
        monitoredEvents: [
            'charge.failed',
            'payment_intent.payment_failed', 
            'invoice.payment_failed'
        ]
    });
});

app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

app.get('/logs', (req, res) => {
    res.json({
        logs: logs.slice(-50), // Last 50 logs
        total: logs.length
    });
});

app.post('/test', async (req, res) => {
    try {
        addLog('info', 'Manual test triggered');
        
        // Test with sample payment failure event
        const testEvent = {
            id: 'evt_test_webhook',
            type: 'charge.failed',
            created: Math.floor(Date.now() / 1000),
            data: {
                object: {
                    id: 'ch_test_failed',
                    amount: 2500,
                    currency: 'usd',
                    customer: 'cus_test_customer',
                    failure_code: 'card_declined',
                    failure_message: 'Your card was declined.',
                    billing_details: {
                        email: 'test@example.com'
                    },
                    payment_method_details: {
                        type: 'card',
                        card: {
                            last4: '0002',
                            brand: 'visa',
                            country: 'US'
                        }
                    },
                    created: Math.floor(Date.now() / 1000),
                    description: 'Test payment failure',
                    metadata: {
                        test: 'true'
                    }
                }
            }
        };

        await sendFailureNotification(testEvent);
        
        res.json({
            success: true,
            message: 'Test notification sent successfully to balkeecom02@gmail.com',
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        addLog('error', 'Test failed', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

app.post('/webhook', async (req, res) => {
    const signature = req.headers['stripe-signature'];
    const payload = req.body;
    
    let event;
    
    try {
        // Verify webhook signature if endpoint secret is available
        if (process.env.STRIPE_WEBHOOK_SECRET) {
            if (!verifySignature(payload, signature, process.env.STRIPE_WEBHOOK_SECRET)) {
                addLog('error', 'Invalid webhook signature');
                return res.status(400).send('Invalid signature');
            }
        }
        
        event = JSON.parse(payload.toString());
        addLog('info', `Received Stripe webhook: ${event.type}`, { eventId: event.id });
        
        // Handle payment failure events
        if (['charge.failed', 'payment_intent.payment_failed', 'invoice.payment_failed'].includes(event.type)) {
            addLog('info', `Processing payment failure: ${event.type}`, { 
                eventId: event.id,
                objectId: event.data.object.id 
            });
            
            try {
                await sendFailureNotification(event);
                addLog('info', `Payment failure notification sent successfully`, { eventType: event.type });
            } catch (emailError) {
                addLog('error', `Failed to send notification for ${event.type}`, emailError);
                // Don't return error to Stripe - we want to acknowledge receipt
            }
        } else {
            addLog('info', `Ignoring non-failure event: ${event.type}`);
        }
        
        res.json({ received: true });
        
    } catch (error) {
        addLog('error', 'Webhook processing failed', error);
        res.status(400).send(`Webhook Error: ${error.message}`);
    }
});

// Error handling middleware
app.use((error, req, res, next) => {
    addLog('error', 'Unhandled error', error);
    res.status(500).json({
        error: 'Internal server error',
        message: error.message
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    addLog('info', `Stripe Payment Failure Monitor started on port ${PORT}`);
});