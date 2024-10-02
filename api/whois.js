const express = require('express');
const whois = require('whois-json');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());

app.get('/api/whois', async (req, res) => {
  const domain = req.query.domain;

  if (!domain) {
    return res.status(400).json({ error: 'Domain parameter is required' });
  }

  try {
    const data = await whois(domain);
    res.status(200).json({ domain, whois: data });
  } catch (error) {
    res.status(500).json({ error: 'Error performing WHOIS lookup' });
  }
});

// Start the server (for local testing)
if (require.main === module) {
  app.listen(port, () => {
    console.log(`WHOIS API running at http://localhost:${port}`);
  });
}

// Export the app for Vercel to use
module.exports = app;
