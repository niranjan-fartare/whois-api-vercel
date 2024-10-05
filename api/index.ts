import express from 'express';
import whois from 'whois-json';
import cors from 'cors';

const app = express();
const port = process.env.PORT || 3000;

const corsOptions = {
  origin: [
    'http://localhost',
    'http://127.0.0.1:80'
    'https://hostingchecker.co',
    'https://www.hostingchecker.co'
  ],
  methods: ['GET'],
  allowedHeaders: ['Content-Type'],
};

app.use(cors(corsOptions));

app.get('/api/whois', async (req, res) => {
  const domain = req.query.domain;

  if (!domain) {
    return res.status(400).json({ error: 'Domain parameter is required' });
  }

  try {
    const data = await whois(domain as string);
    res.status(200).json({ domain, whois: data });
  } catch (error) {
    res.status(500).json({ error: 'Error performing WHOIS lookup' });
  }
});

if (require.main === module) {
  app.listen(port, () => {
    console.log(`WHOIS API running at http://localhost:${port}`);
  });
}
export default app;
