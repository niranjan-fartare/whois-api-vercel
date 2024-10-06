import express from 'express';
import whois from 'whois';
import { promisify } from 'util';
import cors from 'cors';

const app = express();
const port = process.env.PORT || 3000;

const corsOptions = {
  origin: [
    'http://localhost',
    'http://127.0.0.1:80',
    'https://hostingchecker.co',
    'https://www.hostingchecker.co'
  ],
  methods: ['GET'],
  allowedHeaders: ['Content-Type'],
};

app.use(cors(corsOptions));

const whoisLookup = promisify(whois.lookup);

const parseWhoisData = (rawData: string): Record<string, string> => {
  const parsedData: Record<string, string> = {};
  const lines = rawData.split('\n');

  for (const line of lines) {
    const colonIndex = line.indexOf(':');
    if (colonIndex !== -1) {
      const key = line.slice(0, colonIndex).trim();
      const value = line.slice(colonIndex + 1).trim();
      if (key && value) {
        parsedData[key] = value;
      }
    }
  }

  return parsedData;
};

const performWhoisLookup = async (domain: string, retries = 3): Promise<Record<string, string>> => {
  try {
    const rawData = await whoisLookup(domain);
    if (!rawData) {
      throw new Error('Empty WHOIS data');
    }
    return parseWhoisData(rawData);
  } catch (error) {
    if (retries > 0) {
      console.log(`Retrying WHOIS lookup for ${domain}. Attempts left: ${retries - 1}`);
      await new Promise(resolve => setTimeout(resolve, 1000)); // Wait 1 second before retrying
      return performWhoisLookup(domain, retries - 1);
    } else {
      console.error(`Error performing WHOIS lookup for ${domain}:`, error);
      throw error;
    }
  }
};

app.get('/api/whois', async (req, res) => {
  const domain = req.query.domain as string;
  if (!domain) {
    return res.status(400).json({ error: 'Domain parameter is required' });
  }

  try {
    const data = await performWhoisLookup(domain);
    res.status(200).json({ domain, whois: data });
  } catch (error) {
    res.status(500).json({ error: 'Error performing WHOIS lookup', details: error.message });
  }
});

if (require.main === module) {
  app.listen(port, () => {
    console.log(`WHOIS API running at http://localhost:${port}`);
  });
}

export default app;
