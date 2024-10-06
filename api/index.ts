import express from 'express';
import whoisJson from 'whois-json';
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

const performWhoisJsonLookup = async (domain: string): Promise<any> => {
  try {
    const data = await whoisJson(domain);
    if (!data || Object.keys(data).length === 0) {
      throw new Error('Empty WHOIS data from whois-json');
    }
    return data;
  } catch (error) {
    console.error('Error in whois-json lookup:', error);
    throw error;
  }
};

const performWhoisLookup = async (domain: string): Promise<any> => {
  try {
    const data = await whoisLookup(domain);
    if (!data) {
      throw new Error('Empty WHOIS data from whois');
    }
    // Parse the raw WHOIS data into a structured format
    // This is a simple example and may need to be adjusted based on the actual data format
    const parsedData = data.split('\n').reduce((acc, line) => {
      const [key, value] = line.split(':').map(s => s.trim());
      if (key && value) {
        acc[key] = value;
      }
      return acc;
    }, {});
    return parsedData;
  } catch (error) {
    console.error('Error in whois lookup:', error);
    throw error;
  }
};

const performWhoisLookupWithFallback = async (domain: string): Promise<any> => {
  try {
    // Try whois-json first
    return await performWhoisJsonLookup(domain);
  } catch (error) {
    console.log('Falling back to whois lookup');
    // If whois-json fails, fallback to whois
    return await performWhoisLookup(domain);
  }
};

app.get('/api/whois', async (req, res) => {
  const domain = req.query.domain as string;
  if (!domain) {
    return res.status(400).json({ error: 'Domain parameter is required' });
  }

  try {
    const data = await performWhoisLookupWithFallback(domain);
    res.status(200).json({ domain, whois: data });
  } catch (error) {
    console.error(`Error performing WHOIS lookup for ${domain}:`, error);
    res.status(500).json({ error: 'Error performing WHOIS lookup', details: error.message });
  }
});

if (require.main === module) {
  app.listen(port, () => {
    console.log(`WHOIS API running at http://localhost:${port}`);
  });
}

export default app;
