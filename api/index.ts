import express from 'express';
import cors from 'cors';
import https from 'https';

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

const IANA_RDAP_BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';

async function getRDAPServer(domain) {
  const tld = domain.split('.').pop();

  const bootstrapData = await new Promise((resolve, reject) => {
    https.get(IANA_RDAP_BOOTSTRAP_URL, (response) => {
      let data = '';

      response.on('data', (chunk) => {
        data += chunk;
      });

      response.on('end', () => {
        resolve(JSON.parse(data));
      });

      response.on('error', (err) => {
        reject(err);
      });
    });
  });

  for (const entry of bootstrapData.services) {
    if (entry[0].includes(tld)) {
      return entry[1][0];
    }
  }

  throw new Error(`No RDAP server found for TLD: ${tld}`);
}

async function performRDAPLookup(domain, retries = 3) {
  try {
    const rdapServer = await getRDAPServer(domain);
    const rdapResponse = await new Promise((resolve, reject) => {
      https.get(`${rdapServer}/domain/${domain}`, (response) => {
        let data = '';

        response.on('data', (chunk) => {
          data += chunk;
        });

        response.on('end', () => {
          resolve(JSON.parse(data));
        });

        response.on('error', (err) => {
          reject(err);
        });
      });
    });
    return rdapResponse;
  } catch (error) {
    if (retries > 0) {
      console.log(`Retrying RDAP lookup for ${domain}. Attempts left: ${retries - 1}`);
      await new Promise(resolve => setTimeout(resolve, 1000)); // Wait 1 second before retrying
      return performRDAPLookup(domain, retries - 1);
    } else {
      console.error(`Error performing RDAP lookup for ${domain}:`, error);
      throw error;
    }
  }
}

app.get('/api/lookup', async (req, res) => {
  const domain = req.query.domain;
  if (!domain) {
    return res.status(400).json({ error: 'Domain parameter is required' });
  }

  try {
    const data = await performRDAPLookup(domain);
    res.status(200).json({ domain, rdap: data });
  } catch (error) {
    res.status(500).json({ error: 'Error performing RDAP lookup', details: error.message });
  }
});

if (require.main === module) {
  app.listen(port, () => {
    console.log(`Domain Lookup API running at http://localhost:${port}`);
  });
}

export default app;
