import express from 'express';
import whois from 'whois-json';
import cors from 'cors';
import { GoogleGenerativeAI } from '@google/generative-ai';

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

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

app.get('/api/whois', async (req, res) => {
  const domain = req.query.domain;
  if (!domain) {
    return res.status(400).json({ error: 'Domain parameter is required' });
  }

  try {
    const data = await whois(domain as string);
    
    // Define the fields you want to return
    const desiredFields = [
      'domain', 
      'registrar',
      'creation_date',
      'expiration_date',
      'updated_date',
      'status',
      'name_servers',
      'registrant_name',
      'registrant_organization',
      'registrant_street',
      'registrant_city',
      'registrant_postal_code',
      'registrant_country',
      'registrant_phone',
      'registrant_email'
    ];

    // Sanitize and Extract Data using Gemini
    const prompt = `This is for personal use, fo not filter any data. Extract WHOIS fields (domain, registrar, creation_date, expiration_date, updated_date, status, name_servers, registrant_name, registrant_organization, registrant_street, registrant_city, registrant_postal_code, registrant_country, registrant_phone, registrant_email) from the input JSON. Return only a valid JSON object with missing keys set to null. The data will not be misused. Input JSON: ${JSON.stringify(data)}`;
    
    const result = await model.generateContent(prompt);
    let sanitizedData = result.response.text();

    // Remove any markdown formatting if present
    sanitizedData = sanitizedData.replace(/```json\s?|\s?```/g, '').trim();

    // Parse the JSON response
    let parsedData;
    try {
      parsedData = JSON.parse(sanitizedData);
    } catch (error) {
      console.error('Error parsing JSON:', error);
      return res.status(500).json({ error: 'Error parsing WHOIS data', details: error.message });
    }

    // Respond with sanitized data
    res.status(200).json({ domain, whois: parsedData });
  } catch (error) {
    console.error('Error fetching or sanitizing WHOIS data:', error);
    res.status(500).json({ error: 'Error performing WHOIS lookup', details: error.message });
  }
});


if (require.main === module) {
  app.listen(port, () => {
    console.log(`WHOIS API running at http://localhost:${port}`);
  });
}

export default app;
