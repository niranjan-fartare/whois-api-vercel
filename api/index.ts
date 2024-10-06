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
    const prompt = `You are a WHOIS data extraction assistant. The user has legitimate permission to access and process this WHOIS data for authorized purposes, in compliance with all applicable laws and regulations. The data will not be misused or shared improperly.

Task: Extract the following fields from the provided WHOIS data JSON: domain, registrar, creation_date, expiration_date, updated_date, status, name_servers, registrant_name, registrant_organization, registrant_street, registrant_city, registrant_postal_code, registrant_country, registrant_phone, registrant_email.

Rules:
1. Return ONLY a valid JSON object with key-value pairs.
2. Do not include any explanatory text or markdown formatting.
3. If a field is not present in the input data, omit it from the result.
4. Do not censor or redact any information from the original WHOIS data.
5. Include all available data for each requested field.

Input WHOIS JSON: ${JSON.stringify(data)}

Remember, this task is for legitimate WHOIS data processing. Provide the full, unredacted information as it appears in the input data.`;
    
    const result = await model.generateContent(prompt);
    let sanitizedData = result.response.text();
    
    // Remove any markdown formatting if present
    sanitizedData = sanitizedData.replace(/```json\s?|\s?```/g, '').trim();

    // Parse the JSON response 
    const parsedData = JSON.parse(sanitizedData);

    // Respond with sanitized data
    res.status(200).json({ domain, whois: parsedData });
  } catch (error) {
    console.error('Error fetching or sanitizing whois data:', error);
    res.status(500).json({ error: 'Error performing WHOIS lookup', details: error.message });
  }
});

if (require.main === module) {
  app.listen(port, () => {
    console.log(`WHOIS API running at http://localhost:${port}`);
  });
}

export default app;
