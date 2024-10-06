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
    const sanitizedData = await model.generateContent(`Extract the following fields from the provided JSON: ${desiredFields.join(', ')}. JSON: ${JSON.stringify(data)}`);

    // Respond with sanitized data
    res.status(200).json({ domain, whois: sanitizedData.response.text() }); 
  } catch (error) {
    console.error('Error fetching or sanitizing whois data:', error);
    res.status(500).json({ error: 'Error performing WHOIS lookup' });
  }
});

if (require.main === module) {
  app.listen(port, () => {
    console.log(`WHOIS API running at http://localhost:${port}`);
  });
}
export default app;
