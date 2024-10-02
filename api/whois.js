// api/whois.js
const express = require('express');
const whois = require('whois');

const app = express();

function formatDate(dateString) {
  if (!dateString) return '';
  const date = new Date(dateString);
  if (isNaN(date.getTime())) return dateString; // Return original if invalid
  return date.toLocaleDateString('en-US', { 
    day: 'numeric', 
    month: 'long', 
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    timeZoneName: 'short'
  });
}

function extractRelevantInfo(rawData) {
  const lines = rawData.split('\n');
  const relevantData = {};

  lines.forEach(line => {
    const [key, ...valueParts] = line.split(':').map(part => part.trim());
    const value = valueParts.join(':');

    if (key && value) {
      const formattedKey = key.replace(/\s+/g, '');
      if (relevantData[formattedKey]) {
        if (Array.isArray(relevantData[formattedKey])) {
          relevantData[formattedKey].push(value);
        } else {
          relevantData[formattedKey] = [relevantData[formattedKey], value];
        }
      } else {
        relevantData[formattedKey] = value;
      }
    }
  });

  // Format dates
  ['CreationDate', 'UpdatedDate', 'RegistryExpiryDate'].forEach(dateField => {
    if (relevantData[dateField]) {
      relevantData[dateField] = formatDate(relevantData[dateField]);
    }
  });

  return relevantData;
}

app.use(express.json());

app.get('/api/whois', (req, res) => {
  const domain = req.query.domain;

  if (!domain) {
    return res.status(400).json({ error: 'Domain parameter is required' });
  }

  whois.lookup(domain, (err, data) => {
    if (err) {
      return res.status(500).json({ error: 'Error performing WHOIS lookup' });
    }

    const filteredData = extractRelevantInfo(data);
    res.status(200).json({ domain, whois: filteredData });
  });
});

module.exports = app;
