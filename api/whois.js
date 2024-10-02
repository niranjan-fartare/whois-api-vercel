const whois = require('whois-json');

module.exports = async (req, res) => {
  const { query: { domain } } = req;

  if (!domain) {
    return res.status(400).json({ error: 'Domain parameter is required' });
  }

  try {
    const data = await whois(domain);
    return res.status(200).json({ domain, whois: data });
  } catch (error) {
    return res.status(500).json({ error: 'Error performing WHOIS lookup' });
  }
};
