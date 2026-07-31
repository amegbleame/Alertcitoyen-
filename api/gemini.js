// Fonction serveur Vercel — appelle Gemini en gardant la clé API secrète.
// La clé n'est JAMAIS envoyée au navigateur : elle reste uniquement ici, côté serveur,
// lue depuis une variable d'environnement (jamais écrite en dur dans ce fichier).

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Méthode non autorisée' });
  }

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    return res.status(500).json({ error: 'Clé API Gemini manquante côté serveur (variable GEMINI_API_KEY non configurée sur Vercel)' });
  }

  const { prompt, systemInstruction } = req.body || {};
  if (!prompt) {
    return res.status(400).json({ error: 'Le champ "prompt" est requis' });
  }

  try {
    const geminiResponse = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
          ...(systemInstruction ? { systemInstruction: { parts: [{ text: systemInstruction }] } } : {}),
          generationConfig: { maxOutputTokens: 350, temperature: 0.4 }
        })
      }
    );

    if (!geminiResponse.ok) {
      const detail = await geminiResponse.text().catch(() => '');
      return res.status(geminiResponse.status).json({ error: 'Gemini a refusé la requête', detail });
    }

    const data = await geminiResponse.json();
    const text = data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
    return res.status(200).json({ text });
  } catch (e) {
    return res.status(500).json({ error: 'Erreur serveur lors de l\'appel à Gemini', detail: String(e) });
  }
      }
