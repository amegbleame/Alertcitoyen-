// api/envoyer.js : guichet d'ecriture d'AlertCitoyen.
// Les citoyens n'ecrivent plus directement dans Firebase : tout passe ici, avec controles et limites.
// Variable a creer dans Vercel : FIREBASE_SERVICE_ACCOUNT (contenu du fichier JSON du compte de service).
const admin = require('firebase-admin');
const crypto = require('crypto');

const URL_BASE = process.env.FIREBASE_DATABASE_URL || 'https://alertcitoyen-daf62-default-rtdb.firebaseio.com';

// --- Reglages (modifiables) ---
const LIMITES = { incident: 8, message: 40, temoin: 6, coords: 12 }; // envois par adresse IP et par heure
const FENETRE_SEC = 3600;
const DELAI_EDITION_MS = 5 * 60 * 1000 + 15000; // modification d'un message : 5 minutes (+15 s de marge)
const DELAI_COORDS_MS = 10 * 60 * 1000;
const PHOTO_MAX = 3000000; // caracteres (photo en base64)
const CATEGORIES = ['terrorisme', 'vol', 'suspect', 'vandalisme', 'criminalite'];
const URGENCES = ['haute', 'moyenne', 'basse'];

const TEL = /^[+0-9 ()\-.]{6,25}$/;
const CODE = /^ALT-\d{4}-\d{4}$/;
const ID = /^[A-Za-z0-9_-]{8,40}$/;

function erreur(statut, code) { const e = new Error(code); e.statut = statut; e.code = code; return e; }
function repondre(res, statut, corps) { res.status(statut).json(corps); }
const texte = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
const nombre = (v) => (typeof v === 'number' && isFinite(v) ? v : null);
// Zone acceptee : Togo et ancien Togo britannique
function coordsOk(lat, lng) {
  return nombre(lat) !== null && nombre(lng) !== null && lat >= 5.5 && lat <= 11.5 && lng >= -1.0 && lng <= 2.0;
}

function init() {
  if (admin.apps.length) return;
  const brut = process.env.FIREBASE_SERVICE_ACCOUNT;
  if (!brut) throw new Error('FIREBASE_SERVICE_ACCOUNT manquant');
  let compte;
  try { compte = JSON.parse(brut); } catch (e) { throw new Error('FIREBASE_SERVICE_ACCOUNT invalide'); }
  if (compte.private_key) compte.private_key = compte.private_key.replace(/\\n/g, '\n');
  admin.initializeApp({ credential: admin.credential.cert(compte), databaseURL: URL_BASE });
}

function ipDe(req) {
  const h = req.headers || {};
  const v = h['x-vercel-forwarded-for'] || h['x-real-ip'] || h['x-forwarded-for'];
  if (v) return String(v).split(',')[0].trim();
  return (req.socket && req.socket.remoteAddress) || 'inconnue';
}

// 'autorite' si un jeton Firebase valide est fourni, 'citoyen' sinon ; jeton present mais invalide => erreur 401
async function roleAppelant(req) {
  const m = String((req.headers || {}).authorization || '').match(/^Bearer (.+)$/);
  if (!m) return 'citoyen';
  try { await admin.auth().verifyIdToken(m[1]); return 'autorite'; }
  catch (e) { throw erreur(401, 'jeton'); }
}

async function limiter(db, ip, type) {
  const fenetre = Math.floor(Date.now() / (FENETRE_SEC * 1000));
  const cle = crypto.createHash('sha256').update(ip + '|alertcitoyen').digest('hex').slice(0, 24);
  const res = await db.ref('limites/' + type + '/' + cle + '_' + fenetre).transaction((v) => (v || 0) + 1);
  if (res.snapshot.val() > LIMITES[type]) throw erreur(429, 'trop_de_demandes');
}

// ----- Signalement d'incident -----
async function creerIncident(db, c, ip, req) {
  const categorie = texte(c.categorie, 30);
  if (!CATEGORIES.includes(categorie)) throw erreur(400, 'categorie');
  const titre = texte(c.titre, 150);
  if (!titre) throw erreur(400, 'titre');
  const code = texte(c.codeAlerte, 20);
  if (!CODE.test(code)) throw erreur(400, 'code');
  const anonyme = c.anonyme !== false;
  let telephone = null;
  if (!anonyme) { const t = texte(c.telephone, 25); telephone = TEL.test(t) ? t : null; }
  let photo = null;
  if (c.photo) {
    if (typeof c.photo !== 'string' || !/^data:image\/(jpeg|png|webp|gif);base64,/.test(c.photo)) throw erreur(400, 'photo');
    if (c.photo.length > PHOTO_MAX) throw erreur(413, 'photo_trop_grande');
    photo = c.photo;
  }
  const bonnesCoords = coordsOk(c.lat, c.lng);
  const emp = (c.empreinte && typeof c.empreinte === 'object') ? c.empreinte : {};
  const appareil = texte(emp.appareil, 100);
  const incident = {
    categorie, titre,
    lieu: texte(c.lieu, 200),
    description: texte(c.description, 3000),
    urgence: URGENCES.includes(c.urgence) ? c.urgence : 'moyenne',
    timestamp: Date.now(),
    tsLocal: nombre(c.timestamp),
    anonyme, telephone,
    lat: bonnesCoords ? c.lat : null,
    lng: bonnesCoords ? c.lng : null,
    lieuIntrouvable: c.lieuIntrouvable === true ? true : null,
    valide: false, archive: false,
    photo, statut: 'nouveau', codeAlerte: code,
    empreinte: {
      ip: ip,                       // adresse vue par le serveur (non falsifiable par le telephone)
      appareil: appareil, userAgent: appareil,
      langue: texte(emp.langue, 20), ecran: texte(emp.ecran, 20), timezone: texte(emp.timezone, 60),
      heure: new Date().toISOString()
    }
  };
  const ref = db.ref('incidents').push();
  await ref.set(incident);
  return { id: ref.key };
}

// ----- Messages citoyen <-> police -----
async function creerMessage(db, c, role) {
  const code = texte(c.code, 20);
  if (!CODE.test(code)) throw erreur(400, 'code');
  const t = texte(c.texte, 1000);
  if (!t) throw erreur(400, 'texte');
  const expediteur = c.expediteur === 'police' ? 'police' : 'citoyen';
  if (expediteur === 'police' && role !== 'autorite') throw erreur(403, 'reserve_aux_autorites');
  const ref = db.ref('messages/' + code).push();
  await ref.set({ texte: t, expediteur, timestamp: Date.now() });
  return { id: ref.key };
}

async function modifierMessage(db, c, role) {
  const code = texte(c.code, 20);
  if (!CODE.test(code) || !ID.test(String(c.id || ''))) throw erreur(400, 'identifiant');
  const t = texte(c.texte, 1000);
  if (!t) throw erreur(400, 'texte');
  const ref = db.ref('messages/' + code + '/' + c.id);
  const snap = await ref.once('value');
  if (!snap.exists()) throw erreur(404, 'introuvable');
  const m = snap.val();
  const monRole = role === 'autorite' ? 'police' : 'citoyen';
  if (m.expediteur !== monRole) throw erreur(403, 'pas_votre_message');
  if (Date.now() - (m.timestamp || 0) > DELAI_EDITION_MS) throw erreur(403, 'delai_depasse');
  await ref.update({ texte: t, modifie: true });
  return {};
}

// ----- Signalement d'un temoin sur un avis de recherche -----
async function creerTemoin(db, c) {
  const avisId = String(c.avisId || '');
  if (!ID.test(avisId)) throw erreur(400, 'avis');
  const lieu = texte(c.lieu, 200);
  if (!lieu) throw erreur(400, 'lieu');
  const tel = texte(c.telephone, 25);
  if (!TEL.test(tel)) throw erreur(400, 'telephone');
  const existe = await db.ref('avis_recherche/' + avisId + '/nom').once('value');
  if (!existe.exists()) throw erreur(404, 'avis_introuvable');
  const bonnesCoords = coordsOk(c.lat, c.lng);
  const ref = db.ref('avis_recherche/' + avisId + '/signalements').push();
  await ref.set({
    lieu, quand: texte(c.quand, 120) || 'Non precise', telephone: tel,
    timestamp: Date.now(), tsLocal: nombre(c.timestamp),
    lat: bonnesCoords ? c.lat : null, lng: bonnesCoords ? c.lng : null
  });
  return { id: ref.key };
}

async function majCoordsTemoin(db, c) {
  const avisId = String(c.avisId || ''), sigId = String(c.sigId || '');
  if (!ID.test(avisId) || !ID.test(sigId)) throw erreur(400, 'identifiant');
  if (!coordsOk(c.lat, c.lng)) throw erreur(400, 'coordonnees');
  const ref = db.ref('avis_recherche/' + avisId + '/signalements/' + sigId);
  const snap = await ref.once('value');
  if (!snap.exists()) throw erreur(404, 'introuvable');
  if (Date.now() - (snap.val().timestamp || 0) > DELAI_COORDS_MS) throw erreur(403, 'delai_depasse');
  await ref.update({ lat: c.lat, lng: c.lng });
  return {};
}

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method === 'GET') {
    // Controle de configuration (aucun secret affiche)
    if (req.query && req.query.diagnostic) {
      let compte = !!process.env.FIREBASE_SERVICE_ACCOUNT, pret = false;
      try { init(); pret = true; } catch (e) { pret = false; }
      return repondre(res, 200, { ok: pret, compte_present: compte, connexion_prete: pret });
    }
    return repondre(res, 405, { ok: false, erreur: 'methode' });
  }
  if (req.method !== 'POST') return repondre(res, 405, { ok: false, erreur: 'methode' });

  // Uniquement depuis le site lui-meme
  const origine = req.headers && req.headers.origin;
  if (origine) {
    try { if (new URL(origine).host !== req.headers.host) return repondre(res, 403, { ok: false, erreur: 'origine' }); }
    catch (e) { return repondre(res, 403, { ok: false, erreur: 'origine' }); }
  }
  if (!String((req.headers || {})['content-type'] || '').includes('application/json')) return repondre(res, 415, { ok: false, erreur: 'format' });
  const c = req.body;
  if (!c || typeof c !== 'object') return repondre(res, 400, { ok: false, erreur: 'corps' });

  try {
    init();
    const db = admin.database();
    const role = await roleAppelant(req);
    const action = c.action;
    const limite = { incident: 'incident', message: 'message', message_modifier: 'message', temoin: 'temoin', temoin_coords: 'coords' }[action];
    if (!limite) throw erreur(400, 'action');
    if (role !== 'autorite') await limiter(db, ipDe(req), limite);
    let resultat;
    if (action === 'incident') resultat = await creerIncident(db, c, ipDe(req), req);
    else if (action === 'message') resultat = await creerMessage(db, c, role);
    else if (action === 'message_modifier') resultat = await modifierMessage(db, c, role);
    else if (action === 'temoin') resultat = await creerTemoin(db, c);
    else resultat = await majCoordsTemoin(db, c);
    return repondre(res, 200, Object.assign({ ok: true }, resultat));
  } catch (e) {
    if (e && e.statut) return repondre(res, e.statut, { ok: false, erreur: e.code });
    console.error('envoyer.js :', e && e.message);
    return repondre(res, 500, { ok: false, erreur: 'serveur' });
  }
};
