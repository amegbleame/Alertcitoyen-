// api/envoyer.js : guichet d'ecriture d'AlertCitoyen.
// Les citoyens n'ecrivent plus directement dans Firebase : tout passe ici, avec controles et limites.
// Variable a creer dans Vercel : FIREBASE_SERVICE_ACCOUNT (contenu du fichier JSON du compte de service).
const admin = require('firebase-admin');
const crypto = require('crypto');

const URL_BASE = process.env.FIREBASE_DATABASE_URL || 'https://alertcitoyen-daf62-default-rtdb.firebaseio.com';

const VERSION = '2026-10-26-comptes-individuels';

// --- Comptes autorises : un compte par personne, avec un role ---
//  admin : panel d'administration complet (SOS, signalements, alertes officielles, reponses de la police)
//  agent : peut seulement envoyer une demande de renfort
// Comptes "fondateurs" (toujours valides, meme si la base est inaccessible) :
const ADMINS_FONDATEURS = ['mhTvE0AetTSvmcUsdeuhFx9PKzU2'];
const AGENTS_FONDATEURS = ['VLDWJnoc3YRizgGkagGPxhMuWru2'];
// Les autres personnes sont declarees dans la base, noeud  autorites/<UID>/role  ("admin" ou "agent").
// Pour retirer une personne : supprimer son noeud (effet immediat).

// --- Reglages (modifiables) ---
const LIMITES = { incident: 8, message: 40, temoin: 6, coords: 12, sos: 10, sos_maj: 40, push: 20 }; // envois par adresse IP et par heure
const FENETRE_SEC = 3600;
const DELAI_EDITION_MS = 5 * 60 * 1000 + 15000; // modification d'un message : 5 minutes (+15 s de marge)
const DELAI_COORDS_MS = 10 * 60 * 1000;
const DELAI_SOS_MS = 30 * 60 * 1000; // un SOS peut etre complete ou annule pendant 30 minutes
const PHOTO_MAX = 3000000; // caracteres (photo en base64)
// Categorie : mot en minuscules (ex. vol, incendie, kidnapping, autre...). Accepte toutes les categories du formulaire,
// y compris celles ajoutees plus tard, mais refuse tout texte qui ressemble a du code.
const CATEGORIE = /^[a-z][a-z_-]{1,29}$/;
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

// Role d'un compte : 'admin', 'agent' ou null (compte inconnu)
async function roleDuCompte(uid) {
  if (ADMINS_FONDATEURS.includes(uid)) return 'admin';
  if (AGENTS_FONDATEURS.includes(uid)) return 'agent';
  try {
    const snap = await admin.database().ref('autorites/' + uid + '/role').once('value');
    const r = snap.val();
    if (r === 'admin' || r === 'agent') return r;
  } catch (e) {}
  return null;
}
// Jeton Firebase : renvoie { present, uid, role } ; jeton present mais invalide => erreur 401
async function verifierJeton(req) {
  const m = String((req.headers || {}).authorization || '').match(/^Bearer (.+)$/);
  if (!m) return { present: false };
  let d;
  try { d = await admin.auth().verifyIdToken(m[1]); } catch (e) { throw erreur(401, 'jeton'); }
  return { present: true, uid: d.uid, role: await roleDuCompte(d.uid) };
}
// 'autorite' (admin), 'agent', ou 'citoyen' sans jeton ; compte connecte mais absent de la liste => 403
async function roleAppelant(req) {
  const v = await verifierJeton(req);
  if (!v.present) return 'citoyen';
  if (v.role === 'admin') return 'autorite';
  if (v.role === 'agent') return 'agent';
  throw erreur(403, 'non_autorise');
}

async function limiter(db, ip, type) {
  const fenetre = Math.floor(Date.now() / (FENETRE_SEC * 1000));
  const cle = crypto.createHash('sha256').update(ip + '|alertcitoyen').digest('hex').slice(0, 24);
  const res = await db.ref('limites/' + type + '/' + cle + '_' + fenetre).transaction((v) => (v || 0) + 1);
  if (res.snapshot.val() > LIMITES[type]) throw erreur(429, 'trop_de_demandes');
}

// ----- Signalement d'incident -----
async function creerIncident(db, c, ip, avantEcriture) {
  const categorie = texte(c.categorie, 30);
  if (!CATEGORIE.test(categorie)) throw erreur(400, 'categorie');
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
  // Identifiant fixe calcule depuis le code de suivi et l'heure du telephone : si le meme signalement est
  // renvoye (reseau coupe au mauvais moment), il n'est pas cree deux fois.
  const ts = nombre(c.timestamp);
  await avantEcriture();
  if (ts === null) {
    const ref = db.ref('incidents').push();
    await ref.set(incident);
    await envoyerPush('autorites', { titre: '🚨 Nouveau signalement', corps: 'Catégorie : ' + categorie, tag: 'signalement' });
    return { id: ref.key };
  }
  const cle = 'i' + crypto.createHash('sha1').update(code + '|' + ts).digest('hex').slice(0, 19);
  const res = await db.ref('incidents/' + cle).transaction((existant) => (existant === null ? incident : undefined));
  if (res && res.committed) {
    // texte volontairement generique : le contenu du signalement ne transite pas par le service de notification
    await envoyerPush('autorites', { titre: '🚨 Nouveau signalement', corps: 'Catégorie : ' + categorie, tag: 'signalement' });
  }
  return { id: cle };
}

// ----- Messages citoyen <-> police -----
async function creerMessage(db, c, role, avantEcriture) {
  const code = texte(c.code, 20);
  if (!CODE.test(code)) throw erreur(400, 'code');
  const t = texte(c.texte, 1000);
  if (!t) throw erreur(400, 'texte');
  const expediteur = c.expediteur === 'police' ? 'police' : 'citoyen';
  if (expediteur === 'police' && role !== 'autorite') throw erreur(403, 'reserve_aux_autorites');
  await avantEcriture();
  const ref = db.ref('messages/' + code).push();
  await ref.set({ texte: t, expediteur, timestamp: Date.now() });
  return { id: ref.key };
}

async function modifierMessage(db, c, role, avantEcriture) {
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
  await avantEcriture();
  await ref.update({ texte: t, modifie: true });
  return {};
}

// ----- Signalement d'un temoin sur un avis de recherche -----
async function creerTemoin(db, c, avantEcriture) {
  const avisId = String(c.avisId || '');
  if (!ID.test(avisId)) throw erreur(400, 'avis');
  const lieu = texte(c.lieu, 200);
  if (!lieu) throw erreur(400, 'lieu');
  const tel = texte(c.telephone, 25);
  if (!TEL.test(tel)) throw erreur(400, 'telephone');
  const existe = await db.ref('avis_recherche/' + avisId + '/nom').once('value');
  if (!existe.exists()) throw erreur(404, 'avis_introuvable');
  const bonnesCoords = coordsOk(c.lat, c.lng);
  await avantEcriture();
  const ref = db.ref('avis_recherche/' + avisId + '/signalements').push();
  await ref.set({
    lieu, quand: texte(c.quand, 120) || 'Non precise', telephone: tel,
    timestamp: Date.now(), tsLocal: nombre(c.timestamp),
    lat: bonnesCoords ? c.lat : null, lng: bonnesCoords ? c.lng : null
  });
  return { id: ref.key };
}

async function majCoordsTemoin(db, c, avantEcriture) {
  const avisId = String(c.avisId || ''), sigId = String(c.sigId || '');
  if (!ID.test(avisId) || !ID.test(sigId)) throw erreur(400, 'identifiant');
  if (!coordsOk(c.lat, c.lng)) throw erreur(400, 'coordonnees');
  const ref = db.ref('avis_recherche/' + avisId + '/signalements/' + sigId);
  const snap = await ref.once('value');
  if (!snap.exists()) throw erreur(404, 'introuvable');
  if (Date.now() - (snap.val().timestamp || 0) > DELAI_COORDS_MS) throw erreur(403, 'delai_depasse');
  await avantEcriture();
  await ref.update({ lat: c.lat, lng: c.lng });
  return {};
}



// ----- Notifications push (Firebase Cloud Messaging) : groupes 'autorites' et 'citoyens' -----
async function envoyerPush(topic, p) {
  try {
    await admin.messaging().send({
      topic,
      data: { titre: String(p.titre || ''), corps: String(p.corps || ''), url: p.url || '/', tag: p.tag || '', urgent: p.urgent ? '1' : '0' },
      webpush: { headers: { Urgency: 'high', TTL: String(p.ttl || 3600) } }
    });
  } catch (e) { console.error('push :', e && e.message); }
}
const JETON_PUSH = /^[A-Za-z0-9_:\-]{50,500}$/;
async function abonnerPush(c, role, avantEcriture) {
  const token = String(c.token || '');
  if (!JETON_PUSH.test(token)) throw erreur(400, 'jeton_push');
  const groupe = c.groupe === 'autorites' ? 'autorites' : 'citoyens';
  if (groupe === 'autorites' && role !== 'autorite') throw erreur(403, 'reserve_aux_autorites');
  await avantEcriture();
  const m = admin.messaging();
  const rep = await m.subscribeToTopic([token], groupe);
  if (rep && rep.failureCount > 0) throw erreur(400, 'abonnement_refuse');
  // un telephone d'autorite ne recoit pas les alertes destinees aux citoyens (pas de notification de ses propres alertes)
  if (groupe === 'autorites') { try { await m.unsubscribeFromTopic([token], 'citoyens'); } catch (e) {} }
  return {};
}
async function desabonnerPush(c, avantEcriture) {
  const token = String(c.token || '');
  if (!JETON_PUSH.test(token)) throw erreur(400, 'jeton_push');
  const groupe = c.groupe === 'autorites' ? 'autorites' : 'citoyens';
  await avantEcriture();
  await admin.messaging().unsubscribeFromTopic([token], groupe);
  return {};
}
// Alerte officielle publiee par une autorite : notification a tous les citoyens abonnes
async function pushAlerte(db, c, role) {
  if (role !== 'autorite') throw erreur(403, 'reserve_aux_autorites');
  const id = String(c.id || '');
  if (!ID.test(id)) throw erreur(400, 'identifiant');
  const snap = await db.ref('alertes_officielles/' + id).once('value');
  if (!snap.exists()) throw erreur(404, 'introuvable');
  const a = snap.val();
  if (a.actif === false) throw erreur(400, 'alerte_inactive');
  if (Date.now() - (a.timestamp || 0) > 10 * 60 * 1000) throw erreur(403, 'delai_depasse');
  await envoyerPush('citoyens', { titre: '📢 Alerte officielle', corps: texte(a.message, 140), tag: 'alerte-' + id, urgent: true, ttl: 6 * 3600 });
  return {};
}
// Demande de renfort d'un agent : notification aux autorites
async function pushRenfort(db, c, role) {
  if (role !== 'autorite' && role !== 'agent') throw erreur(403, 'reserve_aux_autorites');
  const id = String(c.id || '');
  if (!ID.test(id)) throw erreur(400, 'identifiant');
  const snap = await db.ref('demandes_renfort/' + id).once('value');
  if (!snap.exists()) throw erreur(404, 'introuvable');
  const d = snap.val();
  if (Date.now() - (d.timestamp || 0) > 10 * 60 * 1000) throw erreur(403, 'delai_depasse');
  await envoyerPush('autorites', { titre: '🆘 Demande de renfort', corps: texte((d.type || 'Renfort') + (d.lieu ? ' — ' + d.lieu : ''), 140), tag: 'renfort-' + id, urgent: true });
  return {};
}

// ----- SOS : personne en danger (visible uniquement par les autorites) -----
// Lieu approximatif deduit de l'adresse IP par Vercel (utilise seulement si le GPS n'est pas disponible)
function lieuApproxDepuisEntetes(req) {
  const h = req.headers || {};
  const dec = (v) => { try { return decodeURIComponent(String(v || '')); } catch (e) { return String(v || ''); } };
  const lat = parseFloat(h['x-vercel-ip-latitude']), lng = parseFloat(h['x-vercel-ip-longitude']);
  const ville = dec(h['x-vercel-ip-city']).slice(0, 80);
  const pays = String(h['x-vercel-ip-country'] || '').slice(0, 4);
  const coords = isFinite(lat) && isFinite(lng);
  if (!coords && !ville) return null;
  return { ville: ville || null, pays: pays || null, lat: coords ? lat : null, lng: coords ? lng : null };
}

async function creerSOS(db, c, req, ip, avantEcriture) {
  const idLocal = texte(c.idLocal, 40);
  if (!/^[A-Za-z0-9_-]{8,40}$/.test(idLocal)) throw erreur(400, 'identifiant');
  const gps = coordsOk(c.lat, c.lng);
  const tel = texte(c.telephone, 25);
  const sos = {
    timestamp: Date.now(),
    tsLocal: nombre(c.timestamp),
    statut: 'nouveau',
    gps,
    lat: gps ? c.lat : null, lng: gps ? c.lng : null,
    precision: gps ? nombre(c.precision) : null,
    approx: gps ? null : lieuApproxDepuisEntetes(req),
    telephone: TEL.test(tel) ? tel : null,
    ip, appareil: texte(c.appareil, 100)
  };
  // Identifiant fixe : un SOS renvoye (reseau coupe) n'est pas cree deux fois
  const cle = 's' + crypto.createHash('sha1').update(idLocal).digest('hex').slice(0, 19);
  await avantEcriture();
  const res = await db.ref('sos/' + cle).transaction((existant) => (existant === null ? sos : undefined));
  if (res && res.committed) {
    await envoyerPush('autorites', { titre: '🆘 SOS — personne en danger', corps: 'Ouvrez AlertCitoyen pour voir la position', tag: 'sos-' + cle, urgent: true, ttl: 1800 });
  }
  return { id: cle };
}

async function majSOS(db, c, avantEcriture) {
  const id = String(c.id || '');
  if (!ID.test(id)) throw erreur(400, 'identifiant');
  const ref = db.ref('sos/' + id);
  const snap = await ref.once('value');
  if (!snap.exists()) throw erreur(404, 'introuvable');
  const s = snap.val();
  if (Date.now() - (s.timestamp || 0) > DELAI_SOS_MS) throw erreur(403, 'delai_depasse');
  const maj = {};
  if (coordsOk(c.lat, c.lng)) {
    maj.lat = c.lat; maj.lng = c.lng; maj.gps = true; maj.approx = null;
    const pr = nombre(c.precision); if (pr !== null) maj.precision = pr;
  }
  if (c.telephone !== undefined) {
    const t = texte(c.telephone, 25);
    if (!TEL.test(t)) throw erreur(400, 'telephone');
    maj.telephone = t;
  }
  if (c.annuler === true) {
    maj.annuleParCitoyen = true;
    if (s.statut === 'nouveau') maj.statut = 'annule';
  }
  if (!Object.keys(maj).length) throw erreur(400, 'rien_a_modifier');
  maj.majTs = Date.now();
  await avantEcriture();
  await ref.update(maj);
  return {};
}

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method === 'GET') {
    // Controle de configuration (aucun secret affiche)
    if (req.query && req.query.diagnostic) {
      let compte = !!process.env.FIREBASE_SERVICE_ACCOUNT, pret = false;
      try { init(); pret = true; } catch (e) { pret = false; }
      return repondre(res, 200, { ok: pret, compte_present: compte, connexion_prete: pret, version: VERSION, comptes_fondateurs: ADMINS_FONDATEURS.length + AGENTS_FONDATEURS.length });
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
    const action = c.action;
    if (action === 'moi') {
      // Verification d'un compte : est-il dans la liste des autorites ?
      const v = await verifierJeton(req);
      if (!v.present) throw erreur(401, 'jeton');
      return repondre(res, 200, { ok: true, role: v.role, autorite: v.role === 'admin', uid: v.uid });
    }
    const role = await roleAppelant(req);
    const limite = { incident: 'incident', message: 'message', message_modifier: 'message', temoin: 'temoin', temoin_coords: 'coords', sos: 'sos', sos_maj: 'sos_maj', push_abonner: 'push', push_desabonner: 'push', push_alerte: 'push', push_renfort: 'push' }[action];
    if (!limite) throw erreur(400, 'action');
    const ip = ipDe(req);
    // la limite par IP n'est comptee qu'au moment d'ecrire : un envoi refuse (donnees invalides) n'use pas le quota
    const avantEcriture = async () => { if (role !== 'autorite') await limiter(db, ip, limite); };
    let resultat;
    if (action === 'incident') resultat = await creerIncident(db, c, ip, avantEcriture);
    else if (action === 'message') resultat = await creerMessage(db, c, role, avantEcriture);
    else if (action === 'message_modifier') resultat = await modifierMessage(db, c, role, avantEcriture);
    else if (action === 'temoin') resultat = await creerTemoin(db, c, avantEcriture);
    else if (action === 'sos') resultat = await creerSOS(db, c, req, ip, avantEcriture);
    else if (action === 'sos_maj') resultat = await majSOS(db, c, avantEcriture);
    else if (action === 'push_abonner') resultat = await abonnerPush(c, role, avantEcriture);
    else if (action === 'push_desabonner') resultat = await desabonnerPush(c, avantEcriture);
    else if (action === 'push_alerte') resultat = await pushAlerte(db, c, role);
    else if (action === 'push_renfort') resultat = await pushRenfort(db, c, role);
    else resultat = await majCoordsTemoin(db, c, avantEcriture);
    return repondre(res, 200, Object.assign({ ok: true }, resultat));
  } catch (e) {
    if (e && e.statut) return repondre(res, e.statut, { ok: false, erreur: e.code });
    console.error('envoyer.js :', e && e.message);
    return repondre(res, 500, { ok: false, erreur: 'serveur' });
  }
};
