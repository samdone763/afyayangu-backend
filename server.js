// Afya Yangu Backend — server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'afyayangu_secret_2025';
const PORT = process.env.PORT || 3000;

mongoose.connect(MONGODB_URI).then(() => console.log('MongoDB connected')).catch(console.error);

// ═══════════════ SCHEMAS ═══════════════

const UserSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  username: { type: String, required: true, unique: true, trim: true, lowercase: true },
  passwordHash: { type: String, required: true },
  age: { type: String },
  createdAt: { type: Date, default: Date.now }
});

const MessageSchema = new mongoose.Schema({
  role: { type: String, enum: ['user', 'assistant'], required: true },
  content: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const ConversationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  title: { type: String, default: 'Mazungumzo Mapya' },
  messages: [MessageSchema],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Conversation = mongoose.model('Conversation', ConversationSchema);

// ═══════════════ AUTH MIDDLEWARE ═══════════════

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Hakuna token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token batili — ingia tena' });
  }
}

// ═══════════════ HEALTH ═══════════════

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', app: 'Afya Yangu' });
});

// ═══════════════ REGISTER ═══════════════

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, username, password, age } = req.body;
    if (!name || !username || !password)
      return res.status(400).json({ error: 'Jina, username na password zinahitajika' });
    if (password.length < 4)
      return res.status(400).json({ error: 'Password iwe na herufi 4 au zaidi' });
    const existing = await User.findOne({ username: username.toLowerCase() });
    if (existing)
      return res.status(400).json({ error: 'Username hii imeshatumika — chagua nyingine' });
    const passwordHash = await bcrypt.hash(password, 10);
    const user = new User({ name, username: username.toLowerCase(), passwordHash, age });
    await user.save();
    const token = jwt.sign({ id: user._id, name: user.name, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user._id, name: user.name, username: user.username, age: user.age } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════ LOGIN ═══════════════

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: 'Username na password zinahitajika' });
    const user = await User.findOne({ username: username.toLowerCase() });
    if (!user)
      return res.status(404).json({ error: 'Account haijapatikana — jisajili kwanza' });
    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid)
      return res.status(401).json({ error: 'Password si sahihi — jaribu tena' });
    const token = jwt.sign({ id: user._id, name: user.name, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user._id, name: user.name, username: user.username, age: user.age } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════ CONVERSATIONS ═══════════════

// Pata zote
app.get('/api/conversations', authMiddleware, async (req, res) => {
  try {
    const convs = await Conversation.find({ userId: req.user.id })
      .sort({ updatedAt: -1 }).limit(50);
    const summary = convs.map(c => ({
      id: c._id,
      title: c.title,
      preview: c.messages[c.messages.length - 1]?.content?.substring(0, 80) || '',
      messageCount: c.messages.length,
      updatedAt: c.updatedAt,
      createdAt: c.createdAt
    }));
    res.json(summary);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Pata moja kamili
app.get('/api/conversations/:id', authMiddleware, async (req, res) => {
  try {
    const conv = await Conversation.findOne({ _id: req.params.id, userId: req.user.id });
    if (!conv) return res.status(404).json({ error: 'Haijapatikana' });
    res.json(conv);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Tengeneza mpya
app.post('/api/conversations', authMiddleware, async (req, res) => {
  try {
    const conv = new Conversation({
      userId: req.user.id,
      title: req.body.title || 'Mazungumzo Mapya',
      messages: []
    });
    await conv.save();
    res.json(conv);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Save messages
app.put('/api/conversations/:id/messages', authMiddleware, async (req, res) => {
  try {
    const { messages, title } = req.body;
    const conv = await Conversation.findOne({ _id: req.params.id, userId: req.user.id });
    if (!conv) return res.status(404).json({ error: 'Haijapatikana' });
    conv.messages = messages;
    conv.updatedAt = new Date();
    if (title) conv.title = title;
    await conv.save();
    res.json({ success: true, id: conv._id, title: conv.title });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Futa
app.delete('/api/conversations/:id', authMiddleware, async (req, res) => {
  try {
    await Conversation.findOneAndDelete({ _id: req.params.id, userId: req.user.id });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => console.log(`Afya Yangu backend running on port ${PORT}`));

// ═══════════════ CHAT PROXY ═══════════════
const OPENROUTER_KEY = process.env.OPENROUTER_KEY;

app.post('/api/chat', authMiddleware, async (req, res) => {
  try {
    const { messages, userProfile, hasImage, model } = req.body;

    const selectedModel = hasImage 
      ? 'qwen/qwen2.5-vl-72b-instruct:free' 
      : 'google/gemma-3-27b-it:free';

    const systemPrompt = `Wewe ni daktari bora wa Kitanzania — unaitwa Dkt. Afya. Unazungumza Kiswahili safi cha kawaida cha mitaani, kama rafiki yako ambaye ni daktari. Unaelezea mambo kwa undani lakini kwa lugha rahisi sana.

TAARIFA ZA MTUMIAJI: Jina: ${userProfile?.name || 'Rafiki'}, Umri: ${userProfile?.age || 'Mtu mzima'}

MUUNDO WA JIBU LAKO — fuata hii kila wakati:

**1. NAONA NINI** (mistari 1-2)
Elezea dalili au picha unavyoona kwa urahisi.

**2. INAWEZA KUWA NINI** (mistari 1-2)
Sema uwezekano kwa lugha ya kawaida.

**3. HATARI GANI UKIACHA** (mstari 1)
Elezea hatari kwa ufupi.

**4. FANYA HIVI SASA** (mistari 2-3)
Hatua za vitendo za kufanya nyumbani.

**5. HUKUMU YANGU** (mstari 1)
🟢 Pumzika nyumbani — hali si mbaya
🟡 Nenda duka la dawa leo — unahitaji dawa
🔴 Nenda hospitali SASA HIVI — hali ya hatari

**6. MWISHO DAIMA**
"⚕️ Hii si ushauri wa daktari wa kweli — kwa hali yoyote mbaya nenda hospitali."

SHERIA ZA LUGHA:
- Zungumza kama unavyozungumza na ndugu — "wewe", "kwako", "unaweza", "bora ufanye"
- Usitumie: "zinaonyesha", "uwezekano mkubwa", "inashauriwa", "kituo cha afya"
- Kama ni swali dogo/rahisi — jibu fupi mistari 3-4 tu bila sections zote
- Kama ni hali nzito — tumia sections zote kwa undani
- Dharura: "Piga 112 au nenda hospitali SASA HIVI — usichelewe hata dakika moja!"`;

    const nodeFetch = await import('node-fetch');
    const fetchFn = nodeFetch.default;

    const response = await fetchFn('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${OPENROUTER_KEY}`,
        'HTTP-Referer': 'https://samdone763.github.io/afyayangu',
        'X-Title': 'Afya Yangu'
      },
      body: JSON.stringify({
        model: selectedModel,
        max_tokens: 800,
        messages: [
          { role: 'system', content: systemPrompt },
          ...messages
        ]
      })
    });

    const data = await response.json();
    if (data.error) throw new Error(data.error.message);
    const reply = data.choices?.[0]?.message?.content || 'Samahani, jaribu tena.';
    res.json({ reply });
  } catch (err) {
    console.error('Chat error:', err.message);
    res.status(500).json({ error: err.message });
  }
});
