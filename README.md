# ScamCheck

A simple Flask hackathon app for checking suspicious Vietnamese messages, links, screenshots, and voice text with Gemini.

## Run locally

```powershell
pip install -r requirements.txt
python app.py
```

Open http://localhost:5000/

Put your Gemini key in `.env` as:

```env
GEMINI_API_KEY=your_key_here
```

Do not commit `.env`.
